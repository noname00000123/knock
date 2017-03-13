# rubocop:disable Metrics/LineLength

require 'jwt'

module Knock

  class AuthToken

    attr_reader :token
    attr_reader :payload

    # @param [Hash] payload
    # @param [String] token
    # @param [Hash] verify_options
    def initialize(payload: {}, token: nil, audience: nil, verify_options: {})
      if token.present?
        @payload, _ = JWT.decode(token, decode_key, true, options.merge!(verify_options))
        @token = token
      else
        self.token_audience = audience
        @payload = claims.merge!(payload)
        @token   = JWT.encode(@payload, secret_key, Knock.token_signature_algorithm)
      end
    end

    # @param [Class] entity_class
    # @return [Object, nil]
    def entity_for(entity_class)
      if entity_class.respond_to?(:from_token_payload)
        entity_class.from_token_payload(payload)
      else
        entity_class.find(payload['sub'])
      end
    end

    # @see https://auth0.com/docs/api/authentication#client-credentials
    # @note Includes expiry to support client token refresh strategy
    # @example
    #   {
    #     access_token: "xXx...xXx.yYy...yYy.zZz...zZz",
    #     token_type:   "Bearer",
    #     expires_in:   "86400",
    #     expires_at:   "1491372989"
    #   }
    # @param [Hash] options
    # @return [Hash]
    def serializable_hash(options = {})
      {
        access_token: token,            # **JSON Web Token (JWT)**
        token_type:   'Bearer',         # HTTP Authorization Strategy
        expires_in:   token_expires_in, # TTL
        expires_at:   token_expires_at
      }.except(*options[:except])
    end

    # @return [Hash]
    def to_json(options = {})
      serializable_hash(options).to_json
    end

    private

      def secret_key
        Knock.token_secret_signature_key.call
      end

      def decode_key
        Knock.token_public_key || secret_key
      end

      # **Time To Live (TTL)**
      # @return [Fixnum] if {#verify_expiration?} true
      # @return [nil]
      def token_expires_in
        # Knock.token_expires_in.seconds if verify_expiration?
        token_expires_at - Time.zone.now.to_i if token_expires_at
      end

      # @see https://tools.ietf.org/html/rfc7519#section-2 Terminology: NumericDate
      # @return [Fixnum] if {#verify_expiration?} true
      # @return [nil]
      def token_expires_at
        @token_expires_at ||= Knock.token_expires_in.from_now.to_i if verify_expiration?
      end

      # @!attribute [rw] token_audience
      #   @return [String] if {#verify_audience?} true
      #   @return [nil]
      attr_reader :token_audience

      # @see Piktur::Security Knock.token_audience
      # @return [String] if {#verify_audience?} true
      # @return [nil]
      def token_audience=(val)
        @token_audience = (val || Piktur::Services.uri) if verify_audience?
      end

      # `verify_expiration?` will add duration to `exp` to accommodate possible transfer delay.
      # @return [ActiveSupport::Duration, Fixnum]
      def leeway
        Knock.token_leeway.presence
      end

      # @return [Boolean]
      def verify_expiration?
        Knock.token_expires_in.present?
      end

      # @return [Boolean]
      def verify_audience?
        Knock.token_audience.present?
      end

      # [**JWT claims**](https://tools.ietf.org/html/rfc7519#section-4)
      # @return [Hash]
      def claims
        return @claims if defined?(@claims)
        @claims = {}
        @claims[:exp] = token_expires_at if verify_expiration?
        @claims[:aud] = token_audience if verify_audience?
        # @claims[:iat] = Time.now.to_i
        @claims
      end

      # `JWT.decode` options
      # @return [Hash]
      def options
        options = verify_claims
        options[:algorithm]  = Knock.token_signature_algorithm
        options[:exp_leeway] = leeway.to_i if leeway
        options
      end

      # Configure `JWT.decode` claims verification constraints
      # @return [Hash]
      def verify_claims
        {
          aud:               token_audience,
          verify_aud:        verify_audience?,
          verify_expiration: verify_expiration?
        }
      end

  end

end
