$LOAD_PATH.push File.expand_path('../app', __dir__)

require 'knock/engine' if defined? Rails

require 'active_support/core_ext/module/attribute_accessors'
require 'active_support/core_ext/numeric/time'
require 'active_support/duration'
require 'active_support/core_ext/string/filters'
require 'active_support/dependencies/autoload'

module Knock
  extend ActiveSupport::Autoload

  eager_autoload do
    autoload :AuthToken, 'model/knock/auth_token'
  end

  NotAuthorizedError = Class.new(StandardError)

  # @see https://tools.ietf.org/html/rfc7519#section-4.1.4 OAuth JSON Web Token 4.1.4. "exp" (Expiration Time) Claim
  # **exp** ... identifies the expiration time on or after which the JWT **MUST
  # NOT** be accepted for processing. ... the current date/time MUST be before the expiration
  # date/time listed in the exp claim. **MAY** provide for some small leeway, usually no more than
  # a few minutes, to account for clock skew. Its value **MUST** be a number containing a
  # NumericDate value.
  mattr_accessor(:token_expires_in)               { 1.day }
  mattr_accessor(:token_leeway)                   { 30.seconds }
  mattr_accessor(:token_audience)                 { nil }
  mattr_accessor(:token_signature_algorithm)      { 'HS256' }
  mattr_accessor(:token_secret_signature_key)     { -> { ENV['SECRET_KEY_BASE'] } }
  mattr_accessor(:token_public_key)               { nil }
  mattr_accessor(:not_found_exception_class_name) { 'Knock::NotAuthorizedError' }

  def self.not_found_exception_class
    not_found_exception_class_name.to_s.constantize
  end

  # Default way to setup Knock. Run `rails generate knock:install` to create
  # a fresh initializer with all configuration values.
  def self.setup
    yield self
  end
end
