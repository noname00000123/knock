$LOAD_PATH.push File.expand_path('../app', __dir__)

require 'knock/engine' if defined? Rails

require 'active_support/core_ext/module/attribute_accessors'
require 'active_support/core_ext/numeric/time'
require 'active_support/duration'
require 'active_support/core_ext/string/filters'
require 'active_support/dependencies/autoload'

NotAuthorizedError = Class.new(StandardError)

module Knock
  extend ActiveSupport::Autoload

  eager_autoload do
    autoload :AuthToken, 'model/knock/auth_token'
  end

  mattr_accessor :token_lifetime
  self.token_lifetime = 1.day

  mattr_accessor :token_audience
  self.token_audience = nil

  mattr_accessor :token_signature_algorithm
  self.token_signature_algorithm = 'HS256'

  mattr_accessor :token_secret_signature_key
  self.token_secret_signature_key = -> { ENV['SECRET_KEY_BASE'] }

  mattr_accessor :token_public_key
  self.token_public_key = nil

  mattr_accessor :not_found_exception_class_name
  self.not_found_exception_class_name = 'NotAuthorizedError'

  def self.not_found_exception_class
    not_found_exception_class_name.to_s.constantize
  end

  # Default way to setup Knock. Run `rails generate knock:install` to create
  # a fresh initializer with all configuration values.
  def self.setup
    yield self
  end
end
