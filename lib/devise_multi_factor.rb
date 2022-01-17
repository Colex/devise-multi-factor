require 'devise_multi_factor/version'
require 'devise'
require 'active_support/concern'
require "active_model"
require "active_support/core_ext/class/attribute_accessors"
require "cgi"

module Devise
  mattr_accessor :max_login_attempts
  @@max_login_attempts = 3

  mattr_accessor :allowed_otp_drift_seconds
  @@allowed_otp_drift_seconds = 30

  mattr_accessor :otp_issuer
  @@otp_issuer = nil

  mattr_accessor :otp_length
  @@otp_length = 6

  mattr_accessor :direct_otp_length
  @@direct_otp_length = 6

  mattr_accessor :direct_otp_valid_for
  @@direct_otp_valid_for = 5.minutes

  mattr_accessor :remember_otp_session_for_seconds
  @@remember_otp_session_for_seconds = 0

  mattr_accessor :otp_secret_encryption_key
  @@otp_secret_encryption_key = nil

  mattr_accessor :second_factor_resource_id
  @@second_factor_resource_id = 'id'

  mattr_accessor :delete_cookie_on_logout
  @@delete_cookie_on_logout = false
end

module DeviseMultiFactor
  NEED_AUTHENTICATION = 'need_two_factor_authentication'
  REMEMBER_TFA_COOKIE_NAME = "remember_tfa"

  autoload :Schema, 'devise_multi_factor/schema'
  module Controllers
    autoload :Helpers, 'devise_multi_factor/controllers/helpers'
  end
end

Devise.add_module :two_factor_authenticatable, :model => 'devise_multi_factor/models/two_factor_authenticatable', :controller => :two_factor_authentication, :route => :two_factor_authentication
Devise.add_module :totp_enrollable, model: 'devise_multi_factor/models/totp_enrollable', controller: :totp, route: :totp

require 'devise_multi_factor/orm/active_record' if defined?(ActiveRecord::Base)
require 'devise_multi_factor/routes'
require 'devise_multi_factor/remember_tfa_cookie'
require 'devise_multi_factor/models/two_factor_authenticatable'
require 'devise_multi_factor/rails'
