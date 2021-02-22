require 'devise_multi_factor/hooks/two_factor_authenticatable'
require 'rotp'

module Devise
  module Models
    module TwoFactorAuthenticatable
      extend ActiveSupport::Concern

      module ClassMethods
        def has_one_time_password(options = {})
          include InstanceMethodsOnActivation

          encrypt_options = {
            key: otp_secret_encryption_key,
            encrypted_attribute: 'encrypted_otp_secret_key',
          }.compact
          encrypt_options = encrypt_options.merge(options[:encrypt]) if options[:encrypt].is_a?(Hash)
          encrypts(:otp_secret_key, encrypt_options || {})
        end

        def generate_totp_secret
          # ROTP gem since version 5 to version 5.1
          # at version 5.1 ROTP gem reinstates.
          # Details: https://github.com/mdp/rotp/blob/master/CHANGELOG.md#510
          ROTP::Base32.try(:random) || ROTP::Base32.random_base32
        end

        ::Devise::Models.config(
          self, :max_login_attempts, :allowed_otp_drift_seconds, :otp_issuer, :otp_length,
          :remember_otp_session_for_seconds, :otp_secret_encryption_key,
          :direct_otp_length, :direct_otp_valid_for, :totp_timestamp, :delete_cookie_on_logout
        )
      end

      module InstanceMethodsOnActivation
        def authenticate_otp(code, options = {})
          return true if direct_otp && authenticate_direct_otp(code)
          return true if totp_enabled? && authenticate_totp(code, options)
          false
        end

        def authenticate_direct_otp(code)
          return false if direct_otp.nil? || direct_otp != code || direct_otp_expired?

          clear_direct_otp
          true
        end

        def authenticate_totp(code, options = {})
          totp_secret = options[:otp_secret_key] || otp_secret_key
          digits = options[:otp_length] || self.class.otp_length
          drift = options[:drift] || self.class.allowed_otp_drift_seconds
          raise "authenticate_totp called with no otp_secret_key set" if totp_secret.nil?

          totp = ROTP::TOTP.new(totp_secret, digits: digits)
          new_timestamp = totp.verify(
            without_spaces(code),
            drift_ahead: drift, drift_behind: drift, after: totp_timestamp
          )
          return false unless new_timestamp

          self.totp_timestamp = new_timestamp
          true
        end

        def provisioning_uri(account = nil, options = {})
          totp_secret = options[:otp_secret_key] || otp_secret_key
          options[:digits] ||= options[:otp_length] || self.class.otp_length
          raise "provisioning_uri called with no otp_secret_key set" if totp_secret.nil?
          account ||= email if respond_to?(:email)
          ROTP::TOTP.new(totp_secret, options).provisioning_uri(account)
        end

        def enroll_totp!(otp_secret_key, code)
          return false unless authenticate_totp(code, { otp_secret_key: otp_secret_key })

          update_columns(totp_timestamp: totp_timestamp, otp_secret_key: otp_secret_key)
        end

        def need_two_factor_authentication?(request)
          totp_enabled?
        end

        def send_new_otp(options = {})
          create_direct_otp options
          send_two_factor_authentication_code(direct_otp)
        end

        def send_new_otp_after_login?
          !totp_enabled?
        end

        def send_two_factor_authentication_code(code)
          raise NotImplementedError.new("No default implementation - please define in your class.")
        end

        def max_login_attempts?
          second_factor_attempts_count.to_i >= max_login_attempts.to_i
        end

        def max_login_attempts
          self.class.max_login_attempts
        end

        def totp_enabled?
          respond_to?(:otp_secret_key) && !otp_secret_key.nil?
        end

        def generate_totp_secret
          self.class.generate_totp_secret
        end

        def create_direct_otp(options = {})
          # Create a new random OTP and store it in the database
          digits = options[:length] || self.class.direct_otp_length || 6
          update_columns(
            direct_otp: random_base10(digits),
            direct_otp_sent_at: Time.now.utc
          )
        end

        private

        def without_spaces(code)
          code.gsub(/[[:space:]]/, '')
        end

        def random_base10(digits)
          SecureRandom.random_number(10**digits).to_s.rjust(digits, '0')
        end

        def direct_otp_expired?
          Time.now.utc > direct_otp_sent_at + self.class.direct_otp_valid_for
        end

        def clear_direct_otp
          update_columns(direct_otp: nil, direct_otp_sent_at: nil)
        end
      end
    end
  end
end
