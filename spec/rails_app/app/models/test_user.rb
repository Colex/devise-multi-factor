class TestUser
  extend ActiveModel::Callbacks
  include ActiveModel::Validations
  include Devise::Models::TwoFactorAuthenticatable
  extend Lockbox::Model

  define_model_callbacks :create
  attr_accessor :encrypted_otp_secret_key,
                :email,
                :second_factor_attempts_count,
                :totp_timestamp,
                :direct_otp,
                :direct_otp_sent_at,
                :otp_secret_key

  def self.fields
    {}
  end

  def self.attribute_names
    []
  end

  def serializable_hash(_options = nil)
    {}
  end

  def encrypted_otp_secret_key_changed?
    false
  end

  def update_columns(values)
    values.each do |key, value|
      send("#{key}=", value)
    end
    true
  end
end
