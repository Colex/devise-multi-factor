require 'devise/version'

class Devise::TwoFactorAuthenticationController < DeviseController
  prepend_before_action :authenticate_scope!
  before_action :two_factor_authenticate!, except: [:show, :update, :resend_code]
  before_action :prepare_and_validate, :handle_two_factor_authentication

  def new
    @otp_secret = resource.generate_totp_secret
    @otp_secret_signature = sign_otp_secret(@otp_secret)
    render_enroll_form
  end

  def create
    @otp_secret_signature = params[:otp_secret_signature]
    @otp_secret = verify_otp_secret(@otp_secret_signature)
    if resource.enroll_totp!(@otp_secret, params[:otp_attempt])
      after_two_factor_enroll_success_for(resource)
    else
      flash.now[:error] = 'The authenticator code provided was invalid!'
      render_enroll_form
    end
  rescue ActiveSupport::MessageVerifier::InvalidSignature
    redirect_to send("new_#{resource_name}_two_factor_authentication_path"), flash: { error: 'There has been a problem in the configuration process, please try again.' }
  end

  def show
  end

  def update
    render :show and return if params[:code].nil?

    if resource.authenticate_otp(params[:code])
      after_two_factor_success_for(resource)
    else
      after_two_factor_fail_for(resource)
    end
  end

  def resend_code
    resource.send_new_otp
    redirect_to send("#{resource_name}_two_factor_authentication_path"), notice: I18n.t('devise.two_factor_authentication.code_has_been_sent')
  end

  private

  def generate_qr_code(otp_secret)
    return unless defined?(::RQRCode)

    qr_code = RQRCode::QRCode
      .new(resource.provisioning_uri(nil, otp_secret_key: @otp_secret, issuer: Devise.otp_issuer))
      .as_png(resize_exactly_to: 246)
      .to_data_url
  end

  def render_enroll_form
    @qr_code = generate_qr_code(@otp_secret)
    render :new
  end

  def verifier
    ActiveSupport::MessageVerifier.new(Devise.secret_key, digest: 'SHA256')
  end

  def verify_otp_secret(otp_secret_signature)
    data = verifier.verify(otp_secret_signature)
    valid = data[Devise.second_factor_resource_id] == resource[Devise.second_factor_resource_id]
    raise ActiveSupport::MessageVerifier::InvalidSignature unless valid

    data['otp_secret']
  end

  def sign_otp_secret(otp_secret)
    data = {
      Devise.second_factor_resource_id => resource[Devise.second_factor_resource_id],
      'otp_secret' => otp_secret,
    }
    verifier.generate(data)
  end

  def after_two_factor_enroll_success_for(resource)
    redirect_to after_two_factor_enroll_success_path_for(resource), flash: { success: 'Multi-factor authentication successfully setup!' }
  end

  def after_two_factor_success_for(resource)
    set_remember_two_factor_cookie(resource)

    warden.session(resource_name)[DeviseMultiFactor::NEED_AUTHENTICATION] = false
    # For compatability with devise versions below v4.2.0
    # https://github.com/plataformatec/devise/commit/2044fffa25d781fcbaf090e7728b48b65c854ccb
    if respond_to?(:bypass_sign_in)
      bypass_sign_in(resource, scope: resource_name)
    else
      sign_in(resource_name, resource, bypass: true)
    end
    set_flash_message :notice, :success
    resource.update_attribute(:second_factor_attempts_count, 0)

    redirect_to after_two_factor_success_path_for(resource)
  end

  def set_remember_two_factor_cookie(resource)
    expires_seconds = resource.class.remember_otp_session_for_seconds

    if expires_seconds && expires_seconds > 0
      cookies.signed[DeviseMultiFactor::REMEMBER_TFA_COOKIE_NAME] = {
          value: "#{resource.class}-#{resource.public_send(Devise.second_factor_resource_id)}",
          expires: expires_seconds.seconds.from_now
      }
    end
  end

  def after_two_factor_success_path_for(resource)
    stored_location_for(resource_name) || :root
  end

  def after_two_factor_enroll_success_path_for(resource)
    :root
  end

  def after_two_factor_fail_for(resource)
    resource.second_factor_attempts_count += 1
    resource.save
    set_flash_message :alert, :attempt_failed, now: true

    if resource.max_login_attempts?
      sign_out(resource)
      render :max_login_attempts_reached
    else
      render :show
    end
  end

  def authenticate_scope!
    self.resource = send("current_#{resource_name}")
  end

  def prepare_and_validate
    redirect_to :root and return if resource.nil?
    @limit = resource.max_login_attempts
    if resource.max_login_attempts?
      sign_out(resource)
      render :max_login_attempts_reached and return
    end
  end
end
