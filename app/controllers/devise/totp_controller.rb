require 'devise/version'

class Devise::TotpController < DeviseController
  prepend_before_action :authenticate_scope!
  before_action :two_factor_authenticate!

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
      flash.now[:error] = I18n.t('devise.totp_setup.invalid_code')
      render_enroll_form(status: :unprocessable_entity)
    end
  rescue ActiveSupport::MessageVerifier::InvalidSignature
    redirect_to send("new_#{resource_name}_two_factor_authentication_path"), flash: { error: I18n.t('devise.totp_setup.invalid_signature') }
  end

  def show
  end

  def destroy
  end

  private

  def generate_qr_code(otp_secret)
    return unless defined?(::RQRCode)

    qr_code = RQRCode::QRCode
      .new(resource.provisioning_uri(nil, otp_secret_key: @otp_secret, issuer: Devise.otp_issuer))
      .as_png(resize_exactly_to: 246)
      .to_data_url
  end

  def render_enroll_form(status: :ok)
    @qr_code = generate_qr_code(@otp_secret)
    render :new, status: status
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

  def after_two_factor_enroll_success_path_for(resource)
    :root
  end

  def authenticate_scope!
    send(:"authenticate_#{resource_name}!", force: true)
    self.resource = send("current_#{resource_name}")
  end
end
