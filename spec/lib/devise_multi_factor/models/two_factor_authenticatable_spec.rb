require 'spec_helper'
include AuthenticatedModelHelper

describe Devise::Models::TwoFactorAuthenticatable do
  describe '#create_direct_otp' do
    let(:instance) { build_guest_user }

    it 'set direct_otp field' do
      expect(instance.direct_otp).to be_nil
      instance.create_direct_otp
      expect(instance.direct_otp).not_to be_nil
    end

    it 'set direct_otp_send_at field to current time' do
      Timecop.freeze() do
        instance.create_direct_otp
        expect(instance.direct_otp_sent_at).to eq(Time.now)
      end
    end

    it 'honors .direct_otp_length' do
      expect(instance.class).to receive(:direct_otp_length).and_return(10)
      instance.create_direct_otp
      expect(instance.direct_otp.length).to equal(10)

      expect(instance.class).to receive(:direct_otp_length).and_return(6)
      instance.create_direct_otp
      expect(instance.direct_otp.length).to equal(6)
    end

    it "honors 'direct_otp_length' in options paramater" do
      instance.create_direct_otp(length: 8)
      expect(instance.direct_otp.length).to equal(8)
      instance.create_direct_otp(length: 10)
      expect(instance.direct_otp.length).to equal(10)
    end
  end

  describe '#authenticate_direct_otp' do
    let(:instance) { build_guest_user }
    it 'fails if no direct_otp has been set' do
      expect(instance.authenticate_direct_otp('12345')).to eq(false)
    end

    context 'after generating an OTP' do
      before :each do
        instance.create_direct_otp
      end

      it 'accepts correct OTP' do
        Timecop.freeze(Time.now + instance.class.direct_otp_valid_for - 1.second)
        expect(instance.authenticate_direct_otp(instance.direct_otp)).to eq(true)
      end

      it 'rejects invalid OTP' do
        Timecop.freeze(Time.now + instance.class.direct_otp_valid_for - 1.second)
        expect(instance.authenticate_direct_otp('12340')).to eq(false)
      end

      it 'rejects expired OTP' do
        Timecop.freeze(Time.now + instance.class.direct_otp_valid_for + 1.second)
        expect(instance.authenticate_direct_otp(instance.direct_otp)).to eq(false)
      end

      it 'prevents code re-use' do
        expect(instance.authenticate_direct_otp(instance.direct_otp)).to eq(true)
        expect(instance.authenticate_direct_otp(instance.direct_otp)).to eq(false)
      end
    end
  end

  describe '#authenticate_totp' do
    shared_examples 'authenticate_totp' do |instance|
      before :each do
        instance.otp_secret_key = '2z6hxkdwi3uvrnpn'
        instance.totp_timestamp = nil
        @totp_helper = TotpHelper.new(instance.otp_secret_key, instance.class.otp_length)
      end

      def do_invoke(code, user)
        user.authenticate_totp(code)
      end

      it 'authenticates a recently created code' do
        code = @totp_helper.totp_code
        expect(do_invoke(code, instance)).to eq(true)
      end

      it 'authenticates a code entered with a space' do
        code = @totp_helper.totp_code.insert(3, ' ')
        expect(do_invoke(code, instance)).to eq(true)
      end

      it 'does not authenticate an old code' do
        code = @totp_helper.totp_code(1.minutes.ago.to_i)
        expect(do_invoke(code, instance)).to eq(false)
      end

      it 'prevents code reuse' do
        code = @totp_helper.totp_code
        expect(do_invoke(code, instance)).to eq(true)
        expect(do_invoke(code, instance)).to eq(false)
      end
    end

    it_behaves_like 'authenticate_totp', GuestUser.new
    it_behaves_like 'authenticate_totp', EncryptedUser.new
  end

  describe '#send_two_factor_authentication_code' do
    let(:instance) { build_guest_user }

    it 'raises an error by default' do
      expect { instance.send_two_factor_authentication_code(123) }.
        to raise_error(NotImplementedError)
    end

    it 'is overrideable' do
      def instance.send_two_factor_authentication_code(code)
        'Code sent'
      end
      expect(instance.send_two_factor_authentication_code(123)).to eq('Code sent')
    end
  end

  describe '#provisioning_uri' do

    shared_examples 'provisioning_uri' do |instance|
      it 'fails until generate_totp_secret is called' do
        expect { instance.provisioning_uri }.to raise_error(Exception)
      end

      describe 'with secret set' do
        before do
          instance.email = 'houdini@example.com'
          instance.otp_secret_key = instance.generate_totp_secret
        end

        it "returns uri with user's email" do
          expect(instance.provisioning_uri).
            to match(%r{otpauth://totp/houdini%40example.com\?secret=\w{32}})
        end

        it 'returns uri with issuer option' do
          expect(instance.provisioning_uri('houdini')).
            to match(%r{otpauth://totp/houdini\?secret=\w{32}$})
        end

        it 'returns uri with issuer option' do
          require 'cgi'
          uri = URI.parse(instance.provisioning_uri('houdini', issuer: 'Magic'))
          params = CGI.parse(uri.query)

          expect(uri.scheme).to eq('otpauth')
          expect(uri.host).to eq('totp')
          expect(uri.path).to eq('/Magic:houdini')
          expect(params['issuer'].shift).to eq('Magic')
          expect(params['secret'].shift).to match(/\w{32}/)
        end
      end
    end

    it_behaves_like 'provisioning_uri', GuestUser.new
    it_behaves_like 'provisioning_uri', EncryptedUser.new
  end

  describe '#generate_totp_secret' do
    shared_examples 'generate_totp_secret' do |klass|
      let(:instance) { klass.new }

      it 'returns a 32 character string' do
        secret = instance.generate_totp_secret

        expect(secret).to match(/\w{32}/)
      end
    end

    it_behaves_like 'generate_totp_secret', GuestUser
    it_behaves_like 'generate_totp_secret', EncryptedUser
  end

  describe '#enroll_totp!' do
    shared_examples 'enroll_totp!' do |klass|
      let(:instance) { klass.new }
      let(:secret) { instance.generate_totp_secret }
      let(:totp_helper) { TotpHelper.new(secret, instance.class.otp_length) }

      describe 'when given correct code' do
        it 'populates otp_secret_key column' do
          instance.enroll_totp!(secret, totp_helper.totp_code)

          expect(instance.otp_secret_key).to match(secret)
        end

        it 'updates the encrypted_otp_secret_key and otp totp_timestamp' do
          allow(instance).to receive(:update_columns).and_return(true)
          allow_any_instance_of(ROTP::TOTP).to receive(:verify).and_return(15445051)

          instance.enroll_totp!(secret, totp_helper.totp_code)

          expect(instance).to have_received(:update_columns)
            .with(totp_timestamp: 15445051, otp_secret_key: secret)
        end

        it 'returns true' do
          expect(instance.enroll_totp!(secret, totp_helper.totp_code)).to be true
        end
      end

      describe 'when given incorrect code' do
        it 'does not populate otp_secret_key' do
          instance.enroll_totp!(secret, '123')
          expect(instance.otp_secret_key).to be_nil
        end

        it 'returns false' do
          expect(instance.enroll_totp!(secret, '123')).to be false
        end
      end
    end

    it_behaves_like 'enroll_totp!', GuestUser
    it_behaves_like 'enroll_totp!', EncryptedUser
  end

  describe '#max_login_attempts' do
    let(:instance) { build_guest_user }

    before do
      @original_max_login_attempts = GuestUser.max_login_attempts
      GuestUser.max_login_attempts = 3
    end

    after { GuestUser.max_login_attempts = @original_max_login_attempts }

    it 'returns class setting' do
      expect(instance.max_login_attempts).to eq(3)
    end

    it 'returns false as boolean' do
      instance.second_factor_attempts_count = nil
      expect(instance.max_login_attempts?).to be_falsey
      instance.second_factor_attempts_count = 0
      expect(instance.max_login_attempts?).to be_falsey
      instance.second_factor_attempts_count = 1
      expect(instance.max_login_attempts?).to be_falsey
      instance.second_factor_attempts_count = 2
      expect(instance.max_login_attempts?).to be_falsey
    end

    it 'returns true as boolean after too many attempts' do
      instance.second_factor_attempts_count = 3
      expect(instance.max_login_attempts?).to be_truthy
      instance.second_factor_attempts_count = 4
      expect(instance.max_login_attempts?).to be_truthy
    end
  end

  describe '.has_one_time_password' do
    context 'when encrypted: true option is passed' do
      let(:instance) { EncryptedUser.new }

      it 'encrypts otp_secret_key' do
        instance.otp_secret_key = '2z6hxkdwi3uvrnpn'

        expect(instance.encrypted_otp_secret_key).to match(/.{44}/)
      end

      it 'does not encrypt a nil otp_secret_key' do
        instance.otp_secret_key = nil

        expect(instance.encrypted_otp_secret_key).to be_nil
      end

      it 'does not encrypt an empty otp_secret_key' do
        instance.otp_secret_key = ''

        expect(instance.encrypted_otp_secret_key).to eq ''
      end
    end
  end
end
