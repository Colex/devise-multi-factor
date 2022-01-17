require 'spec_helper'

class MockUser
  def id
    15
  end
end

class MockUserWithRememberTFAToken
  def id
    45
  end

  def remember_tfa_token
    'generated_token'
  end
end

describe DeviseMultiFactor::RememberTFACookie do
  subject(:remember_tfa_cookie) { described_class.new }

  describe '#generate_cookie_data' do
    describe 'when resource does not define remember_tfa_token method' do
      let(:resource) { MockUser.new }

      it 'returns cookie value with expiration date' do
        result = remember_tfa_cookie.generate_cookie_data(
          resource,
          expires_at: Time.utc(2022, 1, 17, 19, 28, 0),
        )

        expect(JSON.parse(result)).to eql(
          'data' => {
            'resource_name' => 'MockUser',
            'resource_id' => 15,
            'remember_tfa_token' => '',
          },
          'expires_at' => '2022-01-17T19:28:00.000Z',
        )
      end
    end

    describe 'when resource defines remember_tfa_token method' do
      let(:resource) { MockUserWithRememberTFAToken.new }

      it 'returns cookie value with expiration date and tfa remember token' do
        result = remember_tfa_cookie.generate_cookie_data(
          resource,
          expires_at: Time.utc(2022, 1, 17, 19, 28, 0),
        )

        expect(JSON.parse(result)).to eql(
          'data' => {
            'resource_name' => 'MockUserWithRememberTFAToken',
            'resource_id' => 45,
            'remember_tfa_token' => 'generated_token',
          },
          'expires_at' => '2022-01-17T19:28:00.000Z',
        )
      end
    end
  end

  describe '#valid_cookie_data?' do
    let(:cookie_data) do
      {
        'data' => {
          'resource_name' => resource_name,
          'resource_id' => resource_id,
          'remember_tfa_token' => remember_tfa_token,
        },
        'expires_at' => '2022-01-17T19:28:00.000Z',
      }.to_json
    end
    let(:resource_name) { 'MockUserWithRememberTFAToken' }
    let(:resource_id) { 45 }
    let(:remember_tfa_token) { 'generated_token' }
    let(:resource) { MockUserWithRememberTFAToken.new }

    describe 'when cookie data has expired' do
      it 'returns false' do
        Timecop.freeze(Time.utc(2022, 1, 17, 19, 29, 0)) do
          result = remember_tfa_cookie.valid_cookie_data?(resource, cookie_data)
          expect(result).to be(false)
        end
      end
    end

    describe 'when cookie data has not expired' do
      let(:date_before_expiration) { Time.utc(2022, 1, 17, 19, 27, 0) }

      describe 'when resource class does not match' do
        let(:resource_name) { 'MockUser' }

        it 'returns false' do
          Timecop.freeze(date_before_expiration) do
            result = remember_tfa_cookie.valid_cookie_data?(resource, cookie_data)
            expect(result).to be(false)
          end
        end
      end

      describe 'when resource id does not match' do
        let(:resource_id) { 46 }

        it 'returns false' do
          Timecop.freeze(date_before_expiration) do
            result = remember_tfa_cookie.valid_cookie_data?(resource, cookie_data)
            expect(result).to be(false)
          end
        end
      end

      describe 'when remember tfa token does not match' do
        let(:remember_tfa_token) { '' }

        it 'returns false' do
          Timecop.freeze(date_before_expiration) do
            result = remember_tfa_cookie.valid_cookie_data?(resource, cookie_data)
            expect(result).to be(false)
          end
        end
      end

      describe 'when all cookie data matches' do
        it 'returns true' do
          Timecop.freeze(date_before_expiration) do
            result = remember_tfa_cookie.valid_cookie_data?(resource, cookie_data)
            expect(result).to be(true)
          end
        end
      end
    end
  end
end
