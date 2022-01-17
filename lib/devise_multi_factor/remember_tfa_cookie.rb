module DeviseMultiFactor
  class RememberTFACookie

    def generate_cookie_data(resource, expires_at:)
      { 'data' => generate_resource_data(resource) }
        .merge('expires_at' => expires_at)
        .to_json
    end

    def valid_cookie_data?(resource, cookie_data)
      return false if cookie_data.nil?

      parsed_data = JSON.parse(cookie_data)
      expires_at = parse_time(parsed_data['expires_at'])
      return false if expires_at.nil? || expires_at < Time.current

      expected_data = generate_resource_data(resource)
      parsed_data['data'] == expected_data
    rescue JSON::ParserError
      false
    end

    private

    def generate_resource_data(resource)
      {
        'resource_name' => resource.class.to_s,
        'resource_id' => resource.public_send(Devise.second_factor_resource_id),
        'remember_tfa_token' => resource.try(:remember_tfa_token) || '',
      }
    end

    def parse_time(time_str)
      Time.parse(time_str)
    rescue StandardError
      nil
    end
  end
end
