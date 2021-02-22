module AuthenticatedModelHelper
  def build_guest_user
    GuestUser.new
  end

  def create_user(type = 'encrypted', attributes = {})
    User.create!(valid_attributes(attributes))
  end

  def create_admin
    Admin.create!(valid_attributes.except(:nickname))
  end

  def valid_attributes(attributes={})
    {
      nickname: 'Marissa',
      email: generate_unique_email,
      password: 'password',
      password_confirmation: 'password'
    }.merge(attributes)
  end

  def generate_unique_email
    email_id = User.order(id: :desc).first&.id.to_i + 1
    "user#{email_id}@example.com"
  end
end

RSpec.configuration.send(:include, AuthenticatedModelHelper)
