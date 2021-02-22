class GuestUser < TestUser
  def self.collection_name
    'guest_users'
  end

  has_one_time_password
end
