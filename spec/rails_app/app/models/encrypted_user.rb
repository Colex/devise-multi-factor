class EncryptedUser < TestUser
  def self.collection_name
    'encrypted_users'
  end

  has_one_time_password
end
