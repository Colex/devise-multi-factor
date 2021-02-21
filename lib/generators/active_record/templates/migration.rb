class DeviseMultiFactorAddTo<%= table_name.camelize %> < ActiveRecord::Migration[6.1]
  def change
    change_table :<%= table_name %>, bulk: true do |t|
      t.integer :second_factor_attempts_count, default: 0, null: false
      t.string :otp_secret_ciphertext
      t.string :direct_otp
      t.datetime :direct_otp_sent_at
      t.integer :totp_timestamp
    end
  end
end
