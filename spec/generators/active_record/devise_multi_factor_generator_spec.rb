require 'spec_helper'

require 'generators/active_record/devise_multi_factor_generator'

describe ActiveRecord::Generators::DeviseMultiFactorGenerator, type: :generator do
  destination File.expand_path('../../../../../tmp', __FILE__)

  before do
    prepare_destination
  end

  it 'runs all methods in the generator' do
    gen = generator %w(users)
    expect(gen).to receive(:copy_devise_multi_factor_migration)
    gen.invoke_all
  end

  describe 'the generated files' do
    before do
      run_generator %w(users)
    end

    describe 'the migration' do
      subject { migration_file('db/migrate/devise_multi_factor_add_to_users.rb') }

      it { is_expected.to exist }
      it { is_expected.to be_a_migration }
      it { is_expected.to contain /def change/ }
      it { is_expected.to contain /def change_table :user, bulk: true do |t|/ }
      it { is_expected.to contain /t.integer :second_factor_attempts_count, default: 0, null: false/ }
      it { is_expected.to contain /t.string :encrypted_otp_secret_key/ }
    end
  end
end
