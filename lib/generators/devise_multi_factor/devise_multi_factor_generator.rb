module TwoFactorAuthenticatable
  module Generators
    class DeviseMultiFactorGenerator < Rails::Generators::NamedBase
      namespace "devise_multi_factor"

      desc "Adds :two_factor_authenticable directive in the given model. It also generates an active record migration."

      def inject_devise_multi_factor_content
        path = File.join("app", "models", "#{file_path}.rb")
        inject_into_file(path, "two_factor_authenticatable, :", :after => "devise :") if File.exists?(path)
        inject_into_file(path, "totp_enrollable, :", :after => "devise :") if File.exists?(path)
      end

      hook_for :orm
    end
  end
end
