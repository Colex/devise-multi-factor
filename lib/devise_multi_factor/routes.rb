module ActionDispatch::Routing
  class Mapper
    protected

    def devise_two_factor_authentication(mapping, controllers)
      resource :two_factor_authentication, only: [:show, :update, :resend_code], path: mapping.path_names[:two_factor_authentication], controller: controllers[:two_factor_authentication] do
        collection { get 'resend_code' }
      end
    end

    def devise_totp(mapping, controllers)
      resource :totp, only: [:new, :create, :show, :destroy], path: mapping.path_names[:totp], controller: controllers[:totp]
    end
  end
end
