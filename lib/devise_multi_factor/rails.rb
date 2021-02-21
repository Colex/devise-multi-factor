module DeviseMultiFactor
  class Engine < ::Rails::Engine
    ActiveSupport.on_load(:action_controller) do
      include DeviseMultiFactor::Controllers::Helpers
    end
  end
end
