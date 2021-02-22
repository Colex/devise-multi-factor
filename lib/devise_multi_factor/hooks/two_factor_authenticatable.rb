Warden::Manager.after_authentication do |resource, auth, options|
  if auth.env["action_dispatch.cookies"]
    expected_cookie_value = "#{resource.class}-#{resource.public_send(Devise.second_factor_resource_id)}"
    actual_cookie_value = auth.env["action_dispatch.cookies"].signed[DeviseMultiFactor::REMEMBER_TFA_COOKIE_NAME]
    bypass_by_cookie = actual_cookie_value == expected_cookie_value
  end

  if resource.respond_to?(:need_two_factor_authentication?) && !bypass_by_cookie
    if auth.session(options[:scope])[DeviseMultiFactor::NEED_AUTHENTICATION] = resource.need_two_factor_authentication?(auth.request)
      resource.send_new_otp if resource.send_new_otp_after_login?
    end
  end
end

Warden::Manager.before_logout do |resource, auth, _options|
  auth.cookies.delete DeviseMultiFactor::REMEMBER_TFA_COOKIE_NAME if Devise.delete_cookie_on_logout
end
