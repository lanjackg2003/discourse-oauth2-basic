# frozen_string_literal: true

class OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"

  # 完全覆盖默认的授权参数
  def authorize_params
    params = {
      'appid' => options.client_id,
      'response_type' => 'code',
      'redirect_uri' => callback_url
    }
    # 添加 state 参数
    if options.provider_ignores_state
      logger.debug("Provider ignores state")
    else
      params['state'] = state
    end
    params
  end

  # 覆盖默认的 state 参数生成方法
  def state
    @state ||= SecureRandom.hex(24)
  end

  uid do
    if path = SiteSetting.oauth2_callback_user_id_path.split(".")
      recurse(access_token, [*path]) if path.present?
    end
  end

  info do
    if paths = SiteSetting.oauth2_callback_user_info_paths.split("|")
      result = Hash.new
      paths.each do |p|
        segments = p.split(":")
        if segments.length == 2
          key = segments.first
          path = [*segments.last.split(".")]
          result[key] = recurse(access_token, path)
        end
      end
      result
    end
  end

  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end

  def recurse(obj, keys)
    return nil if !obj
    k = keys.shift
    result = obj.respond_to?(k) ? obj.send(k) : obj[k]
    keys.empty? ? result : recurse(result, keys)
  end
end
