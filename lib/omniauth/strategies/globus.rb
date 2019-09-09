# frozen_string_literal: true

require "jwt"
require "omniauth/strategies/oauth2"
require "uri"

module OmniAuth
  module Strategies
    class Globus < OmniAuth::Strategies::OAuth2
      option :name, "globus"
      option :issuer, "https://auth.globus.org"
      option :scope, "openid profile email"
      option :authorize_options, %i[access_type login_hint prompt request_visible_actions scope state redirect_uri include_granted_scopes openid_realm device_id device_name]

      option(:client_options, site: 'https://auth.globus.org',
                              authorize_url: 'https://auth.globus.org/v2/oauth2/authorize',
                              token_url: 'https://auth.globus.org/v2/oauth2/token',
                              discovery_endpoint: "https://auth.globus.org/.well-known/openid-configuration",
                              authorization_endpoint: "https://auth.globus.org/v2/oauth2/authorize",
                              token_endpoint: "https://auth.globus.org/v2/oauth2/token",
                              userinfo_endpoint: "https://auth.globus.org/v2/oauth2/userinfo",
                              jwks_uri: "https://auth.globus.org/jwk.json",
                              end_session_endpoint: "https://auth.globus.org/v2/oauth2/token/revoke")

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |k|
            params[k] = request.params[k.to_s] unless [nil, ''].include?(request.params[k.to_s])
          end

          params[:scope] = get_scope(params)
          params[:access_type] = 'offline' if params[:access_type].nil?
          params['openid.realm'] = params.delete(:openid_realm) unless params[:openid_realm].nil?

          session['omniauth.state'] = params[:state] if params[:state]
        end
      end

      uid { raw_info['sub'] }

      info do
        prune!(
          name: raw_info['name'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          email: raw_info['email']
        )
      end

      extra do
        hash = {}
        hash[:id_token] = access_token['id_token']
        if !access_token['id_token'].nil?
          decoded = ::JWT.decode(access_token['id_token'], nil, false).first

          # We have to manually verify the claims because the third parameter to
          # JWT.decode is false since no verification key is provided.
          ::JWT::Verify.verify_claims(decoded,
                                      verify_iss: true,
                                      iss: options.issuer,
                                      verify_expiration: true)

          hash[:id_info] = decoded
        end
        hash[:raw_info] = raw_info unless skip_info?
        prune! hash
      end

      def raw_info
        @raw_info ||= access_token.get(options.client_options.userinfo_endpoint).parsed
      end

      def custom_build_access_token
        get_access_token(request)
      end

      alias build_access_token custom_build_access_token

      private

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def get_access_token(request)
        verifier = request.params['code']
        redirect_uri = request.params['redirect_uri']
        if verifier && request.xhr?
          client_get_token(verifier, redirect_uri || 'postmessage')
        elsif verifier
          client_get_token(verifier, redirect_uri || callback_url)
        elsif verify_token(request.params['access_token'])
          ::OAuth2::AccessToken.from_hash(client, request.params.dup)
        elsif request.content_type =~ /json/i
          begin
            body = JSON.parse(request.body.read)
            request.body.rewind # rewind request body for downstream middlewares
            verifier = body && body['code']
            client_get_token(verifier, 'postmessage') if verifier
          rescue JSON::ParserError => e
            warn "[omniauth globus] JSON parse error=#{e}"
          end
        end
      end

      def client_get_token(verifier, redirect_uri)
        client.auth_code.get_token(verifier, get_token_options(redirect_uri), get_token_params)
      end

      def get_token_params
        deep_symbolize(options.auth_token_params || {})
      end

      def get_scope(params)
        raw_scope = params[:scope] || options.scope
        scope_list = raw_scope.split(" ").map { |item| item.split(",") }.flatten
        scope_list.join(" ")
      end

      def get_token_options(redirect_uri = "")
        { redirect_uri: redirect_uri }.merge(token_params.to_hash(symbolize_keys: true))
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

      def strip_unnecessary_query_parameters(query_parameters)
        # strip `sz` parameter (defaults to sz=50) which overrides `image_size` options
        return nil if query_parameters.nil?

        params = CGI.parse(query_parameters)
        stripped_params = params.delete_if { |key| key == 'sz' }

        # don't return an empty Hash since that would result
        # in URLs with a trailing ? character: http://image.url?
        return nil if stripped_params.empty?

        URI.encode_www_form(stripped_params)
      end

      def verify_token(access_token)
        return false unless access_token

        raw_response = client.request(:get, options.client_options.userinfo_endpoint,
                                      params: { access_token: access_token }).parsed
        raw_response["aud"] == options.client_id
      end
    end
  end
end
