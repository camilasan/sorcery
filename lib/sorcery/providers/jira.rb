module Sorcery
  module Providers
    # This class adds support for OAuth with Jira
    #
    #   config.jira.key = <key>
    #   config.jira.secret = <secret>
    #   ...
    #
    class Jira < Base

      include Protocols::Oauth

      attr_accessor :access_token_path, :authorize_path, :request_token_path,
                    :user_info_path


      def initialize
        @configuration = {
            site: 'http://localhost:2990/jira/plugins/servlet/oauth',
            authorize_path: '/authorize',
            request_token_path: '/request-token',
            access_token_path: '/access-token',
            signature_method: 'RSA-SHA1',
            consumer_key: 'test',
            private_key_file: 'rsakey.pem'
        }
        @user_info_path = '/users/me'
      end

      # Override included get_consumer method to provide authorize_path
      def get_consumer
        ::OAuth::Consumer.new(@key, @secret, @configuration)
      end

      def get_user_hash(access_token)
        response = access_token.get(user_info_path)

        {}.tap do |h|
          h[:user_info] = JSON.parse(response.body)['users'].first
          h[:uid] = user_hash[:user_info]['id'].to_s
        end
      end

      # calculates and returns the url to which the user should be redirected,
      # to get authenticated at the external provider's site.
      def login_url(params, session)
        req_token = get_request_token
        session[:request_token]         = req_token.token
        session[:request_token_secret]  = req_token.secret

        #it was like that -> redirect_to authorize_url({ request_token: req_token.token, request_token_secret: req_token.secret })
        #for some reason Jira does not need these parameters

        get_request_token(
          session[:request_token],
          session[:request_token_secret]
        ).authorize_url
      end

      # tries to login the user from access token
      def process_callback(params, session)
        args = {
          oauth_verifier:       params[:oauth_verifier],
          request_token:        session[:request_token],
          request_token_secret: session[:request_token_secret]
        }

        args.merge!({ code: params[:code] }) if params[:code]
        get_access_token(args)
      end

    end
  end
end
