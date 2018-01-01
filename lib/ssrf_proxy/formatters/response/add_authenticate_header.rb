#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Add WWW-Authenticate header
      #
      class AddAuthenticateHeader
        include Logging

        #
        # @param [Struct] client_request client HTTP request
        # @param [Array] response HTTP response
        #
        def format(client_request, response)
          if response['code'].to_i == 401
            if response['headers'] !~ /^WWW-Authenticate:.*$/i
              auth_uri = URI.parse(client_request['url'].to_s.split('?').first)
              realm = "#{auth_uri.host}:#{auth_uri.port}"
              response['headers'] << "WWW-Authenticate: Basic realm=\"#{realm}\"\n"
              logger.info("Added WWW-Authenticate header for realm: #{realm}")
            end
          end

          response
        end
      end
    end
  end
end
