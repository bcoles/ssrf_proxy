#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Add client request cookies to URI query string
      #
      class AddCookiesToURI
        include Logging

        #
        # @param [String] url destination URL
        # @param [Struct] client_request client HTTP request
        #
        def format(url, client_request)
          return url if client_request.headers['cookie'].nil?

          cookies = []
          logger.debug("Parsing request cookies: #{client_request.headers['cookie']}")
          client_request.headers['cookie'].split(/;\s*/).each do |c|
            cookies << c.to_s unless c.nil?
          end
          url = append_to_query_string(url.to_s, cookies.join('&').to_s)
          logger.info("Added cookies to URI: #{cookies.join('&')}")

          url
        end

        private

        def append_to_query_string(url, params)
          separator = url.include?('?') ? '&' : '?'
          "#{url}#{separator}#{params}"
        end
      end
    end
  end
end
