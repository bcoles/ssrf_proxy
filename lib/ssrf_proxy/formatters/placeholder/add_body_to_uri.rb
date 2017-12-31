#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Add client request body to URI query string
      #
      class AddBodyToURI
        include Logging

        def format(url, client_request)
          unless client_request[:body].eql?('')
            logger.debug("Parsing request body: #{client_request.body}")
            url = append_to_query_string(url.to_s, client_request.body.to_s)
            logger.info("Added request body to URI: #{client_request.body.inspect}")
          end
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
