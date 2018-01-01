#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Decode HTML entities in response body
      #
      class DecodeHTML
        #
        # @param [Struct] client_request client HTTP request
        # @param [Array] response HTTP response
        #
        def format(client_request, response)
          response['body'] = HTMLEntities.new.decode(response['body'])
          response
        end
      end
    end
  end
end
