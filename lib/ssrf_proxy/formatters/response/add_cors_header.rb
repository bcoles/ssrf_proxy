#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Add wildcard CORS header
      #
      class AddCorsHeader
        def format(client_request, response)
          response['headers'] << "Access-Control-Allow-Origin: *\n"
          response
        end
      end
    end
  end
end
