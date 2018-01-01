#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Replaces timeout HTTP status code 504 with 200.
      #
      class TimeoutOk
        include Logging

        #
        # @param [Struct] client_request client HTTP request
        # @param [Array] response HTTP response
        #
        def format(client_request, response)
          if response['code'].eql?('504')
            logger.info('Changed HTTP status code 504 to 200')
            response['code'] = 200
          end

          response
        end
      end
    end
  end
end
