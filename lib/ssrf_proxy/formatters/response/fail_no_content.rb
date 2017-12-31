#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Return 502 if matched response body is empty
      #
      class FailNoContent
        def format(client_request, response)
          if response['body'].to_s.eql?('')
            response['code'] = 502
            response['message'] = 'Bad Gateway'
            response['status_line'] = "HTTP/#{response['http_version']} #{response['code']} #{response['message']}"
          end

          response
        end
      end
    end
  end
end
