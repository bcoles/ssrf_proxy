#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Unescape response body
      #
      class Unescape
        include Logging

        def format(client_request, response)
          # unescape slashes
          response['body'] = response['body'].tr('\\', '\\')
          response['body'] = response['body'].gsub('\\/', '/')
          # unescape whitespace
          response['body'] = response['body'].gsub('\r', "\r")
          response['body'] = response['body'].gsub('\n', "\n")
          response['body'] = response['body'].gsub('\t', "\t")
          # unescape quotes
          response['body'] = response['body'].gsub('\"', '"')
          response['body'] = response['body'].gsub("\\'", "'")

          response
        end
      end
    end
  end
end
