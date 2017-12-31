#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # URL encode client request
      #
      class URLEncode
        include Logging

        def format(url, client_request)
          CGI.escape(url).gsub(/\+/, '%20').to_s
        end
      end
    end
  end
end
