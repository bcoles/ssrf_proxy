#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Reverse request URL
      #
      class Reverse
        include Logging

        def format(url, client_request)
          url.to_s.reverse
        end
      end
    end
  end
end
