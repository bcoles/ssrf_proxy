#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Replace URL with rotate 13
      #
      class Rot13
        include Logging

        def format(url, client_request)
          url.to_s.tr('A-Za-z', 'N-ZA-Mn-za-m')
        end
      end
    end
  end
end
