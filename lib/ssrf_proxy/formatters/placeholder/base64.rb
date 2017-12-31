#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Convert placeholder to Base64
      #
      class Base64
        include Logging

        def format(url, client_request)
          Base64.to_s.strict_encode64(url)
        end
      end
    end
  end
end
