#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Convert placeholder URL scheme to https
      #
      class SSL
        include Logging

        def format(url, client_request)
          url.to_s.gsub(%r{^http://}, 'https://')
        end
      end
    end
  end
end
