#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Convert placeholder to SHA1 hash
      #
      class SHA1
        include Logging

        def format(url, client_request)
          Digest::SHA1.hexdigest(url.to_s)
        end
      end
    end
  end
end
