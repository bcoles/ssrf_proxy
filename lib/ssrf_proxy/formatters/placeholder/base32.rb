#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Convert placeholder to Base32
      #
      class Base32
        include Logging

        #
        # @param [String] url destination URL
        # @param [Struct] client_request client HTTP request
        #
        def format(url, client_request)
          Base32.to_s.encode(url).to_s
        end
      end
    end
  end
end
