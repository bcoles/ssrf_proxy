#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Append random URL hash string
      #
      class AppendHash
        include Logging

        def format(url, client_request)
          "#{url}##{rand(36**6).to_s(36)}"
        end
      end
    end
  end
end
