#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Append 'method=get' and '_method=get' to request query string
      #
      class AppendMethodGet
        include Logging

        def format(url, client_request)
          append_to_query_string(url.to_s, 'method=get&_method=get')
        end
      end
    end
  end
end
