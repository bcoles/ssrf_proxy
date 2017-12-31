#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Append a random value to the client request query string
      #
      class AddCacheBusterToURI
        include Logging

        def format(url, client_request)
          junk = "#{rand(36**6).to_s(36)}=#{rand(36**6).to_s(36)}"
          append_to_query_string(url.to_s, junk)
        end

        private

        def append_to_query_string(url, params)
          separator = url.include?('?') ? '&' : '?'
          "#{url}#{separator}#{params}"
        end
      end
    end
  end
end
