#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Convert placeholder to MD5 hash
      #
      class MD5
        include Logging

        def format(url, client_request)
          md5 = Digest::MD5.new
          md5.update(url.to_s)
          md5.hexdigest.to_s
        end
      end
    end
  end
end
