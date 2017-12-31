#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  #
  # Formats client requests and server responses
  #
  module Formatter
    #
    # Prepare a URL placeholder for the client
    #
    module Placeholder; end
    #
    # Prepare a HTTP request for the client
    #
    module Request; end
    #
    # Prepare a HTTP response for the client
    #
    module Response; end
  end
end
