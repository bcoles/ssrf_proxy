#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  #
  # Formats client requests and server responses
  #
  module Formatter
    #
    # Prepare a URL placeholder for the SSRF server
    #
    module Placeholder; end
    #
    # Prepare a client request for the SSRF server
    #
    module Request; end
    #
    # Prepare a SSRF server response for the client
    #
    module Response; end
  end
end
