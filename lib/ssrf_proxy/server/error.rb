#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  class Server
    #
    # SSRFProxy::Server errors
    #
    module Error
      #
      # SSRFProxy::Server errors
      #
      class Error < StandardError; end

      exceptions = %w[
        InvalidSsrf
        ProxyRecursion
        AddressInUse
        RemoteProxyUnresponsive
        RemoteHostUnresponsive
      ]
      exceptions.each do |e|
        const_set(e, Class.new(Error))
      end
    end
  end
end
