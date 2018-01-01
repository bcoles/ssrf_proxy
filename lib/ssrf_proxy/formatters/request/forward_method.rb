#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Request
      #
      # Forward client HTTP request method
      #
      class ForwardMethod
        include Logging
        def initialize
          @SUPPORTED_METHODS = %w[GET HEAD DELETE POST PUT OPTIONS].freeze
        end

        #
        # @param [Struct] client_request client request headers
        # @param [Struct] ssrf_request SSRF HTTP request
        #
        def format(client_request, ssrf_request)
          unless @SUPPORTED_METHODS.include?(client_request.method)
            raise SSRFProxy::HTTP::Error::InvalidClientRequest,
                  "Request method '#{client_request[:method]}' is not supported"
          end

          ssrf_request.method = client_request[:method]
          ssrf_request
        end
      end
    end
  end
end
