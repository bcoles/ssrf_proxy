#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Request
      #
      # Forward client HTTP request headers
      #
      class ForwardHeaders
        include Logging

        def format(client_request, ssrf_request)
          return ssrf_request if client_request.headers.empty?

          client_request.headers.each do |k, v|
            next if k.eql?('proxy-connection')
            next if k.eql?('proxy-authorization')
            if v.is_a?(Array)
              ssrf_request.headers[k.downcase] = v.flatten.first
            elsif v.is_a?(String)
              ssrf_request.headers[k.downcase] = v.to_s
            end
          end

          ssrf_request
        end
      end
    end
  end
end
