#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Request
      #
      # Forward client HTTP request cookies
      #
      class ForwardCookies
        include Logging

        #
        # @param [Struct] client_request client request headers
        # @param [Struct] ssrf_request SSRF HTTP request
        #
        def format(client_request, ssrf_request)
          new_cookie = []
          new_cookie << ssrf_request.headers['cookie'] unless ssrf_request.headers['cookie'].to_s.eql?('')

          unless client_request.headers['cookie'].nil?
            client_request.headers['cookie'].split(/;\s*/).each do |c|
              new_cookie << c.to_s unless c.nil?
            end
          end

          unless new_cookie.empty?
            ssrf_request.headers['cookie'] = new_cookie.uniq.join('; ')
            logger.info("Using cookie: #{new_cookie.join('; ')}")
          end

          ssrf_request
        end
      end
    end
  end
end
