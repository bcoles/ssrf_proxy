#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Encode host IP address as integer
      #
      class EncodeIpInteger
        include Logging

        def format(url, client_request)
          host = URI.parse(url.to_s.split('?').first).host.to_s

          begin
            ip = IPAddress::IPv4.new(host)
          rescue
            logger.warn("Could not parse requested host as IPv4 address: #{host}")
            return url
          end

          new_ip = ip.to_u32.to_s

          url.gsub(host, new_ip)
        end
      end
    end
  end
end
