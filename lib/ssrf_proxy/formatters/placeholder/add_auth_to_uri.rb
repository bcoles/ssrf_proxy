#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Placeholder
      #
      # Use client request basic authentication credentials in request URI.
      #
      class AddAuthToURI
        include Logging

        #
        # @param [String] url destination URL
        # @param [Struct] client_request client HTTP request
        #
        def format(url, client_request)
          if client_request.headers['authorization'].to_s.downcase.start_with?('basic ')
            logger.debug("Parsing basic authentication header: #{client_request.headers['authorization']}")
            begin
              creds = client_request.headers['authorization'].split(' ')[1]
              user = ::Base64.decode64(creds).chomp
              url.gsub!(%r{://}, "://#{CGI.escape(user).gsub(/\+/, '%20').gsub('%3A', ':')}@")
              logger.info("Using basic authentication credentials: #{user}")
            rescue => e
puts e.message
              logger.warn('Could not parse request authorization header: ' \
                          "#{client_request.headers['authorization']}")
            end
          end
          url
        end
      end
    end
  end
end
