#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Add Location header if redirected
      #
      class AddLocationHeader
        include Logging

        def format(client_request, response)
          if response['code'].to_i == 301 || response['code'].to_i == 302
            if response['headers'] !~ /^location:.*$/i
              location = nil
              if response['body'] =~ /This document may be found <a href="(.+)">/i
                location = $1
              elsif response['body'] =~ /The document has moved <a href="(.+)">/i
                location = $1
              end
              unless location.nil?
                response['headers'] << "Location: #{location}\n"
                logger.info("Added Location header: #{location}")
              end
            end
          end
          response
        end
      end
    end
  end
end
