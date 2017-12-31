#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Strip unwanted HTTP response headers
      #
      class StripHeaders
        include Logging

        #
        # @param headers [Array] Headers to remove from the response.
        #
        def initialize(headers: [])
          @headers = headers
        end

        def format(client_request, response)
          unless @headers.empty?
            headers = ''
            response['headers'].split(/\r?\n/).each do |line|
              header_name = line.split(': ').first
              header_value = line.split(': ')[1..-1].join(': ')
              if header_name.downcase.eql?('content-encoding')
                next if header_value.downcase.eql?('gzip')
              end

              if @headers.include?(header_name.downcase)
                logger.info("Removed response header: #{header_name}")
                next
              end
              headers << "#{header_name}: #{header_value}\n"
            end
            response['headers'] = headers
          end

          response
        end
      end
    end
  end
end
