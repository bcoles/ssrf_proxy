#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Strip unwanted HTTP response headers from the response
      #
      class StripHeaders
        include Logging

        #
        # Specify the unwanted HTTP headers to be removed from the response.
        #
        # @param [Array] headers HTTP headers to remove from the response.
        #
        def initialize(headers: [])
          @headers = headers
        end

        #
        # @param [Struct] client_request client HTTP request
        # @param [Array] response HTTP response
        #
        def format(client_request, response)
          return response if @headers.empty?
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

          response
        end
      end
    end
  end
end
