#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Replace response headers if response headers
      # are identified in the response body.
      #
      class DetectHeaders
        include Logging

        def format(client_request, response)
          headers = ''
          head = response['body'][0..8192] # use first 8192 byes
          detected_headers = head.scan(%r{HTTP/(1\.\d) (\d+) (.*?)\r?\n(.*?)\r?\n\r?\n}m)

          if detected_headers.empty?
            logger.info('Found no HTTP response headers in response body.')
            return response
          end

          # HTTP redirects may contain more than one set of HTTP response headers
          # Use the last
          logger.info("Found #{detected_headers.count} sets of HTTP response headers in response. Using last.")
          version = detected_headers.last[0]
          code = detected_headers.last[1]
          message = detected_headers.last[2]
          detected_headers.last[3].split(/\r?\n/).each do |line|
            if line =~ /^[A-Za-z0-9\-_\.]+: /
              k = line.split(': ').first
              v = line.split(': ')[1..-1].join(': ')
              headers << "#{k}: #{v}\n"
            else
              logger.warn('Could not use response headers in response body : Headers are malformed.')
              headers = ''
              break
            end
          end

          unless headers.eql?('')
            response['http_version'] = version
            response['code'] = code.to_i
            response['message'] = message
            response['headers'] = headers
            response['body'] = response['body'].split(/\r?\n\r?\n/)[detected_headers.count..-1].flatten.join("\n\n")
          end

          response
        end
      end
    end
  end
end
