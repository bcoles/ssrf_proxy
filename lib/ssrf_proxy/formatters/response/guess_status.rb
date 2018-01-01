#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
    
module SSRFProxy
  module Formatter
    module Response
      #
      # Guess response HTTP status code and message
      #
      # Replaces response status code and message
      # headers (determined by common strings in the
      # response body, such as 404 Not Found.)
      #
      class GuessStatus
        include Logging

        #
        # @param [Struct] client_request client HTTP request
        # @param [Array] response HTTP response
        #
        def format(client_request, response)
          head = response['body'][0..8192]
          status = guess_status(head)

          unless status.empty?
            response['code'] = status['code']
            response['message'] = status['message']
            logger.info("Using HTTP response status: #{response['code']} #{response['message']}")
          end

          response
        end

        private

        #
        # Guess HTTP response status code and message based
        # on common strings in the response body such
        # as a default title or exception error message
        #
        # @param [String] response HTTP response
        #
        # @return [Hash] result HTTP response code and message
        #
        def guess_status(response)
          result = {}
          # response status code returned by php-simple-proxy and php-json-proxy
          if response =~ /"status":{"http_code":([\d]+)}/
            result['code'] = $1
            result['message'] = ''
          # generic page titles containing HTTP status
          elsif response =~ />301 Moved</ || response =~ />Document Moved</ || response =~ />Object Moved</ || response =~ />301 Moved Permanently</
            result['code'] = 301
            result['message'] = 'Document Moved'
          elsif response =~ />302 Found</ || response =~ />302 Moved Temporarily</
            result['code'] = 302
            result['message'] = 'Found'
          elsif response =~ />400 Bad Request</
            result['code'] = 400
            result['message'] = 'Bad Request'
          elsif response =~ />401 Unauthorized</
            result['code'] = 401
            result['message'] = 'Unauthorized'
          elsif response =~ />403 Forbidden</
            result['code'] = 403
            result['message'] = 'Forbidden'
          elsif response =~ />404 Not Found</
            result['code'] = 404
            result['message'] = 'Not Found'
          elsif response =~ />The page is not found</
            result['code'] = 404
            result['message'] = 'Not Found'
          elsif response =~ />413 Request Entity Too Large</
            result['code'] = 413
            result['message'] = 'Request Entity Too Large'
          elsif response =~ />500 Internal Server Error</
            result['code'] = 500
            result['message'] = 'Internal Server Error'
          elsif response =~ />503 Service Unavailable</
            result['code'] = 503
            result['message'] = 'Service Unavailable'
          # getaddrinfo() errors
          elsif response =~ /(getaddrinfo|getaddrinfo failed): /
            if response =~ /getaddrinfo( failed)?: nodename nor servname provided/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /getaddrinfo( failed)?: Name or service not known/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            end
          # getnameinfo() errors
          elsif response =~ /getnameinfo failed: /
            result['code'] = 502
            result['message'] = 'Bad Gateway'
          # PHP 'failed to open stream' errors
          elsif response =~ /failed to open stream: /
            # HTTP request failed! HTTP/[version] [code] [message]
            if response =~ %r{failed to open stream: HTTP request failed! HTTP\/(0\.9|1\.0|1\.1) ([\d]+) }
              result['code'] = $2.to_s
              result['message'] = ''
              if response =~ %r{failed to open stream: HTTP request failed! HTTP/(0\.9|1\.0|1\.1) [\d]+ ([a-zA-Z ]+)}
                result['message'] = $2.to_s
              end
            # No route to host
            elsif response =~ /failed to open stream: No route to host in/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # Connection refused
            elsif response =~ /failed to open stream: Connection refused in/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # Connection timed out
            elsif response =~ /failed to open stream: Connection timed out/
              result['code'] = 504
              result['message'] = 'Timeout'
            # Success - This likely indicates an SSL/TLS connection failure
            elsif response =~ /failed to open stream: Success in/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            end
          # Java 'java.net' exceptions
          elsif response =~ /java\.net\.[^\s]*Exception: /
            if response =~ /java\.net\.ConnectException: No route to host/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /java\.net\.ConnectException: Connection refused/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /java\.net\.ConnectException: Connection timed out/
              result['code'] = 504
              result['message'] = 'Timeout'
            elsif response =~ /java\.net\.UnknownHostException: Invalid hostname/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /java\.net\.SocketException: Network is unreachable/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /java\.net\.SocketException: Connection reset/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /java\.net\.SocketTimeoutException: Connection timed out/
              result['code'] = 504
              result['message'] = 'Timeout'
            end
          # C errno
          elsif response =~ /\[Errno -?[\d]{1,5}\]/
            if response =~ /\[Errno -2\] Name or service not known/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 101\] Network is unreachable/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 104\] Connection reset by peer/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 110\] Connection timed out/
              result['code'] = 504
              result['message'] = 'Timeout'
            elsif response =~ /\[Errno 111\] Connection refused/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 113\] No route to host/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 11004\] getaddrinfo failed/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 10053\] An established connection was aborted/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 10054\] An existing connection was forcibly closed/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 10055\] An operation on a socket could not be performed/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 10060\] A connection attempt failed/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /\[Errno 10061\] No connection could be made/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            end
          # Python urllib errors
          elsif response =~ /HTTPError: HTTP Error \d+/
            if response =~ /HTTPError: HTTP Error 400: Bad Request/
              result['code'] = 400
              result['message'] = 'Bad Request'
            elsif response =~ /HTTPError: HTTP Error 401: Unauthorized/
              result['code'] = 401
              result['message'] = 'Unauthorized'
            elsif response =~ /HTTPError: HTTP Error 402: Payment Required/
              result['code'] = 402
              result['message'] = 'Payment Required'
            elsif response =~ /HTTPError: HTTP Error 403: Forbidden/
              result['code'] = 403
              result['message'] = 'Forbidden'
            elsif response =~ /HTTPError: HTTP Error 404: Not Found/
              result['code'] = 404
              result['message'] = 'Not Found'
            elsif response =~ /HTTPError: HTTP Error 405: Method Not Allowed/
              result['code'] = 405
              result['message'] = 'Method Not Allowed'
            elsif response =~ /HTTPError: HTTP Error 410: Gone/
              result['code'] = 410
              result['message'] = 'Gone'
            elsif response =~ /HTTPError: HTTP Error 500: Internal Server Error/
              result['code'] = 500
              result['message'] = 'Internal Server Error'
            elsif response =~ /HTTPError: HTTP Error 502: Bad Gateway/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            elsif response =~ /HTTPError: HTTP Error 503: Service Unavailable/
              result['code'] = 503
              result['message'] = 'Service Unavailable'
            elsif response =~ /HTTPError: HTTP Error 504: Gateway Time-?out/
              result['code'] = 504
              result['message'] = 'Timeout'
            end
          # Ruby exceptions
          elsif response =~ /Errno::[A-Z]+/
            # Connection refused
            if response =~ /Errno::ECONNREFUSED/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # No route to host
            elsif response =~ /Errno::EHOSTUNREACH/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # Connection timed out
            elsif response =~ /Errno::ETIMEDOUT/
              result['code'] = 504
              result['message'] = 'Timeout'
            end
          # ASP.NET System.Net.WebClient errors
          elsif response =~ /System\.Net\.WebClient/
            # The remote server returned an error: ([code]) [message].
            if response =~ /WebException: The remote server returned an error: \(([\d+])\) /
              result['code'] = $1.to_s
              result['message'] = ''
              if response =~ /WebException: The remote server returned an error: \(([\d+])\) ([a-zA-Z ]+)\./
                result['message'] = $2.to_s
              end
            # Could not resolve hostname
            elsif response =~ /WebException: The remote name could not be resolved/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # Remote server denied connection (port closed)
            elsif response =~ /WebException: Unable to connect to the remote server/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # This likely indicates a plain-text connection to a HTTPS or non-HTTP service
            elsif response =~ /WebException: The underlying connection was closed: An unexpected error occurred on a receive/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # This likely indicates a HTTPS connection to a plain-text HTTP or non-HTTP service
            elsif response =~ /WebException: The underlying connection was closed: An unexpected error occurred on a send/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # The operation has timed out
            elsif response =~ /WebException: The operation has timed out/
              result['code'] = 504
              result['message'] = 'Timeout'
            end
          # Generic error messages
          elsif response =~ /(Connection refused|No route to host|Connection timed out) - connect\(\d\)/
            # Connection refused
            if response =~ /Connection refused - connect\(\d\)/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # No route to host
            elsif response =~ /No route to host - connect\(\d\)/
              result['code'] = 502
              result['message'] = 'Bad Gateway'
            # Connection timed out
            elsif response =~ /Connection timed out - connect\(\d\)/
              result['code'] = 504
              result['message'] = 'Timeout'
            end
          end

          result
        end    
      end
    end
  end
end
