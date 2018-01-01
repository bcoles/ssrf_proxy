#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Replaces the response body with regex matched content.
      #
      class Match
        include Logging

        #
        # Specify the match regex to extract content from the response body.
        #
        # @param [String] match Regex to match response body content.
        # (Default: \A(.*)\z)
        #
        def initialize(match: '\A(.+)\z')
          @match = match
        end

        #
        # @param [Struct] client_request client HTTP request
        # @param [Array] response HTTP response
        #
        def format(client_request, response)
          unless @match.nil?
            matches = response['body'].scan(/#{@match}/m)
            if !matches.empty?
              response['body'] = matches.flatten.first.to_s
              logger.info("Response body matches pattern '#{@match}'")
            else
              response['body'] = ''
              logger.warn("Response body does not match pattern '#{@match}'")
            end
          end

          response
        end
      end
    end
  end
end
