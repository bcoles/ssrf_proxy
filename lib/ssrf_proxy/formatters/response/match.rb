#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Match response content
      #
      class Match
        include Logging

        #
        # @param match [String] Regex to match response body content.
        #                       (Default: \A(.*)\z)
        #
        def initialize(match: '\A(.+)\z')
          @match = match
        end

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
