#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  module Formatter
    module Response
      #
      # Guess mime type and add content-type header
      #
      # Replaces response content-type header with the
      # appropriate mime type (determined by the file
      # extension of the requested resource.)
      #
      class GuessMime
        include Logging

        def format(client_request, response)
          content_type = guess_mime(File.extname(client_request['url'].to_s.split('?').first))

          unless content_type.nil?
            logger.info("Using content-type: #{content_type}")
            if response['headers'] =~ /^content-type:.*$/i
              response['headers'].gsub!(/^content-type:.*$/i,
                                      "Content-Type: #{content_type}")
            else
              response['headers'] << "Content-Type: #{content_type}\n"
            end
          end

          response
        end

        private

        #
        # Guess content type based on file extension
        #
        # @param [String] ext File extension including dots
        #
        # @example Return mime type for extension '.png'
        #   guess_mime('favicon.png')
        #
        # @return [String] content-type value
        #
        def guess_mime(ext)
          content_types = WEBrick::HTTPUtils::DefaultMimeTypes
          common_content_types = { 'ico' => 'image/x-icon' }
          content_types.merge!(common_content_types)
          content_types.each do |k, v|
            return v.to_s if ext.eql?(".#{k}")
          end
          nil
        end
      end
    end
  end
end
