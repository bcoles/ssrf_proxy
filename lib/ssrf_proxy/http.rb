#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  #
  # SSRFProxy::HTTP object takes information required to connect
  # to a HTTP(S) server vulnerable to Server-Side Request Forgery
  # (SSRF) and issue arbitrary HTTP requests via the vulnerable
  # server.
  #
  # Once configured, the #send_uri and #send_request methods can
  # be used to tunnel HTTP requests through the vulnerable server.
  #
  # Several request modification options can be used to format
  # the HTTP request appropriately for the SSRF vector and
  # the destination web server accessed via the SSRF.
  #
  # Several response modification options can be used to infer
  # information about the response from the destination server
  # and format the response such that the vulnerable intermediary
  # server is mostly transparent to the client initiating the
  # HTTP request.
  #
  # Refer to the wiki for more information about configuring the
  # SSRF, requestion modification, response modification, and
  # example configurations:
  # https://github.com/bcoles/ssrf_proxy/wiki/Configuration
  #
  class HTTP < SSRF
    # @return [URI] SSRF URL
    attr_reader :url
    # @return [String] SSRF request HTTP method
    attr_reader :method
    # @return [Hash] SSRF request HTTP headers
    attr_reader :headers
    # @return [String] SSRF request HTTP body
    attr_reader :post_data

    #
    # SSRFProxy::HTTP specifies SSRF request and connection details,
    # such as the request URL, headers, body, connection timeout
    # and whether to connect using transport layer security.
    #
    # @param [String] url [String] Target URL vulnerable to SSRF
    #
    # @param [String] file [String] Load HTTP request from a file
    #
    # @param [String] proxy [String] Use a proxy to connect to the server.
    # (Supported proxies: http, https, socks)
    #
    # @param [Boolean] ssl Connect using SSL/TLS
    #
    # @param [Integer] timeout Connection timeout in seconds (Default: 10)
    #
    # @param [Boolean] insecure Skip server SSL certificate validation
    #
    # @param [String] placeholder Placeholder indicating SSRF insertion point.
    # (Default: xxURLxx)
    #
    # @param [String] headers HTTP request headers (separated by '\n')
    # (Default: none)
    #
    # @param [String] method HTTP method (GET/HEAD/DELETE/POST/PUT/OPTIONS)
    # (Default: GET)
    #
    # @param [String] post_data HTTP post data
    #
    # @param [String] user HTTP basic authentication credentials
    #
    # @param [String] cookie HTTP request cookies (separated by ';')
    #
    # @param [String] user_agent HTTP user-agent (Default: none)
    #
    #
    #
    # @example Configure SSRF with URL, GET method
    #   SSRFProxy::HTTP.new(url: 'http://example.local/?url=xxURLxx')
    #
    # @example Configure SSRF with URL, POST method
    #   SSRFProxy::HTTP.new(url: 'http://example.local/',
    #                       method: 'POST',
    #                       post_data: 'url=xxURLxx')
    #
    # @example Configure SSRF with raw HTTP request file
    #   SSRFProxy::HTTP.new(file: 'ssrf.txt')
    #
    # @example Configure SSRF with raw HTTP request file and force SSL/TLS
    #   SSRFProxy::HTTP.new(file: 'ssrf.txt', ssl: true)
    #
    # @example Configure SSRF with raw HTTP request StringIO
    #   SSRFProxy::HTTP.new(file: StringIO.new("GET http://example.local/?url=xxURLxx HTTP/1.1\n\n"))
    #
    #
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidSsrfRequest]
    #        Invalid SSRF request specified.
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidUpstreamProxy]
    #        Invalid upstream proxy specified.
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidSsrfRequestMethod]
    #        Invalid SSRF request method specified.
    #        Supported methods: GET, HEAD, DELETE, POST, PUT, OPTIONS.
    #
    # @raise [SSRFProxy::HTTP::Error::NoUrlPlaceholder]
    #        'xxURLxx' URL placeholder must be specified in the
    #         SSRF request URL or body.
    #
    def initialize(url: nil,
                   file: nil,
                   proxy: nil,
                   ssl: false,
                   timeout: 10,
                   insecure: false,
                   method: 'GET',
                   placeholder: 'xxURLxx',
                   headers: {},
                   post_data: nil,
                   cookie: nil,
                   user: nil,
                   user_agent: nil)

      @SUPPORTED_METHODS = %w[GET HEAD DELETE POST PUT OPTIONS].freeze

      # SSRF request options
      @placeholder = placeholder.to_s || 'xxURLxx'
      @method = method.to_s.upcase || 'GET'
      @headers ||= {}
      @post_data = post_data.to_s || ''
      @user = ''
      @pass = ''

      # ensure either a URL or file path was provided
      if url.to_s.eql?('') && file.to_s.eql?('')
        raise ArgumentError,
              "Option 'url' or 'file' must be provided."
      end
      unless url.to_s.eql?('') || file.to_s.eql?('')
        raise ArgumentError,
              "Options 'url' and 'file' are mutually exclusive."
      end

      # parse HTTP request file
      unless file.to_s.eql?('')
        if file.is_a?(String)
          if File.exist?(file) && File.readable?(file)
            http = File.read(file).to_s
          else
            raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
                  "Invalid SSRF request specified : Could not read file #{file.inspect}"
          end
        elsif file.is_a?(StringIO)
          http = file.read
        end

        req = parse_http_request(http)
        url = req['uri']
        @method = req['method']
        @headers = {}
        req['headers'].each do |k, v|
          @headers[k.downcase] = v.flatten.first
        end
        @headers.delete('host')
        @post_data = req['body']
      end

      # parse SSRF URL
      begin
        @url = URI.parse(url.to_s)
      rescue URI::InvalidURIError
        raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
              'Invalid SSRF request specified : Could not parse URL.'
      end

      if @url.scheme.nil? || @url.host.nil? || @url.port.nil?
        raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
              'Invalid SSRF request specified : Invalid URL.'
      end

      unless @url.scheme.eql?('http') || @url.scheme.eql?('https')
        raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
              'Invalid SSRF request specified : URL scheme must be http(s).'
      end

      if ssl
        @url.scheme = 'https'
      end

      # parse method
      unless @SUPPORTED_METHODS.include?(@method)
        raise SSRFProxy::HTTP::Error::InvalidSsrfRequestMethod.new,
              'Invalid SSRF request method specified. ' \
              "Supported methods: #{@SUPPORTED_METHODS.join(', ')}."
      end

      # parse headers
      if headers
        raise ArgumentError, "Option 'headers' must be a hash." unless headers.is_a?(Hash)

        headers.each do |k, v|
          if v.is_a?(Array)
            @headers[k.downcase] = v.flatten.first
          elsif v.is_a?(String)
            @headers[k.downcase] = v.to_s
          end
        end
      end

      if cookie
        @headers['cookie'] = cookie.to_s
      end

      if user_agent
        @headers['user-agent'] = user_agent
      end

      if user
        if user.to_s =~ /^(.*?):(.*)/
          @user = $1
          @pass = $2
        else
          @user = user.to_s
        end
      end

      # Ensure a URL placeholder was provided
      unless @url.request_uri.to_s.include?(@placeholder) ||
             @post_data.to_s.include?(@placeholder) ||
             @headers.to_s.include?(@placeholder)
        raise SSRFProxy::HTTP::Error::NoUrlPlaceholder.new,
              'You must specify a URL placeholder with ' \
              "'#{@placeholder}' in the SSRF request"
      end

      super(
        host: @url.host,
        port: @url.port,
        proxy: proxy,
        timeout: timeout.to_i || 10,
        tls: @url.scheme.eql?('https') ? true : false,
        insecure: insecure || false
      )
    end

    #
    # Parse a raw HTTP request as a string,
    # then send the request using #send_uri
    #
    # @param request [String] Raw HTTP request
    # @param use_ssl [Boolean] Connect using SSL/TLS
    #
    # @return [Hash] HTTP response hash (version, code, message, headers, body)
    #
    def send_request(request,
                     use_ssl: false,
                     placeholder_formatters: [],
                     request_formatters: [],
                     response_formatters: [])
      req = parse_http_request(request)

      req['uri'].scheme = 'https' if use_ssl

      send_uri(req['uri'],
               method: req['method'],
               headers: req['headers'],
               body: req['body'],
               placeholder_formatters: placeholder_formatters,
               request_formatters: request_formatters,
               response_formatters: response_formatters)
    end

    #
    # Request a URI via SSRF
    #
    # @param [String] uri URI to fetch
    # @param [String] method HTTP request method
    # @param [Hash] headers HTTP request headers
    # @param [String] body HTTP request body
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidClientRequest]
    #        An invalid client HTTP request was supplied.
    #
    # @return [Hash] HTTP response hash (version, code, message, headers, body, etc)
    #
    def send_uri(uri,
                 method: 'GET',
                 headers: {},
                 body: '',
                 placeholder_formatters: [],
                 request_formatters: [],
                 response_formatters: [])
      unless uri.to_s.start_with?('http://', 'https://')
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              'Invalid request URI'
      end
      unless placeholder_formatters.is_a?(Array)
        raise ArgumentError,
              "Option 'placeholder_formatters' expects an array."
      end
      unless request_formatters.is_a?(Array)
        raise ArgumentError,
              "Option 'request_formatters' expects an array."
      end
      unless response_formatters.is_a?(Array)
        raise ArgumentError,
              "Option 'response_formatters' expects an array."
      end

      destination_url = uri.to_s

      headers = {} unless headers.is_a?(Hash)

      client_headers = {}
      headers.each do |k, v|
        if v.is_a?(Array)
          client_headers[k.downcase] = v.flatten.first
        elsif v.is_a?(String)
          client_headers[k.downcase] = v.to_s
        else
          raise SSRFProxy::HTTP::Error::InvalidClientRequest,
                "Request header #{k.inspect} value is malformed: #{v}"
        end
      end

      if client_headers['upgrade'].to_s.start_with?('WebSocket')
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              'WebSocket tunneling is not supported'
      end

      http_request = Struct.new(:url, :method, :headers, :body)

      client_request = http_request.new(
        uri.to_s,
        method.to_s,
        client_headers,
        body.to_s
      )

      ssrf_request = http_request.new(
        @url.dup.to_s,
        @method.dup,
        @headers.dup,
        @post_data.dup
      )

      # format destination URL for SSRF server
      placeholder_formatters.each do |formatter|
        destination_url = formatter.format(destination_url, client_request)
      end

      # URL encode destination URL
      destination_url = CGI.escape(destination_url).gsub(/\+/, '%20').to_s

      # replace xxURLxx placeholder in request
      ssrf_request.url.gsub!(/#{@placeholder}/, destination_url)
      ssrf_request.body.gsub!(/#{@placeholder}/, destination_url)
      ssrf_request.headers.each do |k, v|
        ssrf_request.headers[k] = v.gsub(/#{@placeholder}/, destination_url)
      end

      # format HTTP request for the SSRF server
      request_formatters.each do |formatter|
        ssrf_request = formatter.format(client_request, ssrf_request)
      end

      # set content type
      if ssrf_request.headers['content-type'].nil? && !ssrf_request.body.eql?('')
        ssrf_request.headers['content-type'] = 'application/x-www-form-urlencoded'
      end

      # set content length
      ssrf_request.headers['content-length'] = ssrf_request.body.length.to_s

      logger.debug("Prepared request:\n" \
                   "#{ssrf_request.method} #{ssrf_request.url} HTTP/1.1\n" \
                   "#{ssrf_request.headers.map{|k, v| "#{k}: #{v}"}.join("\n")}\n" \
                   "#{ssrf_request.body}")

      # send request
      start_time = Time.now
      result = send_http_request(ssrf_request.url,
                                 ssrf_request.method,
                                 ssrf_request.headers,
                                 ssrf_request.body)
      end_time = Time.now
      result['duration'] = ((end_time - start_time) * 1_000).round(3)

      logger.info("Received #{result['body'].bytes.length} bytes in #{result['duration']} ms")

      logger.debug("Received response:\n" \
                   "HTTP/#{result['http_version']} #{result['code']} #{result['message']}\n" \
                   "#{result['headers']}\n" \
                   "#{result['body']}")

      # format response for client
      response_formatters.each do |formatter|
        result = formatter.format(client_request, result)
      end

      # set title
      result['title'] = result['body'][0..8192] =~ %r{<title>([^<]*)</title>}im ? $1.to_s : ''

      # set status line
      result['status_line'] = "HTTP/#{result['http_version']} #{result['code']} #{result['message']}"

      # advise client to close HTTP connection
      if result['headers'] =~ /^connection:.*$/i
        result['headers'].gsub!(/^connection:.*$/i, 'Connection: close')
      else
        result['headers'] << "Connection: close\n"
      end

      # set content length
      content_length = result['body'].length
      if result['headers'] =~ /^transfer\-encoding:.*$/i
        result['headers'].gsub!(/^transfer\-encoding:.*$/i,
                                "Content-Length: #{content_length}")
      elsif result['headers'] =~ /^content\-length:.*$/i
        result['headers'].gsub!(/^content\-length:.*$/i,
                                "Content-Length: #{content_length}")
      else
        result['headers'] << "Content-Length: #{content_length}\n"
      end

      # return HTTP response
      logger.debug("Prepared response:\n" \
                   "#{result['status_line']}\n" \
                   "#{result['headers']}\n" \
                   "#{result['body']}")
      result
    end

    private

    #
    # Parse a raw HTTP request as a string
    #
    # @param [String] request raw HTTP request
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidClientRequest]
    #        An invalid client HTTP request was supplied.
    #
    # @return [Hash] HTTP request hash (url, method, headers, body)
    #
    def parse_http_request(request)
      # parse method
      if request.to_s !~ /\A(GET|HEAD|DELETE|POST|PUT|OPTIONS) /
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              'HTTP request method is not supported.'
      end

      # parse client request
      begin
        req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
        req.parse(StringIO.new(request))
      rescue
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              'HTTP request is malformed.'
      end

      # validate host
      if request.to_s !~ %r{\A(GET|HEAD|DELETE|POST|PUT|OPTIONS) https?://}
        if request.to_s =~ /^Host: ([^\s]+)\r?\n/
          logger.info("Using host header: #{$1}")
        else
          raise SSRFProxy::HTTP::Error::InvalidClientRequest,
                'HTTP request is malformed : No host specified.'
        end
      end

      # return request hash
      uri = req.request_uri
      method = req.request_method
      headers = req.header
      begin
        body = req.body.to_s
      rescue WEBrick::HTTPStatus::BadRequest => e
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              "HTTP request is malformed : #{e.message}"
      rescue WEBrick::HTTPStatus::LengthRequired
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              "HTTP request is malformed : Request body without 'Content-Length' header."
      end

      { 'uri'     => uri,
        'method'  => method,
        'headers' => headers,
        'body'    => body }
    end

    #
    # Send HTTP request to the SSRF server
    #
    # @param [String] url URI to fetch
    # @param [String] method HTTP request method
    # @param [Hash] headers HTTP request headers
    # @param [String] body HTTP request body
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidClientRequest]
    #        Unsupported SSRF request method specified.
    #        Method must be GET/HEAD/DELETE/POST/PUT/OPTIONS.
    # @raise [SSRFProxy::HTTP::Error::InvalidResponse]
    #        Server returned an invalid HTTP response
    # @raise [SSRFProxy::HTTP::Error::ConnectionFailed]
    #        Connection failed
    # @raise [SSRFProxy::HTTP::Error::InvalidUpstreamProxy]
    #        Invalid upstream proxy specified.
    #
    # @return [Hash] Hash of the HTTP response (status, code, headers, body)
    #
    def send_http_request(url, method, headers, body)
      # use upstream proxy
      if @proxy.nil?
        http = Net::HTTP::Proxy(nil).new(
          @host,
          @port
        )
      elsif @proxy.scheme.eql?('http') || @proxy.scheme.eql?('https')
        http = Net::HTTP::Proxy(
          @proxy.host,
          @proxy.port
        ).new(
          @host,
          @port
        )
      elsif @proxy.scheme.eql?('socks')
        http = Net::HTTP.SOCKSProxy(
          @proxy.host,
          @proxy.port
        ).new(
          @host,
          @port
        )
      else
        raise SSRFProxy::HTTP::Error::InvalidUpstreamProxy.new,
              'Unsupported upstream proxy specified. Scheme must be http(s) or socks.'
      end

      # SSL/TLS
      if @tls
        http.use_ssl = true
        http.verify_mode = @insecure ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
      end

      # socket options
      http.open_timeout = @timeout
      http.read_timeout = @timeout

      # overwrite default user-agent
      headers['user-agent'] = '' unless !headers['user-agent'].nil?

      # parse request URI
      request_uri = URI.parse(url).request_uri

      # HTTP request method
      case method
      when 'GET'
        request = Net::HTTP::Get.new(request_uri, headers.to_hash)
      when 'HEAD'
        request = Net::HTTP::Head.new(request_uri, headers.to_hash)
      when 'DELETE'
        request = Net::HTTP::Delete.new(request_uri, headers.to_hash)
      when 'POST'
        request = Net::HTTP::Post.new(request_uri, headers.to_hash)
      when 'PUT'
        request = Net::HTTP::Put.new(request_uri, headers.to_hash)
      when 'OPTIONS'
        request = Net::HTTP::Options.new(request_uri, headers.to_hash)
      else
        logger.info("Request method #{method.inspect} not implemented")
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              "Request method #{method.inspect} not implemented"
      end

      # HTTP request basic authentication credentials
      request.basic_auth(@user, @pass) unless @user.eql?('') && @pass.eql?('')

      # send HTTP request
      logger.info("Sending request: #{url}")
      unless body.eql?('')
        request.body = body
        logger.info("Using request body: #{request.body.inspect}")
      end

      begin
        response = http.request(request)
      rescue Net::HTTPBadResponse, EOFError
        logger.info('Server returned an invalid HTTP response')
        raise SSRFProxy::HTTP::Error::InvalidResponse,
              'Server returned an invalid HTTP response'
      rescue Errno::ECONNREFUSED, Errno::ECONNRESET
        logger.info('Connection failed')
        raise SSRFProxy::HTTP::Error::ConnectionFailed,
              'Connection failed'
      rescue Timeout::Error, Errno::ETIMEDOUT
        logger.info("Connection to #{@host}:#{@port} timed out [#{@timeout}]")
        raise SSRFProxy::HTTP::Error::ConnectionTimeout,
              "Connection to #{@host}:#{@port} timed out [#{@timeout}]"
      rescue => e
        logger.error("Unhandled exception: #{e}")
        raise e
      end

      if response.code.eql?('401')
        if @user.eql?('') && @pass.eql?('')
          logger.warn('Authentication required'.yellow)
        else
          logger.warn('Authentication failed'.yellow)
        end
      end

      # decompress response body
      if response['content-encoding'].to_s.downcase.eql?('gzip') && response.body
        begin
          sio = StringIO.new(response.body)
          gz = Zlib::GzipReader.new(sio)
          response.body = gz.read
        rescue
          logger.warn('Could not decompress response body'.yellow)
        end
      end

      # parse headers
      headers = ''
      response.each_header {|k, v| headers << "#{k}: #{v}\n" }

      result = {
        'url'          => url,
        'http_version' => response.http_version,
        'code'         => response.code,
        'message'      => response.message,
        'headers'      => headers,
        'body'         => response.body.to_s || ''
      }

      # encode body content
      result['body'].force_encoding('BINARY')
      unless result['body'].valid_encoding?
        begin
          result['body'] = result['body'].encode(
            'UTF-8',
            'binary',
            :invalid => :replace,
            :undef   => :replace,
            :replace => ''
          )
        rescue
          logger.warn('Could not encode response body'.yellow)
        end
      end

      result
    end

    # private methods
    private :parse_http_request,
            :send_http_request
  end
end
