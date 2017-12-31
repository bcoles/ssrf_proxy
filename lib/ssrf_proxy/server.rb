#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  #
  # SSRFProxy::Server takes a SSRFProxy::HTTP object, interface
  # and port, and starts a HTTP proxy server on the specified
  # interface and port. All client HTTP requests are sent via
  # the specified SSRFProxy::HTTP object.
  #
  class Server
    include Logging
    include Celluloid::IO
    finalizer :shutdown

    #
    # Start the local server and listen for connections
    #
    # @param [SSRFProxy::HTTP] ssrf A configured SSRFProxy::HTTP object
    # @param [String] interface Listen interface (Default: 127.0.0.1)
    # @param [Integer] port Listen port (Default: 8081)
    #
    # @raise [SSRFProxy::Server::Error::InvalidSsrf]
    #        Invalid SSRFProxy::SSRF object provided.
    #
    # @raise [SSRFProxy::Server::Error::ProxyRecursion]
    #        Proxy recursion error. SSRF Proxy cannot use itself as an
    #        upstream proxy.
    #
    # @example Start SSRF Proxy server with the default options
    #   ssrf_proxy = SSRFProxy::Server.new(
    #     SSRFProxy::HTTP.new('http://example.local/?url=xxURLxx'),
    #     '127.0.0.1',
    #     8081)
    #   ssrf_proxy.serve
    #
    def initialize(ssrf,
                  interface: '127.0.0.1',
                  port: 8081,
                  placeholder_formatters: [],
                  request_formatters: [],
                  response_formatters: [])
      @banner = 'SSRF Proxy'
      @server = nil

      unless ssrf.class == SSRFProxy::HTTP
        raise SSRFProxy::Server::Error::InvalidSsrf.new,
              'Invalid SSRF provided'
      end

      @ssrf = ssrf.freeze
      @interface = interface.freeze
      @port = port.to_i.freeze
      @placeholder_formatters = placeholder_formatters.freeze
      @request_formatters = request_formatters.freeze
      @response_formatters = response_formatters.freeze

      unless @ssrf.proxy.nil?
        if @ssrf.proxy.host == @interface && @ssrf.proxy.port == @port
          raise SSRFProxy::Server::Error::ProxyRecursion.new,
                "Proxy recursion error: #{@ssrf.proxy}"
        end
      end

      check_connection
      start_server
    end

    #
    # Check if the remote server is responsive
    #
    # @raise [SSRFProxy::Server::Error::RemoteProxyUnresponsive]
    #        Could not connect to remote proxy.
    # @raise [SSRFProxy::Server::Error::RemoteHostUnresponsive]
    #        Could not connect to remote host.
    #
    def check_connection
      # check if the remote proxy server is responsive
      unless @ssrf.proxy.nil?
        print_status("Connecting to #{@ssrf.proxy.host}:#{@ssrf.proxy.port}")

        unless port_open?(@ssrf.proxy.host, @ssrf.proxy.port)
          raise SSRFProxy::Server::Error::RemoteProxyUnresponsive.new,
                "Could not connect to remote proxy #{@ssrf.proxy.host}:#{@ssrf.proxy.port}"
        end

        print_good("Connected to remote proxy #{@ssrf.proxy.host}:#{@ssrf.proxy.port} successfully")
      end

      # if no upstream proxy is set, check if the remote server is responsive
      if @ssrf.proxy.nil?
        print_status("Connecting to #{@ssrf.host}:#{@ssrf.port}")

        unless port_open?(@ssrf.host, @ssrf.port)
          raise SSRFProxy::Server::Error::RemoteHostUnresponsive.new,
                "Could not connect to remote host #{@ssrf.host}:#{@ssrf.port}"
        end

        print_good("Connected to remote host #{@ssrf.host}:#{@ssrf.port} successfully")
      end
    end

    #
    # Start the proxy server
    #
    # @raise [SSRFProxy::Server::Error::AddressInUse]
    #        Could not bind to the port on the specified interface as
    #        address already in use.
    #
    def start_server
      logger.info "Starting HTTP proxy on #{@interface}:#{@port}"
      print_status "Listening on #{@interface}:#{@port}"
      @server = TCPServer.new(@interface, @port)
    rescue Errno::EADDRINUSE
      raise SSRFProxy::Server::Error::AddressInUse.new,
            "Could not bind to #{@interface}:#{@port} - address already in use"
    end

    #
    # Checks if a port is open or not on a remote host
    # From: https://gist.github.com/ashrithr/5305786
    #
    # @param [String] ip connect to IP
    # @param [Integer] port connect to port
    # @param [Integer] seconds connection timeout
    #
    def port_open?(ip, port, seconds = 10)
      Timeout.timeout(seconds) do
        TCPSocket.new(ip, port).close
        true
      end
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError, Timeout::Error
      false
    end

    #
    # Print status message
    #
    # @param [String] msg message to print
    #
    def print_status(msg = '')
      puts '[*] '.blue + msg
    end

    #
    # Print progress messages
    #
    # @param [String] msg message to print
    #
    def print_good(msg = '')
      puts '[+] '.green + msg
    end

    #
    # Print error message
    #
    # @param [String] msg message to print
    #
    def print_error(msg = '')
      puts '[-] '.red + msg
    end

    #
    # Run proxy server asynchronously
    #
    def serve
      loop { async.handle_connection(@server.accept) }
    end

    #
    # Handle shutdown of server socket
    #
    def shutdown
      logger.info 'Shutting down'
      @server.close if @server
      logger.debug 'Shutdown complete'
    end

    #
    # Handle client socket connection
    #
    # @param [Celluloid::IO::TCPSocket] socket client socket
    #
    def handle_connection(socket)
      start_time = Time.now
      _, port, host = socket.peeraddr
      logger.debug("Client #{host}:#{port} connected")
      request = socket.read
      logger.debug("Received client request (#{request.length} bytes):\n" \
                   "#{request}")

      response = nil
      if request.to_s =~ /\ACONNECT ([_a-zA-Z0-9\.\-]+:[\d]+) .*$/
        host = $1.to_s
        logger.info("Negotiating connection to #{host}")
        response = send_request("GET http://#{host}/ HTTP/1.0\n\n")

        if response['code'].to_i == 502 || response['code'].to_i == 504
          logger.info("Connection to #{host} failed")
          socket.write("#{response['status_line']}\n" \
                       "#{response['headers']}\n" \
                       "#{response['body']}")
          raise Errno::ECONNRESET
        end

        logger.info("Connected to #{host} successfully")
        socket.write("HTTP/1.0 200 Connection established\r\n\r\n")
        request = socket.read
        logger.debug("Received client request (#{request.length} bytes):\n" \
                     "#{request}")

        # CHANGE_CIPHER_SPEC  20   0x14
        # ALERT               21   0x15
        # HANDSHAKE           22   0x16
        # APPLICATION_DATA    23   0x17
        if request.to_s.start_with?("\x14", "\x15", "\x16", "\x17")
          logger.warn("Received SSL/TLS client request. SSL/TLS tunneling is not supported. Aborted.")
          raise Errno::ECONNRESET
        end
      end

      response = send_request(request.to_s)
      socket.write("#{response['status_line']}\n" \
                   "#{response['headers']}\n" \
                   "#{response['body']}")
      raise Errno::ECONNRESET
    rescue EOFError, Errno::ECONNRESET, Errno::EPIPE
      socket.close
      logger.debug("Client #{host}:#{port} disconnected")
      end_time = Time.now
      duration = ((end_time - start_time) * 1000).round(3)
      if response.nil?
        logger.info("Served 0 bytes in #{duration} ms")
      else
        logger.info("Served #{response['body'].length} bytes in #{duration} ms")
      end
    end

    #
    # Send client HTTP request
    #
    # @param [String] request client HTTP request
    #
    # @return [Hash] HTTP response
    #
    def send_request(request)
      response_error = { 'uri' => '',
                         'duration' => '0',
                         'http_version' => '1.0',
                         'headers' => "Server: #{@banner}\n",
                         'body' => '' }

      # parse client request
      begin
        if request.to_s !~ %r{\A(CONNECT|GET|HEAD|DELETE|POST|PUT|OPTIONS) https?://}
          if request.to_s !~ /^Host: ([^\s]+)\r?\n/
            raise SSRFProxy::HTTP::Error::InvalidClientRequest,
                  'No host specified'
          end
        end
        req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
        req.parse(StringIO.new(request))
      rescue => e
        logger.warn("Received malformed client HTTP request: #{e.message}")
        response_error['code'] = '502'
        response_error['message'] = 'Bad Gateway'
        response_error['status_line'] = "HTTP/#{response_error['http_version']}"
        response_error['status_line'] << " #{response_error['code']}"
        response_error['status_line'] << " #{response_error['message']}"
        return response_error
      end
      uri = req.request_uri

      # send request
      response = nil
      logger.info("Requesting URL: #{uri}")
      status_msg = "Request  -> #{req.request_method}"
      status_msg << " -> PROXY[#{@ssrf.proxy.host}:#{@ssrf.proxy.port}]" unless @ssrf.proxy.nil?
      status_msg << " -> SSRF[#{@ssrf.host}:#{@ssrf.port}] -> URI[#{uri}]"
      print_status(status_msg)

      begin
        response = @ssrf.send_request(
          request.to_s,
          placeholder_formatters: @placeholder_formatters,
          request_formatters: @request_formatters,
          response_formatters: @response_formatters
        )
      rescue SSRFProxy::HTTP::Error::InvalidClientRequest => e
        logger.warn(e.message)
        response_error['code'] = '502'
        response_error['message'] = 'Bad Gateway'
        response_error['status_line'] = "HTTP/#{response_error['http_version']}"
        response_error['status_line'] << " #{response_error['code']}"
        response_error['status_line'] << " #{response_error['message']}"
        return response_error
      rescue SSRFProxy::HTTP::Error::InvalidResponse => e
        logger.info(e.message)
        error_msg = 'Response <- 503'
        error_msg << " <- PROXY[#{@ssrf.proxy.host}:#{@ssrf.proxy.port}]" unless @ssrf.proxy.nil?
        error_msg << " <- SSRF[#{@ssrf.host}:#{@ssrf.port}] <- URI[#{uri}]"
        error_msg << " -- Error: #{e.message}"
        print_error(error_msg)
        response_error['code'] = '503'
        response_error['message'] = 'Service Unavailable'
        response_error['status_line'] = "HTTP/#{response_error['http_version']}"
        response_error['status_line'] << " #{response_error['code']}"
        response_error['status_line'] << " #{response_error['message']}"
        return response_error
      rescue SSRFProxy::HTTP::Error::ConnectionFailed => e
        logger.info(e.message)
        error_msg = 'Response <- 503'
        error_msg << " <- PROXY[#{@ssrf.proxy.host}:#{@ssrf.proxy.port}]" unless @ssrf.proxy.nil?
        error_msg << " <- SSRF[#{@ssrf.host}:#{@ssrf.port}] <- URI[#{uri}]"
        error_msg << " -- Error: #{e.message}"
        print_error(error_msg)
        response_error['code'] = '503'
        response_error['message'] = 'Service Unavailable'
        response_error['status_line'] = "HTTP/#{response_error['http_version']}"
        response_error['status_line'] << " #{response_error['code']}"
        response_error['status_line'] << " #{response_error['message']}"
        return response_error
      rescue SSRFProxy::HTTP::Error::ConnectionTimeout => e
        logger.info(e.message)
        error_msg = 'Response <- 504'
        error_msg << " <- PROXY[#{@ssrf.proxy.host}:#{@ssrf.proxy.port}]" unless @ssrf.proxy.nil?
        error_msg << " <- SSRF[#{@ssrf.host}:#{@ssrf.port}] <- URI[#{uri}]"
        error_msg << " -- Error: #{e.message}"
        print_error(error_msg)
        response_error['code'] = '504'
        response_error['message'] = 'Timeout'
        response_error['status_line'] = "HTTP/#{response_error['http_version']}"
        response_error['status_line'] << " #{response_error['code']}"
        response_error['status_line'] << " #{response_error['message']}"
        return response_error
      rescue => e
        logger.error(e.message)
        response_error['code'] = '502'
        response_error['message'] = 'Bad Gateway'
        response_error['status_line'] = "HTTP/#{response_error['http_version']}"
        response_error['status_line'] << " #{response_error['code']} "
        response_error['status_line'] << " #{response_error['message']}"
        return response_error
      end

      # return response
      status_msg = "Response <- #{response['code']}"
      status_msg << " <- PROXY[#{@ssrf.proxy.host}:#{@ssrf.proxy.port}]" unless @ssrf.proxy.nil?
      status_msg << " <- SSRF[#{@ssrf.host}:#{@ssrf.port}] <- URI[#{uri}]"
      status_msg << " -- Title[#{response['title']}]" unless response['title'].eql?('')
      status_msg << " -- [#{response['body'].size} bytes]"
      print_good(status_msg)
      response
    end

    # private methods
    private :print_status,
            :print_good,
            :print_error,
            :start_server,
            :check_connection,
            :shutdown,
            :handle_connection,
            :send_request,
            :port_open?
  end
end
