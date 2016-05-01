# coding: utf-8
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
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
    include Celluloid::IO
    finalizer :shutdown

    #
    # SSRFProxy::Server errors
    #
    module Error
      # SSRFProxy::Server custom errors
      class Error < StandardError; end
      exceptions = %w(
        InvalidSsrf
        ProxyRecursion
        AddressInUse
        RemoteProxyUnresponsive
        RemoteHostUnresponsive )
      exceptions.each { |e| const_set(e, Class.new(Error)) }
    end

    #
    # Start the local server and listen for connections
    #
    # @param [SSRFProxy::HTTP] ssrf A configured SSRFProxy::HTTP object
    # @param [String] interface Listen interface (Default: 127.0.0.1)
    # @param [Integer] port Listen port (Default: 8081)
    #
    # @example Start SSRF Proxy server with the default options
    #   ssrf = SSRFProxy::HTTP.new('http://example.local/index.php?url=xxURLxx')
    #   ssrf_proxy = SSRFProxy::Server.new(ssrf, '127.0.0.1', 8081)
    #   ssrf_proxy.serve
    #
    def initialize(ssrf, interface = '127.0.0.1', port = 8081)
      @max_request_len = 8192
      @logger = ::Logger.new(STDOUT).tap do |log|
        log.progname = 'ssrf-proxy-server'
        log.level = ::Logger::WARN
        log.datetime_format = '%Y-%m-%d %H:%M:%S '
      end
      # set ssrf
      unless ssrf.class == SSRFProxy::HTTP
        raise SSRFProxy::Server::Error::InvalidSsrf.new,
              'Invalid SSRF provided'
      end
      @ssrf = ssrf

      # check if the remote proxy server is running
      unless @ssrf.proxy.nil?
        if port_open?(@ssrf.proxy.host, @ssrf.proxy.port)
          print_good("Connected to remote proxy #{@ssrf.proxy.host}:#{@ssrf.proxy.port} successfully")
        else
          raise SSRFProxy::Server::Error::RemoteProxyUnresponsive.new,
                "Could not connect to remote proxy #{@ssrf.proxy.host}:#{@ssrf.proxy.port}"
        end
      # check if the remote server is running
      else
        if port_open?(@ssrf.host, @ssrf.port)
          print_good("Connected to remote host #{@ssrf.host}:#{@ssrf.port} successfully")
        else
          raise SSRFProxy::Server::Error::RemoteHostUnresponsive.new,
                "Could not connect to remote host #{@ssrf.host}:#{@ssrf.port}"
        end
      end

      # start server
      logger.info "Starting HTTP proxy on #{interface}:#{port}"
      if ssrf.proxy && ssrf.proxy.host == interface && ssrf.proxy.port == port
        raise SSRFProxy::Server::Error::ProxyRecursion.new,
              "Proxy recursion error: #{ssrf.proxy}"
      end
      begin
        print_status "Listening on #{interface}:#{port}"
        @server = TCPServer.new(interface, port.to_i)
      rescue Errno::EADDRINUSE
        raise SSRFProxy::Server::Error::AddressInUse.new,
              "Could not bind to #{interface}:#{port} - address already in use"
      end
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
      Timeout::timeout(seconds) do
        begin
          TCPSocket.new(ip, port).close
          true
        rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError
          false
        end
      end
      rescue Timeout::Error
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
    # Logger accessor
    #
    # @return [Logger] class logger object
    #
    def logger
      @logger
    end

    #
    # Run proxy server asynchronously
    #
    def serve
      loop { async.handle_connection(@server.accept) }
    end

    #
    # Handle shutdown of client socket
    #
    def shutdown
      logger.info 'Shutting down'
      @server.close if @server
      logger.debug 'Shutdown complete'
    end

    #
    # Handle client request
    #
    # @param [Celluloid::IO::TCPSocket] socket client socket
    #
    def handle_connection(socket)
      start_time = Time.now
      _, port, host = socket.peeraddr
      logger.debug("Client #{host}:#{port} connected")
      request = socket.readpartial(@max_request_len)
      logger.debug("Received client request (#{request.length} bytes):\n#{request}")
      if request.to_s =~ /\ACONNECT ([_a-zA-Z0-9\.\-]+:[\d]+) .*$/
        host = $1.to_s
        logger.info("Negotiating connection to #{host}")
        response = @ssrf.send_request("GET http://#{host}/ HTTP/1.0\n\n")
        if response =~ /^Server: SSRF Proxy$/i && response =~ /^Content-Length: 0$/i
          logger.warn("Connection to #{host} failed")
          socket.write("HTTP/1.0 502 Bad Gateway\r\n\r\n")
          socket.close
        else
          logger.info("Connected to #{host} successfully")
          socket.write("HTTP/1.0 200 Connection established\r\n\r\n")
          handle_connection(socket)
        end
      else
        response = @ssrf.send_request(request)
        socket.write(response)
        socket.close
        end_time = Time.now
        duration = end_time - start_time
        logger.info("Served #{response.length} bytes in #{(duration * 1000).round(3)} ms")
      end
    rescue EOFError, Errno::ECONNRESET
      socket.close
      logger.debug("Client #{host}:#{port} disconnected")
    end

    # private methods
    private :print_status,
            :print_good,
            :shutdown,
            :handle_connection,
            :port_open?
  end
end
