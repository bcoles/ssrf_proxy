#!/usr/bin/env ruby
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

require "ssrf_proxy"

module SSRFProxy
#
# @note SSRFProxy::Server
#
class Server

  # @note output status messages
  def print_status(msg='')
    puts '[*] '.blue + msg
  end
  # @note output progress messages
  def print_good(msg='')
    puts '[+] '.green + msg
  end

  require 'socket'
  require 'celluloid/current'
  require 'celluloid/io'

  include Celluloid::IO
  finalizer :shutdown

  attr_accessor :logger

  # @note logger
  def logger
    @logger || ::Logger.new(STDOUT).tap do |log|
      log.progname = 'ssrf-proxy-server'
      log.level = ::Logger::WARN
      log.datetime_format = '%Y-%m-%d %H:%M:%S '
    end
  end

  #
  # @note SSRFProxy::Server errors
  #
  module Error
    # custom errors
    class Error < StandardError; end
    exceptions = %w( InvalidSsrf ProxyRecursion )
    exceptions.each { |e| const_set(e, Class.new(Error)) }
  end

  #
  # @note Start the local server and listen for connections
  #
  # @options
  # - interface - String - Listen interface (Default: 127.0.0.1)
  # - port - Integer - Listen port (Default: 8081)
  # - ssrf - SSRFProxy::HTTP - SSRF
  #
  def initialize(interface='127.0.0.1', port=8081, ssrf)
    @logger = ::Logger.new(STDOUT).tap do |log|
      log.progname = 'ssrf-proxy-server'
      log.level = ::Logger::WARN
      log.datetime_format = '%Y-%m-%d %H:%M:%S '
    end
    # set ssrf
    unless ssrf.class == SSRFProxy::HTTP
      raise SSRFProxy::Server::Error::InvalidSsrf.new,
        "Invalid SSRF provided"
    end
    @ssrf = ssrf
    # start server
    logger.info "Starting HTTP proxy on #{interface}:#{port}"
    if ssrf.proxy && ssrf.proxy.host == interface && ssrf.proxy.port == port
      raise SSRFProxy::Server::Error::ProxyRecursion.new,
        "Proxy recursion error: #{ssrf.proxy}"
    end
    print_status "Listening on #{interface}:#{port}"
    @server = TCPServer.new(interface, port.to_i)
  end

  #
  # @note Run proxy server
  #
  def serve
    loop { async.handle_connection(@server.accept) }
  end

  private

  #
  # @note Handle shutdown of client socket
  #
  def shutdown
    logger.info 'Shutting down'
    @server.close if @server
    logger.debug 'Shutdown complete'
  end

  #
  # @note Handle client request
  #
  # @options
  # - socket - String - client socket
  #
  def handle_connection(socket)
    _, port, host = socket.peeraddr
    max_len = 4096
    logger.debug "Client #{host}:#{port} connected"
    request = socket.readpartial(max_len)
    logger.debug("Received client request (#{request.length} bytes):\n#{request}")
    if request.length >= max_len
      logger.warn("Client request too long (truncated at #{request.length} bytes)")
    end
    if request.to_s !~ /\A[A-Z]{1,20} /
      logger.warn("Malformed client HTTP request")
      response = "HTTP/1.0 501 Error\r\n\r\n"
    elsif request.to_s =~ /\ACONNECT ([a-zA-Z0-9\.\-]+:[\d]+) .*$/
      host = "#{$1}"
      logger.info("Negotiating connection to #{host}")
      response = @ssrf.send_request("GET http://#{host}/ HTTP/1.0\n\n")
      if response =~ /^Server: SSRF Proxy$/i && response =~ /^Content-Length: 0$/i
        logger.warn("Connection to #{host} failed")
        response = "HTTP/1.0 502 Bad Gateway\r\n\r\n"
      else
        logger.info("Connected to #{host} successfully")
        socket.write("HTTP/1.0 200 Connection established\r\n\r\n")
        request = socket.readpartial(max_len)
        logger.debug("Received client request (#{request.length} bytes):\n#{request}")
        if request.length >= max_len
          logger.warn("Client request too long (truncated at #{request.length} bytes)")
        end
        response = @ssrf.send_request(request)
      end
    else
      response = @ssrf.send_request(request)
    end
    socket.write(response)
    socket.close
  rescue EOFError, Errno::ECONNRESET
    logger.debug "Client #{host}:#{port} disconnected"
    socket.close
  end

  private :print_status,:print_good,:shutdown,:handle_connection

end

end

