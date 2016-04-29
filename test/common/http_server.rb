# coding: utf-8
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

require 'webrick'
require 'webrick/https'
require 'net/http'
require 'logger'
require 'open-uri'
require 'typhoeus'

#
# @note: example HTTP Server vulnerable to SSRF
#
class HTTPServer

  # @note logger
  def logger
    @logger
  end

  # @note start server
  def initialize(opts = {})
    @logger = ::Logger.new(STDOUT).tap do |log|
      log.progname = 'http-server'
      log.level = ::Logger::WARN
      log.datetime_format = '%Y-%m-%d %H:%M:%S '
    end

    @timeout = 15

    cert_name = [
      %w(CN localhost)
    ]

    # options
    interface = '127.0.0.1'
    port = 8088
    ssl = false
    opts.each do |option, value|
      next if value.eql?('')
      case option
      when 'interface'
        interface = value.to_s
      when 'port'
        port = value.to_i
      when 'ssl'
        ssl = true if value
      when 'verbose'
        @logger.level = ::Logger::INFO if value unless @logger.level == ::Logger::DEBUG
      when 'debug'
        @logger.level = ::Logger::DEBUG if value
      end
    end

    logger.info("Starting server #{interface}:#{port}")
    webrick_opts = {
      :Interface => interface,
      :Port => port,
      :ServerSoftware => 'Server',
      :MaxClients => 10000,
      :Logger => @logger,
      :SSLEnable => ssl,
      :SSLCertName => cert_name,
      :SSLCertComment => ''}
    webrick_opts[:AccessLog] = [] if @logger.level > 1
    @server = WEBrick::HTTPServer.new(webrick_opts)

    #
    # @note web root
    #
    @server.mount_proc '/' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      res.body = '<html><head><title>public</title></head><body><p></p></body></html>'
    end

    #
    # @note user input
    #
    @server.mount_proc '/submit' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      res.body = "<html><head><title>submit</title></head><body><p>#{req.query['data']}</p></body></html>"
    end

    #
    # @note user cookies
    #
    @server.mount_proc '/cookies' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      res.body = "<html><head><title>cookies</title></head><body><p>#{req.cookies.flatten}</p></body></html>"
    end

    #
    # @note print server info
    #
    @server.mount_proc '/auth' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      WEBrick::HTTPAuth.basic_auth(req, res, '') do |user, password|
        if user == 'admin' && password == 'test'
          res.body = "<html><head><title>authentication successful</title></head><body><p>#{@server.inspect}</p></body></html>"
        else
          res.status = 401
          res.body = '<html><head><title>401 Unauthorized</title></head><body><p>authentication required</p></body></html>'
        end
      end
    end

    #
    # @note fetch a URL with Net::HTTP and print the HTTP response body
    #
    @server.mount_proc '/net_http' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      if req.query['url'].nil?
        res.body = 'No URL specified'
      else
        uri = req.query['url'].split(/\r?\n/).first
        if uri !~ %r{\Ahttps?://.}
          res.body = 'Invalid URL specified'
        else
          response = get_url_http(uri.to_s)
          res.body = "Response:<br/>\n<textarea>#{response}</textarea>"
        end
      end
    end

    #
    # @note fetch a URL with OpenURI and print the HTTP response body
    #
    @server.mount_proc '/openuri' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      if req.query['url'].nil?
        res.body = 'No URL specified'
      else
        uri = req.query['url'].split(/\r?\n/).first
        if uri !~ %r{\Ahttps?://.}
          res.body = 'Invalid URL specified'
        else
          response = get_url_openuri(uri.to_s)
          res.body = "Response:<br/>\n<textarea>#{response}</textarea>"
        end
      end
    end

    #
    # @note fetch a URL with cURL and print the HTTP response body
    #
    @server.mount_proc '/curl' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      if req.query['url'].nil?
        res.body = 'No URL specified'
      else
        uri = req.query['url'].split(/\r?\n/).first
        if uri !~ %r{\Ahttps?://.}
          res.body = 'Invalid URL specified'
        else
          response = get_url_curl(uri.to_s)
          res.body = "Response:<br/>\n<textarea>#{response}</textarea>"
        end
      end
    end

    #
    # @note fetch a URL with Typhoeus and print the HTTP response body
    #
    @server.mount_proc '/typhoeus' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      if req.query['url'].nil?
        res.body = 'No URL specified'
      else
        uri = req.query['url'].split(/\r?\n/).first
        if uri !~ %r{\Ahttps?://.}
          res.body = 'Invalid URL specified'
        else
          response = get_url_typhoeus(uri.to_s)
          res.body = "Response:<br/>\n<textarea>#{response}</textarea>"
        end
      end
    end

    #
    # @note fetch a URL and do nothing
    #
    @server.mount_proc '/net_http_blind' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      if req.query['url'].nil?
        res.body = 'No URL specified'
      else
        uri = req.query['url'].split(/\r?\n/).first
        if uri !~ %r{\Ahttps?://.}
          res.body = 'Invalid URL specified'
        else
          get_url_http(uri.to_s)
          res.body = ''
        end
      end
    end

    %w(INT QUIT TERM).each { |s| Signal.trap(s) { @server.shutdown } }
    @server.start
  end

  #
  # @note shutdown server
  #
  def shutdown
    @server.shutdown
  end

  private

  #
  # @note fetch a URL with Ruby Net::HTTP
  #
  def get_url_http(uri)
    logger.info "Fetching URL: #{uri}"
    uri = URI.parse(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    if uri.scheme == 'https'
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE # VERIFY_PEER
    end
    # set socket options
    http.open_timeout = @timeout
    http.read_timeout = @timeout
    # send http request
    response = ''
    begin
      res = http.request Net::HTTP::Get.new(uri.request_uri)
      if res.nil?
        response = 'Could not fetch URL'
      else
        headers = []
        res.each_header do |header_name, header_value|
          headers << "#{header_name}: #{header_value}"
        end
        logger.info "Received response: HTTP/#{res.http_version} #{res.code} #{res.message}\n#{headers.join("\n")}\n\n#{res.body}"
        response = res.body
      end
    rescue Timeout::Error, Errno::ETIMEDOUT
      response = 'Timeout fetching URL'
    rescue => e
      response = "Unhandled exception: #{e.message}: #{e}"
    end
    response
  end

  #
  # @note fetch a URL with Ruby OpenURI
  #
  def get_url_openuri(uri)
    logger.info "Fetching URL: #{uri}"
    begin
      uri = URI.parse(uri)
      response = ''
      open(uri) do |f|
        f.each_line do |line|
          response << line
        end
      end
    rescue => e
      response = "Unhandled exception: #{e.message}: #{e}"
    end
    response
  end

  #
  # @note fetch a URL with cURL
  #
  def get_url_curl(uri)
    logger.info "Fetching URL: #{uri}"
    begin
      response = IO.popen(['/usr/bin/curl', '-sk', uri.to_s], 'r+').read.to_s
    rescue => e
      response = "Unhandled exception: #{e.message}: #{e}"
    end
    response
  end

  #
  # @note fetch a URL with Typhoeus
  #
  def get_url_typhoeus(uri)
    logger.info "Fetching URL: #{uri}"
    begin
      response = Typhoeus.get(uri).body
    rescue => e
      response = "Unhandled exception: #{e.message}: #{e}"
    end
    response
  end
end
