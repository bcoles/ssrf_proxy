#!/usr/bin/env ruby
#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
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
# @note: start HTTP server if run from command line
#
def run!
  #
  # @note start http server
  #
  interface = '127.0.0.1'
  port = '8088'
  puts 'Starting HTTP server...'
  Thread.new do
    begin
      HTTPServer.new(
        'interface' => interface,
        'port' => port,
        'ssl' => false,
        'verbose' => false,
        'debug' => false
      )
    rescue => e
      puts "Error: Could not start test HTTP server: #{e}"
    end
  end
  puts "HTTP server listening on #{interface}:#{port} (Press ENTER to exit)..."
  gets
end

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
      %w[CN localhost]
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
        if value
          @logger.level = ::Logger::INFO unless @logger.level == ::Logger::DEBUG
        end
      when 'debug'
        @logger.level = ::Logger::DEBUG if value
      end
    end

    logger.info("Starting server #{interface}:#{port}")
    webrick_opts = {
      :BindAddress => interface,
      :Port => port,
      :ServerSoftware => 'Server',
      :MaxClients => 10_000,
      :Logger => @logger,
      :SSLEnable => ssl,
      :SSLCertName => cert_name,
      :SSLCertComment => ''
    }
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
      data = ''
      req.query.each do |k, v|
        data << "<p>#{k}: #{v}</p>\n"
      end
      res.body = "<html><head><title>submit</title></head><body><p>Received query:</p>\n#{data}\n</body></html>"
    end

    #
    # @note print user cookies
    #
    @server.mount_proc '/cookies' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      res.body = "<html><head><title>cookies</title></head><body><p>#{req.cookies.flatten}</p></body></html>"
    end

    #
    # @note print request headers
    #
    @server.mount_proc '/headers' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      data = ''
      req.raw_header.each do |header|
        data << "<p>#{header.strip}</p>\n"
      end
      res.body = "<html><head><title>headers</title></head><body>\n#{data}\n</body></html>"
    end

    #
    # @note print server info
    #       access restricted by basic authentication:
    #       - username: admin user
    #       - password: test password!@#$%^&*()_+-={}|\:";'<>?,./
    #
    @server.mount_proc '/auth' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      WEBrick::HTTPAuth.basic_auth(req, res, '') do |user, password|
        if user == 'admin user' && password == 'test password!@#$%^&*()_+-={}|\:";\'<>?,./'
          res.body = "<html><head><title>authentication successful</title></head><body><p>#{@server.inspect}</p></body></html>"
        else
          res.status = 401
          res.body = '<html><head><title>401 Unauthorized</title></head><body><p>authentication required</p></body></html>'
        end
      end
    end

    #
    # @note redirect to admin panel
    #
    @server.mount_proc '/redirect' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      res.status = 302
      res['Location'] = '/admin'
      res.body = '<html><head><title>302 Found</title></head><body>The document has moved <a href="/admin">here</a>.</body></html>'
      raise WEBrick::HTTPStatus::TemporaryRedirect
    end

    #
    # @note print server info
    #       access restricted by IP whitelist (127.0.0.1)
    #
    @server.mount_proc '/admin' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      if req.remote_ip.eql?('127.0.0.1')
        res.body = "<html><head><title>administration</title></head><body><p>#{@server.inspect}</p></body></html>"
      else
        res.status = 403
        res.body = '<html><head><title>403 Forbidden</title></head><body><p>access denied</p></body></html>'
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
    # @note proxy request URL, headers and body with cURL and print the HTTP response body
    #
    @server.mount_proc '/curl_proxy' do |req, res|
      logger.info "Received request: #{req.request_line}#{req.raw_header.join}#{req.body}"
      if req.query['url'].nil?
        res.body = 'No URL specified'
      else
        uri = req.query['url'].split(/\r?\n/).first
        if uri !~ %r{\Ahttps?://.}
          res.body = 'Invalid URL specified'
        else
          response = curl_proxy(uri.to_s, req.request_method, req.raw_header, req.query)
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

    %w[INT QUIT TERM].each { |s| Signal.trap(s) { @server.shutdown } }
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
    uri = URI.parse(uri)
    response = ''
    open(uri) do |f|
      f.each_line do |line|
        response << line
      end
    end
    response
  rescue => e
    return "Unhandled exception: #{e.message}: #{e}"
  end

  #
  # @note fetch a URL with cURL
  #
  def get_url_curl(uri)
    logger.info "Fetching URL: #{uri}"
    IO.popen(['/usr/bin/curl', '-sk', uri.to_s], 'r+').read.to_s
  rescue => e
    return "Unhandled exception: #{e.message}: #{e}"
  end

  #
  # @note post data to a URL with cURL
  #
  def curl_proxy(uri, method = 'GET', headers = {}, data = {})
    logger.info "Fetching URL: #{uri}"
    post_data = []
    data.each do |k, v|
      post_data << "#{k}=#{v}" unless k.eql?('url')
    end
    body = post_data.join('&').to_s
    args = ['/usr/bin/curl', '-sk', uri.to_s, '-X', method, '-d', body]
    headers.each do |header|
      args << '-H'
      if header.to_s.downcase.start_with?('content-length:')
        args << "Content-Length: #{body.length}"
      else
        args << header.strip
      end
    end
    IO.popen(args, 'r+').read.to_s
  rescue => e
    return "Unhandled exception: #{e.message}: #{e}"
  end

  #
  # @note fetch a URL with Typhoeus
  #
  def get_url_typhoeus(uri)
    logger.info "Fetching URL: #{uri}"
    Typhoeus.get(uri).body
  rescue => e
    return "Unhandled exception: #{e.message}: #{e}"
  end

  #
  # @note post data to a URL with Typhoeus
  #
  def typhoeus_proxy(uri, headers = {}, data = {})
    Typhoeus.post(uri, headers: headers, body: data).body
  rescue => e
    return "Unhandled exception: #{e.message}: #{e}"
  end
end

run! if $PROGRAM_NAME == __FILE__
