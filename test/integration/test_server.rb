# coding: utf-8
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'

class SSRFProxyServerTest < Minitest::Test
  require './test/common/constants.rb'
  require './test/common/http_server.rb'

  #
  # @note start test HTTP server
  #
  puts 'Starting HTTP server...'
  Thread.new do
    begin
      HTTPServer.new(
        'interface' => '127.0.0.1',
        'port' => '8088',
        'ssl' => false,
        'verbose' => false,
        'debug' => false)
    rescue => e
      puts "Error: Could not start test HTTP server: #{e}"
    end
  end
  puts 'Waiting for HTTP server to start...'
  sleep 1

  #
  # @note start Celluloid before tasks
  #
  def before_setup
    Celluloid.shutdown
    Celluloid.boot
  end

  #
  # @note (re)set default SSRF and SSRF Proxy options
  #
  def setup
    @server_opts = SERVER_DEFAULT_OPTS.dup
    @ssrf_opts = SSRF_DEFAULT_OPTS.dup
    @url = 'http://127.0.0.1:8088/curl?url=xxURLxx'
  end

  #
  # @note stop Celluloid
  #
  def teardown
    Celluloid.shutdown
  end

  #
  # @note check a HTTP response is valid
  #
  def validate_response(res)
    assert(res)
    assert(res =~ %r{\AHTTP/})
    true
  end

  #
  # @note start SSRF Proxy server
  #
  def start_server(url, ssrf_opts, server_opts)
    puts 'Starting SSRF Proxy server...'

    # setup ssrf
    ssrf = SSRFProxy::HTTP.new(url, ssrf_opts)
    ssrf.logger.level = ::Logger::WARN

    # start proxy server
    Thread.new do
      begin
        @ssrf_proxy = SSRFProxy::Server.new(ssrf, server_opts['interface'], server_opts['port'])
        @ssrf_proxy.logger.level = ::Logger::WARN
        @ssrf_proxy.serve
      rescue => e
        puts "Error: Could not start SSRF Proxy server: #{e.message}"
      end
    end
    puts 'Waiting for SSRF Proxy server to start...'
    sleep 1
  end

  #
  # @note test proxy with Net:HTTP
  #
  def test_proxy_net_http
    # Configure SSRF options
    @ssrf_opts['rules'] = 'urlencode'
    @ssrf_opts['strip'] = 'server,date'
    @ssrf_opts['guess_mime'] = true
    @ssrf_opts['guess_status'] = true
    @ssrf_opts['ask_password'] = true
    @ssrf_opts['forward_cookies'] = true
    @ssrf_opts['body_to_uri'] = true
    @ssrf_opts['auth_to_uri'] = true
    @ssrf_opts['cookies_to_uri'] = true

    # Start SSRF Proxy server and open connection
    start_server(@url, @ssrf_opts, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    # get request
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert(res.body =~ %r{<title>public<\/title>})

    # strip headers
    assert(res['Server'].nil?)
    assert(res['Date'].nil?)

    # post request
    headers = {}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = Net::HTTP::Post.new('/', headers.to_hash)
    req.body = ''
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<title>public<\/title>})

    # body to URI
    junk = ('a'..'z').to_a.sample(8).join.to_s
    url = '/submit'
    headers = {}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = Net::HTTP::Post.new(url, headers.to_hash)
    req.body = "data=#{junk}"
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<p>#{junk}<\/p>})

    # auth to URI
    url = '/auth'
    headers = {}
    req = Net::HTTP::Get.new(url, headers.to_hash)
    req.basic_auth('admin', 'test')
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<title>authentication successful</title>})

    # cookies to URI
    junk = ('a'..'z').to_a.sample(8).join.to_s
    url = '/submit'
    headers = {}
    headers['Cookie'] = "data=#{junk}"
    res = http.request Net::HTTP::Get.new(url, headers.to_hash)
    assert(res)
    assert(res.body =~ %r{<p>#{junk}<\/p>})

    # ask password
    url = '/auth'
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal('Basic realm="127.0.0.1:8088"', res['WWW-Authenticate'])

    # guess mime
    url = "/#{('a'..'z').to_a.sample(8).join}.ico"
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal('image/x-icon', res['Content-Type'])

    # guess status
    url = '/auth'
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal(401, res.code.to_i)
  end

  #
  # @note test proxy with curl
  #
  def test_proxy_curl
    # Configure path to curl
    if File.file?('/usr/sbin/curl')
      @curl_path = '/usr/sbin/curl'
    elsif File.file?('/usr/bin/curl')
      @curl_path = '/usr/bin/curl'
    end
    assert(@curl_path, 'Could not find curl executable. Skipping curl tests...')

    # Configure SSRF options
    @ssrf_opts['rules'] = 'urlencode'
    @ssrf_opts['strip'] = 'server,date'
    @ssrf_opts['guess_mime'] = true
    @ssrf_opts['guess_status'] = true
    @ssrf_opts['ask_password'] = true
    @ssrf_opts['forward_cookies'] = true
    @ssrf_opts['body_to_uri'] = true
    @ssrf_opts['auth_to_uri'] = true
    @ssrf_opts['cookies_to_uri'] = true

    # Start SSRF Proxy server and open connection
    start_server(@url, @ssrf_opts, @server_opts)

    # get request
    cmd = [@curl_path, '-isk',
           '-X', 'GET',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<title>public</title>})

    # strip headers
    assert(res !~ /^Server: /)
    assert(res !~ /^Date: /)

    # post request
    cmd = [@curl_path, '-isk',
           '-X', 'POST',
           '-d', '',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<title>public</title>})

    # body to URI
    junk = ('a'..'z').to_a.sample(8).join.to_s
    cmd = [@curl_path, '-isk',
           '-X', 'POST',
           '-d', "data=#{junk}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<p>#{junk}</p>})

    # auth to URI
    cmd = [@curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           '-u', 'admin:test',
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<title>authentication successful</title>})

    # cookies to URI
    junk = ('a'..'z').to_a.sample(8).join.to_s
    cmd = [@curl_path, '-isk',
           '--cookie', "data=#{junk}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<p>#{junk}</p>})

    # ask password
    cmd = [@curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # guess mime
    cmd = [@curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           "http://127.0.0.1:8088/#{('a'..'z').to_a.sample(8).join}.ico"]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{^Content-Type: image\/x\-icon$}i)

    # guess status
    cmd = [@curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{\AHTTP/\d\.\d 401 Unauthorized})

    # CONNECT tunnel
    cmd = [@curl_path, '-isk',
           '-X', 'GET',
           '--proxytunnel',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<title>public</title>})
  end
end
