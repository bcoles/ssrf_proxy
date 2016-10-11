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
  require './test/common/proxy_server.rb'

  #
  # @note start test HTTP server
  #
  puts 'Starting HTTP server...'
  Thread.new do
    begin
      HTTPServer.new( 'interface' => '127.0.0.1',
                      'port' => '8088',
                      'ssl' => false,
                      'verbose' => false,
                      'debug' => false )
    rescue => e
      puts "Error: Could not start test HTTP server: #{e}"
    end
  end
  puts 'Waiting for HTTP server to start...'
  sleep 1

  #
  # @note start test HTTP server
  #
  puts 'Starting HTTPS server...'
  Thread.new do
    begin
      HTTPServer.new( 'interface' => '127.0.0.1',
                      'port' => '8089',
                      'ssl' => true,
                      'verbose' => false,
                      'debug' => false )
    rescue => e
      puts "Error: Could not start test HTTPS server: #{e}"
    end
  end
  puts 'Waiting for HTTPS server to start...'
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
    assert(res =~ %r{\AHTTP/\d\.\d [\d]+ })
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
  # @note start upstream HTTP proxy server
  #
  def start_proxy_server(interface, port)
    puts 'Starting HTTP proxy server...'
    t = Thread.new do
      begin
        ProxyServer.new.run('127.0.0.1', port.to_i)
      rescue => e
        puts "Error: Could not start HTTP proxy server: #{e}"
      end
    end
    puts 'Waiting for HTTP proxy server to start...'
    sleep 1
    t
  end

  #
  # @note test proxy server socket
  #
  def test_server_socket
    start_server(@url, @ssrf_opts, @server_opts)
    Timeout.timeout(5) do
      begin
        TCPSocket.new(@server_opts['interface'], @server_opts['port']).close
        assert(true)
      rescue => e
        assert(false,
          "Connection to #{@server_opts['interface']}:#{@server_opts['port']} failed: #{e.message}")
      end
    end
  end

  #
  # @note test proxy server with invalid SSRF
  #
  def test_server_invalid_ssrf
    assert_raises SSRFProxy::Server::Error::InvalidSsrf do
      ssrf = nil
      SSRFProxy::Server.new(ssrf, @server_opts['interface'], @server_opts['port'])
    end
  end

  #
  # @note test proxy server proxy recursion
  #
  def test_server_proxy_recursion
    assert_raises SSRFProxy::Server::Error::ProxyRecursion do
      ssrf_opts = @ssrf_opts
      ssrf_opts['proxy'] = "http://#{@server_opts['interface']}:#{@server_opts['port']}"
      ssrf = SSRFProxy::HTTP.new(@url, ssrf_opts)
      ssrf.logger.level = ::Logger::WARN
      SSRFProxy::Server.new(ssrf, @server_opts['interface'], @server_opts['port'])
    end
  end

  #
  # @note test proxy server address in use
  #
  def test_server_address_in_use
    assert_raises SSRFProxy::Server::Error::AddressInUse do
      ssrf_opts = @ssrf_opts
      ssrf = SSRFProxy::HTTP.new(@url, ssrf_opts)
      SSRFProxy::Server.new(ssrf, @server_opts['interface'], 8088)
    end
  end

  #
  # @note test proxy server remote proxy unresponsive
  #
  def test_server_proxy_unresponsive
    assert_raises SSRFProxy::Server::Error::RemoteProxyUnresponsive do
      ssrf_opts = @ssrf_opts
      ssrf_opts['proxy'] = "http://#{@server_opts['interface']}:99999"
      ssrf = SSRFProxy::HTTP.new(@url, ssrf_opts)
      ssrf.logger.level = ::Logger::WARN
      SSRFProxy::Server.new(ssrf, @server_opts['interface'], @server_opts['port'])
    end
  end

  #
  # @note test proxy server remote host unresponsive
  #
  def test_server_host_unresponsive
    assert_raises SSRFProxy::Server::Error::RemoteHostUnresponsive do
      ssrf_opts = @ssrf_opts
      url = 'http://127.0.0.1:99999/curl?url=xxURLxx'
      ssrf = SSRFProxy::HTTP.new(url, ssrf_opts)
      ssrf.logger.level = ::Logger::WARN
      SSRFProxy::Server.new(ssrf, @server_opts['interface'], @server_opts['port'])
    end
  end

  #
  # @note test upstream HTTP proxy server
  #
  def test_upstream_proxy
    # Start upstream HTTP proxy server
    assert(start_proxy_server('127.0.0.1', 8008),
      'Could not start upstream HTTP proxy server')

    # Configure SSRF options
    @ssrf_opts['proxy'] = 'http://127.0.0.1:8008/'
    @ssrf_opts['match'] = '<textarea>(.*)</textarea>\z'
    @ssrf_opts['strip'] = 'server,date'
    @ssrf_opts['guess_mime'] = true
    @ssrf_opts['guess_status'] = true
    @ssrf_opts['forward_cookies'] = true
    @ssrf_opts['body_to_uri'] = true
    @ssrf_opts['auth_to_uri'] = true
    @ssrf_opts['cookies_to_uri'] = true
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server and open connection
    start_server(@url, @ssrf_opts, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert(res.body =~ %r{<title>public</title>})
  end

  #
  # @note test proxy with raw TCP socket
  #
  def test_proxy_socket
    # Configure SSRF options
    @ssrf_opts['match'] = '<textarea>(.*)</textarea>\z'
    @ssrf_opts['strip'] = 'server,date'
    @ssrf_opts['guess_mime'] = true
    @ssrf_opts['guess_status'] = true
    @ssrf_opts['forward_cookies'] = true
    @ssrf_opts['body_to_uri'] = true
    @ssrf_opts['auth_to_uri'] = true
    @ssrf_opts['cookies_to_uri'] = true
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server and open connection
    start_server(@url, @ssrf_opts, @server_opts)

    # valid HTTP/1.0 request
    client = TCPSocket.new(@server_opts['interface'], @server_opts['port'])
    client.write("GET http://127.0.0.1:8088/ HTTP/1.0\n\n")
    res = client.readpartial(1024)
    client.close
    validate_response(res)
    assert(res =~ %r{<title>public</title>})

    # valid HTTP/1.1 request
    client = TCPSocket.new(@server_opts['interface'], @server_opts['port'])
    client.write("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    res = client.readpartial(1024)
    client.close
    validate_response(res)
    assert(res =~ %r{<title>public</title>})

    # invalid HTTP/1.0 request
    client = TCPSocket.new(@server_opts['interface'], @server_opts['port'])
    client.write("GET / HTTP/1.0\n\n")
    res = client.readpartial(1024)
    client.close
    validate_response(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # invalid HTTP/1.1 request
    client = TCPSocket.new(@server_opts['interface'], @server_opts['port'])
    client.write("GET / HTTP/1.1\n\n")
    res = client.readpartial(1024)
    client.close
    validate_response(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # CONNECT tunnel
    client = TCPSocket.new(@server_opts['interface'], @server_opts['port'])
    client.write("CONNECT 127.0.0.1:8088 HTTP/1.0\n\n")
    res = client.readpartial(1024)
    validate_response(res)
    assert(res =~ %r{\AHTTP/1\.0 200 Connection established\r\n\r\n\z})
    client.write("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    res = client.readpartial(1024)
    validate_response(res)
    client.close
    assert(res =~ %r{<title>public</title>})

    # CONNECT tunnel host unreachable
    client = TCPSocket.new(@server_opts['interface'], @server_opts['port'])
    client.write("CONNECT 10.99.88.77:80 HTTP/1.0\n\n")
    res = client.readpartial(1024)
    validate_response(res)
    client.close
    assert(res =~ %r{\AHTTP/1\.0 504 Timeout})
  end

  #
  # @note test proxy forwarding with Net::HTTP requests
  #
  def test_proxy_forwarding
    @url = 'http://127.0.0.1:8088/curl_proxy'

    # Configure SSRF options
    @ssrf_opts['method'] = 'GET'
    @ssrf_opts['post_data'] = 'url=xxURLxx'
    @ssrf_opts['match'] = '<textarea>(.*)</textarea>\z'
    @ssrf_opts['strip'] = 'server,date'
    @ssrf_opts['cookie'] = 'ssrf_cookie=123'
    @ssrf_opts['guess_mime'] = true
    @ssrf_opts['guess_status'] = true
    @ssrf_opts['forward_method'] = true
    @ssrf_opts['forward_headers'] = true
    @ssrf_opts['forward_body'] = true
    @ssrf_opts['forward_cookies'] = true
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server and open connection
    start_server(@url, @ssrf_opts, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    junk1 = "#{('a'..'z').to_a.shuffle[0,8].join}"
    junk2 = "#{('a'..'z').to_a.shuffle[0,8].join}"
    junk3 = "#{('a'..'z').to_a.shuffle[0,8].join}"
    junk4 = "#{('a'..'z').to_a.shuffle[0,8].join}"

    # check if method and post data are forwarded
    data = "data1=#{junk1}&data2=#{junk2}"
    headers = {}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = Net::HTTP::Post.new('/submit', headers.to_hash)
    req.body = data
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<p>data1: #{junk1}</p>})
    assert(res.body =~ %r{<p>data2: #{junk2}</p>})

    # check if headers (including cookies) are forwarded
    headers = {'header1' => junk1, 'header2' => junk2, 'cookie' => "junk3=#{junk3}; junk4=#{junk4}"}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = Net::HTTP::Post.new('/headers', headers.to_hash)
    req.body = ''
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<p>Header1: #{junk1}</p>})
    assert(res.body =~ %r{<p>Header2: #{junk2}</p>})
    assert(res.body =~ %r{ssrf_cookie=123})
    assert(res.body =~ %r{junk3=#{junk3}})
    assert(res.body =~ %r{junk4=#{junk4}})
  end

  #
  # @note test proxy https
  #
  def test_proxy_net_http_ssl
    # Configure SSRF options
    @ssrf_opts['match'] = '<textarea>(.*)</textarea>\z'
    @ssrf_opts['rules'] = 'ssl'
    @ssrf_opts['insecure'] = true
    @ssrf_opts['timeout'] = 2

    # Configure server options
    @server_opts['port'] = '8082'

    # Start SSRF Proxy server and open connection
    start_server(@url, @ssrf_opts, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8082').new('127.0.0.1', '8089')
    http.open_timeout = 10
    http.read_timeout = 10

    # get request method
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert(res.body =~ %r{<title>public</title>})
  end

  #
  # @note test proxy with Net::HTTP requests
  #
  def test_proxy_net_http
    # Configure SSRF options
    @ssrf_opts['match'] = '<textarea>(.*)</textarea>\z'
    @ssrf_opts['strip'] = 'server,date'
    @ssrf_opts['guess_mime'] = true
    @ssrf_opts['guess_status'] = true
    @ssrf_opts['forward_cookies'] = true
    @ssrf_opts['body_to_uri'] = true
    @ssrf_opts['auth_to_uri'] = true
    @ssrf_opts['cookies_to_uri'] = true
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server and open connection
    start_server(@url, @ssrf_opts, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    # get request method
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert(res.body =~ %r{<title>public</title>})

    # strip headers
    assert(res['Server'].nil?)
    assert(res['Date'].nil?)

    # post request method
    headers = {}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = Net::HTTP::Post.new('/', headers.to_hash)
    req.body = ''
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<title>public</title>})

    # body to URI
    junk1 = "#{('a'..'z').to_a.shuffle[0,8].join}"
    junk2 = "#{('a'..'z').to_a.shuffle[0,8].join}"
    data = "data1=#{junk1}&data2=#{junk2}"
    url = '/submit'
    headers = {}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = Net::HTTP::Post.new(url, headers.to_hash)
    req.body = data
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<p>data1: #{junk1}</p>})
    assert(res.body =~ %r{<p>data2: #{junk2}</p>})

    url = '/submit?query'
    headers = {}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = Net::HTTP::Post.new(url, headers.to_hash)
    req.body = data
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<p>data1: #{junk1}</p>})
    assert(res.body =~ %r{<p>data2: #{junk2}</p>})

    # auth to URI
    url = '/auth'
    headers = {}
    req = Net::HTTP::Get.new(url, headers.to_hash)
    req.basic_auth('admin user', 'test password!@#$%^&*()_+-={}|\:";\'<>?,./')
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<title>authentication successful</title>})

    # cookies to URI
    cookie_name = "#{('a'..'z').to_a.shuffle[0,8].join}"
    cookie_value = "#{('a'..'z').to_a.shuffle[0,8].join}"
    url = '/submit'
    headers = {}
    headers['Cookie'] = "#{cookie_name}=#{cookie_value}"
    res = http.request Net::HTTP::Get.new(url, headers.to_hash)
    assert(res)
    assert(res.body =~ %r{<p>#{cookie_name}: #{cookie_value}</p>})

    url = '/submit?query'
    headers = {}
    headers['Cookie'] = "#{cookie_name}=#{cookie_value}"
    res = http.request Net::HTTP::Get.new(url, headers.to_hash)
    assert(res)
    assert(res.body =~ %r{<p>#{cookie_name}: #{cookie_value}</p>})

    # ask password
    url = '/auth'
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal('Basic realm="127.0.0.1:8088"', res['WWW-Authenticate'])

    # detect redirect
    url = '/redirect'
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal('/admin', res['Location'])

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

    # CONNECT tunnel
    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert(res.body =~ %r{<title>public</title>})

    # CONNECT tunnel host unreachable
    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('10.99.88.77', '80')
    http.open_timeout = 10
    http.read_timeout = 10
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(504, res.code.to_i)
  end

  #
  # @note test proxy with curl requests
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
    @ssrf_opts['match'] = '<textarea>(.*)</textarea>\z'
    @ssrf_opts['strip'] = 'server,date'
    @ssrf_opts['guess_mime'] = true
    @ssrf_opts['guess_status'] = true
    @ssrf_opts['forward_cookies'] = true
    @ssrf_opts['body_to_uri'] = true
    @ssrf_opts['auth_to_uri'] = true
    @ssrf_opts['cookies_to_uri'] = true
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server and open connection
    start_server(@url, @ssrf_opts, @server_opts)

    # invalid request
    cmd = [@curl_path, '-isk',
           '-X', 'GET',
           '--proxy', '127.0.0.1:8081',
           "http://127.0.0.1:8088/#{'A'*5000}"]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # get request method
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

    # post request method
    cmd = [@curl_path, '-isk',
           '-X', 'POST',
           '-d', '',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<title>public</title>})

    # invalid request method
    cmd = [@curl_path, '-isk',
           '-X', "#{('a'..'z').to_a.shuffle[0,8].join}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # body to URI
    junk1 = "#{('a'..'z').to_a.shuffle[0,8].join}"
    junk2 = "#{('a'..'z').to_a.shuffle[0,8].join}"
    data = "data1=#{junk1}&data2=#{junk2}"
    cmd = [@curl_path, '-isk',
           '-X', 'POST',
           '-d', "#{data}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<p>data1: #{junk1}</p>})
    assert(res =~ %r{<p>data2: #{junk2}</p>})

    cmd = [@curl_path, '-isk',
           '-X', 'POST',
           '-d', "#{data}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit?query']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<p>data1: #{junk1}</p>})
    assert(res =~ %r{<p>data2: #{junk2}</p>})

    # auth to URI
    cmd = [@curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           '-u', 'admin user:test password!@#$%^&*()_+-={}|\:";\'<>?,./',
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<title>authentication successful</title>})

    cmd = [@curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           '-u', (1 .. 255).to_a.shuffle.pack('C*'),
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<title>401 Unauthorized</title>})

    # cookies to URI
    cookie_name = "#{('a'..'z').to_a.shuffle[0,8].join}"
    cookie_value = "#{('a'..'z').to_a.shuffle[0,8].join}"
    cmd = [@curl_path, '-isk',
           '--cookie', "#{cookie_name}=#{cookie_value}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<p>#{cookie_name}: #{cookie_value}</p>})

    cmd = [@curl_path, '-isk',
           '--cookie', "#{cookie_name}=#{cookie_value}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit?query']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<p>#{cookie_name}: #{cookie_value}</p>})

    # ask password
    cmd = [@curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # detect redirect
    cmd = [@curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/redirect']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{^Location: /admin$}i)

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

    # WebSocket request
    cmd = [@curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/auth',
           '-H', 'Upgrade: WebSocket']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # CONNECT tunnel
    cmd = [@curl_path, '-isk',
           '-X', 'GET',
           '--proxytunnel',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{<title>public</title>})

    # CONNECT tunnel host unreachable
    cmd = [@curl_path, '-isk',
           '-X', 'GET',
           '--proxytunnel',
           '--proxy', '127.0.0.1:8081',
           'http://10.99.88.77/']
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ %r{\AHTTP/1\.0 504 Timeout})
  end
end
