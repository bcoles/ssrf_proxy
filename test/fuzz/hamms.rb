#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'
require './test/integration_test_helper.rb'

class TestFuzzHammsSSRFProxyServer < Minitest::Test
  #
  # @note Check for Python
  #
  unless File.file?('/usr/bin/python')
    puts 'Error: Could not find Python. Skipping Hamms fuzz tests...'
    exit
  end

  #
  # @note start Celluloid before tasks
  #
  def before_setup
    Celluloid.shutdown
    Celluloid.boot
  end

  #
  # @note (re)set default SSRF and SSRF Proxy options and start Hamms server
  #
  def setup
    @server_opts = SERVER_DEFAULT_OPTS.dup
    @ssrf_opts = SSRF_DEFAULT_OPTS.dup

    # start Hamms server
    Thread.new do
      hamms = IO.popen(['/usr/bin/python', '-m', 'hamms'], 'r+')
      @pid = hamms.pid
      if @pid.nil?
        puts 'Error: Could not start Python Hamms module. Skipping Hamms fuzz tests...'
        exit
      end
    end

    puts 'Waiting for Hamms server to start...'
    sleep 1
  end

  #
  # @note kill Hamms server
  #
  def teardown
    Process.kill('HUP', @pid)
  end

  #
  # Fuzz test port 5500
  # - nothing listening
  #
  def test_not_listening
    @ssrf_opts[:url] = 'http://127.0.0.1:5500/?url=xxURLxx'
    assert_raises SSRFProxy::Server::Error::RemoteHostUnresponsive do
      ssrf = SSRFProxy::HTTP.new(@ssrf_opts)
      ssrf.logger.level = ::Logger::WARN
      SSRFProxy::Server.new(ssrf, interface: @server_opts['interface'], port: @server_opts['port'])
    end
  end

  #
  # Fuzz test port 5501
  # - port accepts traffic but never sends back data
  #
  def test_no_data
    @ssrf_opts[:url] = 'http://127.0.0.1:5501/?url=xxURLxx'
    @ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(504, res.code.to_i)
  end

  #
  # Fuzz test port 5502
  # - port sends back an empty string immediately upon connection
  #
  def test_empty_string_upon_connection
    @ssrf_opts[:url] = 'http://127.0.0.1:5502/?url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(503, res.code.to_i)
  end

  #
  # Fuzz test port 5503
  # - port sends back an empty string after the client sends data
  #
  def test_empty_string_after_client_data
    @ssrf_opts[:url] = 'http://127.0.0.1:5503/?url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(503, res.code.to_i)
  end

  #
  # Fuzz test port 5504
  # - port sends back a malformed response ("foo bar") immediately upon connection
  #
  def test_malformed_response_upon_connection
    @ssrf_opts[:url] = 'http://127.0.0.1:5504/?url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(503, res.code.to_i)
  end

  #
  # Fuzz test port 5505
  # - port sends back a malformed response ("foo bar") after the client sends data
  #
  def test_malformed_response_after_client_data
    @ssrf_opts[:url] = 'http://127.0.0.1:5505/?url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(503, res.code.to_i)
  end

  #
  # Fuzz test port 5506
  # - sends back one byte every 5 seconds
  #
  def test_one_byte_every_5_seconds
    @ssrf_opts[:url] = 'http://127.0.0.1:5506/?url=xxURLxx'
    @ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(504, res.code.to_i)
  end

  #
  # Fuzz test port 5507
  # - sends back one byte every 30 seconds
  #
  def test_one_byte_every_30_seconds
    @ssrf_opts[:url] = 'http://127.0.0.1:5507/?url=xxURLxx'
    @ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(504, res.code.to_i)
  end

  #
  # Fuzz test port 5508
  # - sleeps for the specified time
  #
  def test_sleep
    @ssrf_opts[:url] = 'http://127.0.0.1:5508/?url=xxURLxx&sleep=5'
    @ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(504, res.code.to_i)
  end

  #
  # Fuzz test port 5510
  # - port sends 1MB response with header 'Content-Length: 3'
  #
  def test_content_length_too_short
    @ssrf_opts[:url] = 'http://127.0.0.1:5510/?url=xxURLxx'
    @ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(200, res.code.to_i)
  end

  # Fuzz port 5516
  # - server closes the connection partway through
  #
  def test_close_part_way_through
    @ssrf_opts[:url] = 'http://127.0.0.1:5516/?url=xxURLxx'
    @ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(@ssrf_opts)

    # Start SSRF Proxy server with dummy SSRF
    start_server(ssrf, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(200, res.code.to_i)
  end
end
