# coding: utf-8
#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require "minitest/autorun"

class SSRFProxyFuzzHamms < Minitest::Test
  require 'ssrf_proxy'
  require './test/common/constants.rb'
  require './test/common/http_server.rb'

  #
  # @note Check for Python
  #
  unless File.file?('/usr/bin/python')
    puts 'Error: Could not find Python. Skipping Hamms fuzz tests...'
    exit
  end

  #
  # @note start test HTTP server
  #
  puts "Starting HTTP server..."
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
    url = 'http://127.0.0.1:5500/?url=xxURLxx'
    assert_raises SSRFProxy::Server::Error::RemoteHostUnresponsive do
      ssrf = SSRFProxy::HTTP.new(url, @ssrf_opts)
      ssrf.logger.level = ::Logger::WARN
      SSRFProxy::Server.new(ssrf, @server_opts['interface'], @server_opts['port'])
    end
  end

  #
  # Fuzz test port 5501
  # - port accepts traffic but never sends back data
  #
  def test_no_data
    url = 'http://127.0.0.1:5501/?url=xxURLxx'

    # Configure SSRF options
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

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
    url = 'http://127.0.0.1:5502/?url=xxURLxx'

    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

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
    url = 'http://127.0.0.1:5503/?url=xxURLxx'

    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

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
    url = 'http://127.0.0.1:5504/?url=xxURLxx'

    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

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
    url = 'http://127.0.0.1:5505/?url=xxURLxx'

    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

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
    url = 'http://127.0.0.1:5506/?url=xxURLxx'

    # Configure SSRF options
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

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
    url = 'http://127.0.0.1:5507/?url=xxURLxx'

    # Configure SSRF options
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

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
    url = 'http://127.0.0.1:5508/?url=xxURLxx&sleep=5'

    # Configure SSRF options
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

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
    url = 'http://127.0.0.1:5510/?url=xxURLxx'

    # Configure SSRF options
    @ssrf_opts['timeout'] = 2

    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

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
    url = 'http://127.0.0.1:5516/?url=xxURLxx'
  
    # Configure SSRF options
    @ssrf_opts['timeout'] = 2
  
    # Start SSRF Proxy server with dummy SSRF
    start_server(url, @ssrf_opts, @server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(200, res.code.to_i)
  end
end
