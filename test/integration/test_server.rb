#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'
require './test/integration_test_helper.rb'

#
# @note SSRFProxy::Server integration tests
#
class TestIntegrationSSRFProxyServer < Minitest::Test

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
    @url = 'http://127.0.0.1:8088/curl?url=xxURLxx'
  end

  #
  # @note stop Celluloid
  #
  def teardown
    Celluloid.shutdown
  end

  #
  # @note test server socket
  #
  def test_server_socket
    server_opts = SERVER_DEFAULT_OPTS.dup
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = @url
    start_server(ssrf_opts, server_opts)
    Timeout.timeout(5) do
      begin
        TCPSocket.new(server_opts['interface'], server_opts['port']).close
        assert(true)
      rescue => e
        assert(false,
          "Connection to #{server_opts['interface']}:#{server_opts['port']} failed: #{e.message}")
      end
    end
  end

  #
  # @note test server address in use
  #
  def test_server_address_in_use
    server_opts = SERVER_DEFAULT_OPTS.dup
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = @url
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)
    assert_raises SSRFProxy::Server::Error::AddressInUse do
      SSRFProxy::Server.new(ssrf, server_opts['interface'], 8088)
    end
  end

  #
  # @note test server upstream proxy unresponsive
  #
  def test_server_upstream_proxy_unresponsive
    server_opts = SERVER_DEFAULT_OPTS.dup
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = @url
    ssrf_opts[:proxy] = "http://#{server_opts['interface']}:99999"
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)
    ssrf.logger.level = ::Logger::WARN
    assert_raises SSRFProxy::Server::Error::RemoteProxyUnresponsive do
      SSRFProxy::Server.new(ssrf, server_opts['interface'], server_opts['port'])
    end
  end

  #
  # @note test server remote host unresponsive
  #
  def test_server_host_unresponsive
    server_opts = SERVER_DEFAULT_OPTS.dup
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:99999/curl?url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)
    ssrf.logger.level = ::Logger::WARN
    assert_raises SSRFProxy::Server::Error::RemoteHostUnresponsive do
      SSRFProxy::Server.new(ssrf, server_opts['interface'], server_opts['port'])
    end
  end

  #
  # @note test server invalid response
  #
  def test_server_invalid_response
    server_opts = SERVER_DEFAULT_OPTS.dup

    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    # HTTP URL scheme for HTTPS server
    ssrf_opts[:url] = 'http://127.0.0.1:8089/curl?url=xxURLxx'
    ssrf_opts[:timeout] = 2

    # Start SSRF Proxy server and open connection
    start_server(ssrf_opts, server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 5
    http.read_timeout = 5

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert(503, res.code)
  end

  #
  # @note test upstream HTTP proxy server
  #
  def test_upstream_proxy
    server_opts = SERVER_DEFAULT_OPTS.dup

    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = @url
    ssrf_opts[:proxy] = 'http://127.0.0.1:8008/'
    ssrf_opts[:match] = '<textarea>(.*)</textarea>\z'
    ssrf_opts[:strip] = 'server,date'
    ssrf_opts[:guess_mime] = true
    ssrf_opts[:guess_status] = true
    ssrf_opts[:forward_cookies] = true
    ssrf_opts[:body_to_uri] = true
    ssrf_opts[:auth_to_uri] = true
    ssrf_opts[:cookies_to_uri] = true
    ssrf_opts[:timeout] = 2

    # Start SSRF Proxy server and open connection
    start_server(ssrf_opts, server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_includes(res.body, '<title>public</title>')
  end
end
