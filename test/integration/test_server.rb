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
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/curl?url=xxURLxx')

    start_server(ssrf, server_opts)
    Timeout.timeout(5) do
      begin
        TCPSocket.new(server_opts[:interface], server_opts[:port]).close
        assert(true)
      rescue => e
        assert(false,
          "Connection to #{server_opts[:interface]}:#{server_opts[:port]} failed: #{e.message}")
      end
    end
  end

  #
  # @note test server address in use
  #
  # Invokes an AddressInUse error by trying to use
  # the port in use by the WEBrick HTTP test server
  #
  def test_server_address_in_use
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/curl?url=xxURLxx')

    server_opts = SERVER_DEFAULT_OPTS.dup
    server_opts[:port] = 8088
    assert_raises SSRFProxy::Server::Error::AddressInUse do
      SSRFProxy::Server.new(ssrf, server_opts)
    end
  end

  #
  # @note test server upstream proxy unresponsive
  #
  # Invokes a RemoteProxyUnresponsive error
  # by specifying an invalid port.
  #
  def test_server_upstream_proxy_unresponsive
    server_opts = SERVER_DEFAULT_OPTS.dup
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
    ssrf_opts[:proxy] = "http://#{server_opts[:interface]}:99999"
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)
    assert_raises SSRFProxy::Server::Error::RemoteProxyUnresponsive do
      SSRFProxy::Server.new(ssrf)
    end
  end

  #
  # @note test server remote host unresponsive
  #
  # Invokes a RemoteHostUnresponsive error
  # by specifying an invalid port.
  #
  def test_server_host_unresponsive
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:99999/curl?url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)
    assert_raises SSRFProxy::Server::Error::RemoteHostUnresponsive do
      SSRFProxy::Server.new(ssrf)
    end
  end

  #
  # @note test server invalid response
  #
  def test_server_invalid_response
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    # Invoke an invalid response with 'http' URL scheme for HTTPS server
    ssrf_opts[:url] = 'http://127.0.0.1:8089/curl?url=xxURLxx'
    ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)

    start_server(ssrf)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert(503, res.code)
  end

  #
  # @note test upstream HTTP proxy server
  #
  def test_upstream_proxy
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
    ssrf_opts[:proxy] = 'http://127.0.0.1:8008/'
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)

    start_server(ssrf)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_includes(res.body, '<title>public</title>')
  end
end
