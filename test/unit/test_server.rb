#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper'

class TestUnitSSRFProxyServer < Minitest::Test

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
  # @note test server with invalid SSRF
  #
  def test_invalid_ssrf
    server_opts = SERVER_DEFAULT_OPTS.dup
    assert_raises SSRFProxy::Server::Error::InvalidSsrf do
      ssrf = nil
      SSRFProxy::Server.new(ssrf, server_opts['interface'], server_opts['port'])
    end
  end

  #
  # @note test server with proxy recursion
  #
  def test_proxy_recursion
    server_opts = SERVER_DEFAULT_OPTS.dup
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1/xxURLxx'
    ssrf_opts[:proxy] = "http://#{server_opts['interface']}:#{server_opts['port']}"
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)
    ssrf.logger.level = ::Logger::WARN
    assert_raises SSRFProxy::Server::Error::ProxyRecursion do
      SSRFProxy::Server.new(ssrf, server_opts['interface'], server_opts['port'])
    end
  end

  #
  # @note test accessors
  #
  def test_accessors
    assert_equal(true, SSRFProxy::Server.public_method_defined?(:logger))
  end

  #
  # @note test public methods
  #
  def test_public_methods
    assert_equal(true, SSRFProxy::Server.public_method_defined?(:serve))
  end

  #
  # @note test private methods
  #
  def test_private_methods
    assert_equal(true, SSRFProxy::Server.private_method_defined?(:print_status))
    assert_equal(true, SSRFProxy::Server.private_method_defined?(:print_good))
    assert_equal(true, SSRFProxy::Server.private_method_defined?(:print_error))
    assert_equal(true, SSRFProxy::Server.private_method_defined?(:shutdown))
    assert_equal(true, SSRFProxy::Server.private_method_defined?(:handle_connection))
    assert_equal(true, SSRFProxy::Server.private_method_defined?(:send_request))
    assert_equal(true, SSRFProxy::Server.private_method_defined?(:port_open?))
  end
end
