#
# Copyright (c) 2015 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require 'minitest/autorun'

class SSRFProxyServerTest < Minitest::Test

  require 'ssrf_proxy'

  #
  # @note test accessors
  #
  def test_accessors
    assert_equal(true, SSRFProxy::Server.method_defined?(:logger))
  end

  #
  # @note test public methods
  #
  def test_public_methods
    assert_equal(true, SSRFProxy::Server.method_defined?(:serve))
  end

  #
  # @note test private methods
  #
  def test_private_methods
    assert_equal(false, SSRFProxy::Server.method_defined?(:print_status))
    assert_equal(false, SSRFProxy::Server.method_defined?(:print_good))
    assert_equal(false, SSRFProxy::Server.method_defined?(:shutdown))
    assert_equal(false, SSRFProxy::Server.method_defined?(:handle_connection))
  end

end

