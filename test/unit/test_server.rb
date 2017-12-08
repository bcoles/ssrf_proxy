# coding: utf-8
#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper'

class SSRFProxyServerTest < Minitest::Test

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
