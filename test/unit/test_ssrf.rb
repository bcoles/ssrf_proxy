#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper'

class TestUnitSSRF < Minitest::Test
  parallelize_me!

  #
  # @note test accessors
  #
  def test_accessors
    assert_equal(true, SSRFProxy::SSRF.public_method_defined?(:host))
    assert_equal(true, SSRFProxy::SSRF.public_method_defined?(:port))
    assert_equal(true, SSRFProxy::SSRF.public_method_defined?(:proxy))
    assert_equal(true, SSRFProxy::SSRF.public_method_defined?(:timeout))
    assert_equal(true, SSRFProxy::SSRF.public_method_defined?(:tls))
    assert_equal(true, SSRFProxy::SSRF.public_method_defined?(:insecure))
  end
end
