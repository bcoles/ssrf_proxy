# coding: utf-8
#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper'

class SSRFProxyTest < Minitest::Test
  def test_ssrfproxy_classes
    assert_kind_of(Module, SSRFProxy)
    assert_kind_of(Module, SSRFProxy::HTTP)
    assert_kind_of(Module, SSRFProxy::Server)
  end

  def test_ssrfproxy_constants
    assert_kind_of(String, SSRFProxy::VERSION)
    assert_kind_of(String, SSRFProxy::BANNER)
  end
end
