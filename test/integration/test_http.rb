#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'
require './test/integration_test_helper.rb'

#
# @note SSRFProxy::HTTP integration tests
#
class TestIntegrationSSRFProxyHTTP < Minitest::Test
  parallelize_me!

  #
  # @note test upstream HTTP proxy server
  #
  def test_upstream_proxy
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:proxy] = 'http://127.0.0.1:8008/'

    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    assert valid_ssrf_response?(res)
    assert_includes(res['body'], '<title>public</title>')
  end
end
