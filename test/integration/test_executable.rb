#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper'

class TestIntegrationSSRFProxyExecutable < Minitest::Test
  parallelize_me!

  #
  # @note test no arguments
  #
  def test_no_args
    cmd = ['bundle', 'exec', 'bin/ssrf-proxy']
    res = IO.popen(cmd, 'r+').read.to_s
    assert_includes(res, "SSRF Proxy v#{SSRFProxy::VERSION}")
  end

  #
  # @note test version
  #
  def test_version
    cmd = ['bundle', 'exec', 'bin/ssrf-proxy', '--version']
    res = IO.popen(cmd, 'r+').read.to_s
    assert_equal(res, "SSRF Proxy v#{SSRFProxy::VERSION}\n")
  end
end
