#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'
require './test/integration_test_helper.rb'

#
# @note SSRFProxy::Server integration tests with nmap client
#
class TestIntegrationSSRFProxyServerNmapClient < Minitest::Test

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
  # @note test server with nmap requests via proxychains
  #
  def test_server_proxychains_nmap
    skip 'Could not find nmap executable. Skipping proxychains tests...' unless nmap_path
    skip 'Could not find proxychains executable. Skipping proxychains tests...' unless proxychains_path

    server_opts = SERVER_DEFAULT_OPTS.dup

    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
    ssrf_opts[:match] = '<textarea>(.*)</textarea>\z'
    ssrf_opts[:guess_mime] = true
    ssrf_opts[:guess_status] = true
    ssrf_opts[:forward_cookies] = true
    ssrf_opts[:body_to_uri] = true
    ssrf_opts[:auth_to_uri] = true
    ssrf_opts[:cookies_to_uri] = true
    ssrf_opts[:fail_no_content] = true
    ssrf_opts[:timeout] = 2

    # Start SSRF Proxy server and open connection
    start_server(ssrf_opts, server_opts)

    # change to ./test/common to load proxychains.conf
    Dir.chdir("#{$root_dir}/test/common/") do
      cmd = [proxychains_path,
             nmap_path,
             '127.0.0.1',
             '-p', '1,8088']
      res = IO.popen(cmd, 'r+').read.to_s
      puts '-' * 80
      puts res
      puts '-' * 80
      assert(res =~ %r{8088/tcp\s*open})
      assert(res =~ %r{1/tcp\s*closed})
    end
  end
end
