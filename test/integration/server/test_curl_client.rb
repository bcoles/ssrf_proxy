#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'
require './test/integration_test_helper.rb'

#
# @note SSRFProxy::Server integration tests with cURL client
#
class TestIntegrationSSRFProxyServerCurlClient < Minitest::Test

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
  # @note test forwarding headers, method, body and cookies with cURL requests
  #
  def test_forwarding_curl_client
    # Configure path to curl
    skip 'Could not find curl executable. Skipping curl tests...' unless curl_path

    server_opts = SERVER_DEFAULT_OPTS.dup

    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl_proxy'
    ssrf_opts[:method] = 'GET'
    ssrf_opts[:post_data] = 'url=xxURLxx'
    ssrf_opts[:match] = '<textarea>(.*)</textarea>\z'
    ssrf_opts[:strip] = 'server,date'
    ssrf_opts[:guess_mime] = true
    ssrf_opts[:guess_status] = true
    ssrf_opts[:forward_method] = true
    ssrf_opts[:forward_headers] = true
    ssrf_opts[:forward_body] = true
    ssrf_opts[:forward_cookies] = true
    ssrf_opts[:timeout] = 2

    # Start SSRF Proxy server and open connection
    start_server(ssrf_opts, server_opts)

    # junk request data
    junk1 = ('a'..'z').to_a.sample(8).join.to_s
    junk2 = ('a'..'z').to_a.sample(8).join.to_s
    junk3 = ('a'..'z').to_a.sample(8).join.to_s
    junk4 = ('a'..'z').to_a.sample(8).join.to_s

    # check if method and post data are forwarded
    cmd = [curl_path, '-isk',
           '-X', 'POST',
           '-d', "data1=#{junk1}&data2=#{junk2}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert_equal(junk1, res.scan(%r{<p>data1: (#{junk1})</p>}).flatten.first)
    assert_equal(junk2, res.scan(%r{<p>data2: (#{junk2})</p>}).flatten.first)

    # check if method and headers (including cookies) are forwarded
    cmd = [curl_path, '-isk',
           '-X', 'POST',
           '-d', '',
           '-H', "header1: #{junk1}",
           '-H', "header2: #{junk2}",
           '--cookie', "junk3=#{junk3}; junk4=#{junk4}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/headers']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{<p>Header1: #{junk1}</p>})
    assert(res =~ %r{<p>Header2: #{junk2}</p>})
    assert(res =~ /junk3=#{junk3}/)
    assert(res =~ /junk4=#{junk4}/)

    # test forwarding method and headers with compression headers
    cmd = [curl_path, '-isk',
           '-X', 'POST',
           '-d', '',
           '--compressed',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert_includes(res, '<title>public</title>')
  end

  #
  # @note test server with https request using 'ssl' rule
  #
  def test_server_https_curl_client
    server_opts = SERVER_DEFAULT_OPTS.dup

    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
    ssrf_opts[:match] = '<textarea>(.*)</textarea>\z'
    ssrf_opts[:rules] = 'ssl'
    ssrf_opts[:insecure] = true
    ssrf_opts[:timeout] = 2

    # Start SSRF Proxy server and open connection
    start_server(ssrf_opts, server_opts)

    # get request method
    cmd = [curl_path, '-isk',
           '-X', 'GET',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8089/']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert_includes(res, '<title>public</title>')
  end

  #
  # @note test server with curl requests
  #
  def test_server_curl_client
    skip 'Could not find curl executable. Skipping curl tests...' unless curl_path

    server_opts = SERVER_DEFAULT_OPTS.dup

    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
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

    # invalid request
    cmd = [curl_path, '-isk',
           '-X', 'GET',
           '--proxy', '127.0.0.1:8081',
           "http://127.0.0.1:8088/#{'A' * 5000}"]
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # get request method
    cmd = [curl_path, '-isk',
           '-X', 'GET',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert_includes(res, '<title>public</title>')

    # strip headers
    assert(res !~ /^Server: /)
    assert(res !~ /^Date: /)

    # post request method
    cmd = [curl_path, '-isk',
           '-X', 'POST',
           '-d', '',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert_includes(res, '<title>public</title>')

    # invalid request method
    cmd = [curl_path, '-isk',
           '-X', ('a'..'z').to_a.sample(8).join.to_s,
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # body to URI
    junk1 = ('a'..'z').to_a.sample(8).join.to_s
    junk2 = ('a'..'z').to_a.sample(8).join.to_s
    data = "data1=#{junk1}&data2=#{junk2}"

    cmd = [curl_path, '-isk',
           '-X', 'POST',
           '-d', data.to_s,
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)

    assert_equal(junk1, res.scan(%r{<p>data1: (#{junk1})</p>}).flatten.first)
    assert_equal(junk2, res.scan(%r{<p>data2: (#{junk2})</p>}).flatten.first)

    cmd = [curl_path, '-isk',
           '-X', 'POST',
           '-d', data.to_s,
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit?query']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert_equal(junk1, res.scan(%r{<p>data1: (#{junk1})</p>}).flatten.first)
    assert_equal(junk2, res.scan(%r{<p>data2: (#{junk2})</p>}).flatten.first)

    # auth to URI
    cmd = [curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           '-u', 'admin user:test password!@#$%^&*()_+-={}|\:";\'<>?,./',
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{<title>authentication successful</title>})

    cmd = [curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           '-u', (1..255).to_a.shuffle.pack('C*'),
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{<title>401 Unauthorized</title>})

    # cookies to URI
    cookie_name = ('a'..'z').to_a.sample(8).join.to_s
    cookie_value = ('a'..'z').to_a.sample(8).join.to_s
    cmd = [curl_path, '-isk',
           '--cookie', "#{cookie_name}=#{cookie_value}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{<p>#{cookie_name}: #{cookie_value}</p>})

    cmd = [curl_path, '-isk',
           '--cookie', "#{cookie_name}=#{cookie_value}",
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/submit?query']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{<p>#{cookie_name}: #{cookie_value}</p>})

    # ask password
    cmd = [curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # detect redirect
    cmd = [curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/redirect']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{^Location: /admin$}i)

    # guess mime
    cmd = [curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           "http://127.0.0.1:8088/#{('a'..'z').to_a.sample(8).join}.ico"]
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{^Content-Type: image\/x\-icon$}i)

    # guess status
    cmd = [curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/auth']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{\AHTTP/\d\.\d 401 Unauthorized})

    # WebSocket request
    cmd = [curl_path, '-isk',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/auth',
           '-H', 'Upgrade: WebSocket']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # CONNECT tunnel
    cmd = [curl_path, '-isk',
           '-X', 'GET',
           '--proxytunnel',
           '--proxy', '127.0.0.1:8081',
           'http://127.0.0.1:8088/']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert_includes(res, '<title>public</title>')

    # CONNECT tunnel host unreachable
    cmd = [curl_path, '-isk',
           '-X', 'GET',
           '--proxytunnel',
           '--proxy', '127.0.0.1:8081',
           'http://10.99.88.77/']
    res = IO.popen(cmd, 'r+').read.to_s
    assert valid_http_response?(res)
    assert(res =~ %r{\AHTTP/1\.0 504 Timeout})
  end

  #
  # @note test server with curl requests via proxychains
  #
  def test_server_proxychains_curl
    skip 'Could not find curl executable. Skipping proxychains tests...' unless curl_path
    skip 'Could not find proxychains executable. Skipping proxychains tests...' unless proxychains_path

    server_opts = SERVER_DEFAULT_OPTS.dup

    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
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

    # change to ./test/common to load proxychains.conf
    Dir.chdir("#{$root_dir}/test/common/") do

      # invalid request
      cmd = [proxychains_path,
             curl_path, '-isk',
             '-X', 'GET',
             "http://127.0.0.1:8088/#{'A' * 5000}"]
      res = IO.popen(cmd, 'r+').read.to_s
      assert(res =~ %r{^HTTP/1\.0 502 Bad Gateway})

      # get request method
      cmd = [proxychains_path,
             curl_path, '-isk',
             '-X', 'GET',
             'http://127.0.0.1:8088/']
      res = IO.popen(cmd, 'r+').read.to_s
      assert_includes(res, '<title>public</title>')

      # strip headers
      assert(res !~ /^Server: /)
      assert(res !~ /^Date: /)

      # post request method
      cmd = [proxychains_path,
             curl_path, '-isk',
             '-X', 'POST',
             '-d', '',
             'http://127.0.0.1:8088/']
      res = IO.popen(cmd, 'r+').read.to_s
      assert_includes(res, '<title>public</title>')
    end
  end
end
