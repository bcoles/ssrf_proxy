#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'
require './test/integration_test_helper.rb'

#
# @note SSRFProxy::Server integration tests
#
class TestIntegrationSSRFProxyServerNetHttpClient < Minitest::Test

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
  # @note test forwarding headers, method, body and cookies with Net::HTTP requests
  #
  def test_forwarding_net_http_client
    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl_proxy'
    ssrf_opts[:method] = 'GET'
    ssrf_opts[:post_data] = 'url=xxURLxx'
    ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)

    # Configure server options
    server_opts = SERVER_DEFAULT_OPTS.dup
    server_opts[:request_formatters] = [
      SSRFProxy::Formatter::Request::ForwardMethod.new,
      SSRFProxy::Formatter::Request::ForwardCookies.new,
      SSRFProxy::Formatter::Request::ForwardHeaders.new,
      SSRFProxy::Formatter::Request::ForwardBody.new
    ]
    server_opts[:response_formatters] = [
      SSRFProxy::Formatter::Response::Match.new(match: '<textarea>(.*)</textarea>\z'),
      SSRFProxy::Formatter::Response::StripHeaders.new(headers: ['server', 'date']),
      SSRFProxy::Formatter::Response::GuessStatus.new,
      SSRFProxy::Formatter::Response::GuessMime.new,
      SSRFProxy::Formatter::Response::AddLocationHeader.new,
      SSRFProxy::Formatter::Response::AddAuthenticateHeader.new
    ]

    # Start SSRF Proxy server and open connection
    start_server(ssrf, server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    # junk request data
    junk1 = ('a'..'z').to_a.sample(8).join.to_s
    junk2 = ('a'..'z').to_a.sample(8).join.to_s
    junk3 = ('a'..'z').to_a.sample(8).join.to_s
    junk4 = ('a'..'z').to_a.sample(8).join.to_s

    # check if method and post data are forwarded
    req = Net::HTTP::Post.new('/submit')
    req.set_form_data('data1' => junk1, 'data2' => junk2)
    res = http.request req
    assert(res)
    assert_includes(res.body, "<p>data1: #{junk1}</p>")
    assert_includes(res.body, "<p>data2: #{junk2}</p>")

    # check if method and headers (including cookies) are forwarded
    headers = { 'header1' => junk1,
                'header2' => junk2,
                'cookie'  => "junk3=#{junk3}; junk4=#{junk4}" }
    req = Net::HTTP::Post.new('/headers', headers.to_hash)
    req.set_form_data({})
    res = http.request req
    assert(res)
    assert_includes(res.body, "<p>Header1: #{junk1}</p>")
    assert_includes(res.body, "<p>Header2: #{junk2}</p>")
    assert_includes(res.body, "junk3=#{junk3}")
    assert_includes(res.body, "junk4=#{junk4}")

    # test forwarding method and headers with compression headers
    headers = { 'accept-encoding' => 'deflate, gzip' }
    req = Net::HTTP::Post.new('/', headers.to_hash)
    req.set_form_data({})
    res = http.request req
    assert(res)
    assert_includes(res.body, '<title>public</title>')
  end

  #
  # @note test server with https request using 'ssl' rule
  #
  def test_server_https_net_http_client
    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
    ssrf_opts[:insecure] = true
    ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)

    # Configure server options
    server_opts = SERVER_DEFAULT_OPTS.dup
    server_opts[:placeholder_formatters] = [
      SSRFProxy::Formatter::Placeholder::SSL.new
    ]
    server_opts[:response_formatters] = [
      SSRFProxy::Formatter::Response::Match.new(match: '<textarea>(.*)</textarea>\z')
    ]

    # Start SSRF Proxy server and open connection
    start_server(ssrf, server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8089')
    http.open_timeout = 10
    http.read_timeout = 10

    # get request method
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_includes(res.body, '<title>public</title>')
  end

  #
  # @note test server with Net::HTTP requests
  #
  def test_server_net_http_client
    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
    ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)

    # Configure server options
    server_opts = SERVER_DEFAULT_OPTS.dup
    server_opts[:placeholder_formatters] = [
      SSRFProxy::Formatter::Placeholder::AddBodyToURI.new,
      SSRFProxy::Formatter::Placeholder::AddAuthToURI.new,
      SSRFProxy::Formatter::Placeholder::AddCookiesToURI.new
    ]
    server_opts[:request_formatters] = [
      SSRFProxy::Formatter::Request::ForwardCookies.new
    ]
    server_opts[:response_formatters] = [
      SSRFProxy::Formatter::Response::Match.new(match: '<textarea>(.*)</textarea>\z'),
      SSRFProxy::Formatter::Response::StripHeaders.new(headers: ['server', 'date']),
      SSRFProxy::Formatter::Response::GuessStatus.new,
      SSRFProxy::Formatter::Response::GuessMime.new,
      SSRFProxy::Formatter::Response::AddLocationHeader.new,
      SSRFProxy::Formatter::Response::AddAuthenticateHeader.new
    ]

    # Start SSRF Proxy server and open connection
    start_server(ssrf, server_opts)

    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    # get request method
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_includes(res.body, '<title>public</title>')

    # strip headers
    assert(res['Server'].nil?)
    assert(res['Date'].nil?)

    # post request method
    headers = {}
    req = Net::HTTP::Post.new('/', headers.to_hash)
    req.set_form_data({})
    res = http.request req
    assert(res)
    assert_includes(res.body, '<title>public</title>')

    # body to URI
    junk1 = ('a'..'z').to_a.sample(8).join.to_s
    junk2 = ('a'..'z').to_a.sample(8).join.to_s

    url = '/submit'
    headers = {}
    req = Net::HTTP::Post.new(url, headers.to_hash)
    req.set_form_data('data1' => junk1, 'data2' => junk2)
    res = http.request req
    assert(res)
    assert_equal(junk1, res.body.scan(%r{<p>data1: (#{junk1})</p>}).flatten.first)
    assert_equal(junk2, res.body.scan(%r{<p>data2: (#{junk2})</p>}).flatten.first)

    url = '/submit?query'
    headers = {}
    req = Net::HTTP::Post.new(url, headers.to_hash)
    req.set_form_data('data1' => junk1, 'data2' => junk2)
    res = http.request req
    assert(res)
    assert_equal(junk1, res.body.scan(%r{<p>data1: (#{junk1})</p>}).flatten.first)
    assert_equal(junk2, res.body.scan(%r{<p>data2: (#{junk2})</p>}).flatten.first)

    # auth to URI
    url = '/auth'
    headers = {}
    req = Net::HTTP::Get.new(url, headers.to_hash)
    req.basic_auth('admin user', 'test password!@#$%^&*()_+-={}|\:";\'<>?,./')
    res = http.request req
    assert(res)
    assert(res.body =~ %r{<title>authentication successful</title>})

    # cookies to URI
    cookie_name = ('a'..'z').to_a.sample(8).join.to_s
    cookie_value = ('a'..'z').to_a.sample(8).join.to_s
    url = '/submit'
    headers = {}
    headers['Cookie'] = "#{cookie_name}=#{cookie_value}"
    res = http.request Net::HTTP::Get.new(url, headers.to_hash)
    assert(res)
    assert(res.body =~ %r{<p>#{cookie_name}: #{cookie_value}</p>})

    url = '/submit?query'
    headers = {}
    headers['Cookie'] = "#{cookie_name}=#{cookie_value}"
    res = http.request Net::HTTP::Get.new(url, headers.to_hash)
    assert(res)
    assert(res.body =~ %r{<p>#{cookie_name}: #{cookie_value}</p>})

    # ask password
    url = '/auth'
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal('Basic realm="127.0.0.1:8088"', res['WWW-Authenticate'])

    # detect redirect
    url = '/redirect'
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal('/admin', res['Location'])

    # guess mime
    url = "/#{('a'..'z').to_a.sample(8).join}.ico"
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal('image/x-icon', res['Content-Type'])

    # guess status
    url = '/auth'
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal(401, res.code.to_i)

    # CONNECT tunnel
    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert(res.body =~ %r{<title>public</title>})

    # CONNECT tunnel host unreachable
    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('10.99.88.77', '80')
    http.open_timeout = 10
    http.read_timeout = 10
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert_equal(504, res.code.to_i)
  end
end
