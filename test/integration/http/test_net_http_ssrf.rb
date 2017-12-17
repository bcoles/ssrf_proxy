#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'
require './test/integration_test_helper.rb'

#
# @note SSRFProxy::HTTP integration tests with Net::HTTP SSRF
#
class TestIntegrationSSRFProxyHTTPNetHttpSsrf < Minitest::Test
  parallelize_me!

  #
  # @note test send_uri GET method
  #
  def test_send_uri_get_net_http
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    assert valid_ssrf_response?(res)
    assert_equal('public', res['title'])

    res = ssrf.send_uri('http://127.0.0.1:8088/admin')
    assert valid_ssrf_response?(res)
    assert_equal('administration', res['title'])

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    assert valid_ssrf_response?(res)
    assert_equal('401 Unauthorized', res['title'])
  end

  #
  # @note test send_uri HEAD method
  #
  def test_send_uri_head_net_http
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:method] = 'HEAD'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    assert valid_ssrf_response?(res)
  end

  #
  # @note test send_uri POST method
  # 
  def test_send_uri_post_net_http
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http'
    opts[:method] = 'POST'
    opts[:post_data] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    assert valid_ssrf_response?(res)
    assert_equal('public', res['title'])

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    assert valid_ssrf_response?(res)
    assert_equal('401 Unauthorized', res['title'])
  end

  #
  # @note test send_uri match
  # 
  def test_send_uri_match_net_http
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:match] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/")
    assert valid_ssrf_response?(res)
    assert(res['body'].start_with?('<html>'))
    refute_includes(res['body'], 'Response:')
    refute_includes(res['body'], '<textarea>')
  end

  #
  # @note test send_uri guess_mime
  # 
  def test_send_uri_guess_mine_net_http
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:guess_mime] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/#{('a'..'z').to_a.sample(8).join}.ico")
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Content-Type: image\/x\-icon$/i)
  end

  #
  # @note test send_uri guess_status
  # 
  def test_send_uri_guess_status_net_http
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    assert valid_ssrf_response?(res)
    assert_equal('HTTP/1.1 401 Unauthorized', res['status_line'])
  end

  #
  # @note test send_uri ask password
  # 
  def test_send_uri_ask_password_net_http
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)
  end

  #
  # @note test send_uri detect redirect
  # 
  def test_send_uri_detect_redirect_net_http
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/redirect')
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Location: \/admin$/i)
  end

  #
  # @note test send_uri ip_encoding
  # 
  def test_send_uri_ip_encoding_net_http
    %w[int oct hex dotted_hex].each do |encoding|
      opts = SSRF_DEFAULT_OPTS.dup
      opts[:url] = "http://127.0.0.1:8088/net_http?url=xxURLxx"
      opts[:ip_encoding] = encoding
      ssrf = SSRFProxy::HTTP.new(opts)
      assert valid_ssrf?(ssrf)

      res = ssrf.send_uri('http://127.0.0.1:8088/')
      assert valid_ssrf_response?(res)
      assert_equal('public', res['title'])

      res = ssrf.send_uri('http://127.0.0.1:8088/auth')
      assert valid_ssrf_response?(res)
      assert_equal('401 Unauthorized', res['title'])
    end
  end

  #
  # @note test send_request
  #
  def test_send_request_net_http
    # http get
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert_equal('public', res['title'])

    res = ssrf.send_request("GET /admin HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert_equal('administration', res['title'])

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert_equal('401 Unauthorized', res['title'])

    # http head
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:method] = 'HEAD'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)

    # http post
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http'
    opts[:method] = 'POST'
    opts[:post_data] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert_equal('public', res['title'])

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert_equal('401 Unauthorized', res['title'])

    # match
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:match] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert(res['body'].start_with?('<html>'))
    refute_includes(res['body'], 'Response:')
    refute_includes(res['body'], '<textarea>')

    # guess mime
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:guess_mime] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET /#{('a'..'z').to_a.sample(8).join}.ico HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert_equal('HTTP/1.1 401 Unauthorized', res['status_line'])

    # ask password
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # detect redirect
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)
      
    res = ssrf.send_uri('http://127.0.0.1:8088/redirect')
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Location: \/admin$/i)

    # body to URI
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:body_to_uri] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    junk1 = "#{('a'..'z').to_a.sample(8).join}"
    junk2 = "#{('a'..'z').to_a.sample(8).join}"
    data = "data1=#{junk1}&data2=#{junk2}"

    req = "POST /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Content-Length: #{data.length}\n"
    req << "\n"
    req << "#{data}"
    res = ssrf.send_request(req)
    assert valid_ssrf_response?(res)
    assert_includes(res['body'], "data1: #{junk1}")
    assert_includes(res['body'], "data2: #{junk2}")

    req = "POST /submit?query HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Content-Length: #{data.length}\n"
    req << "\n"
    req << "#{data}"
    res = ssrf.send_request(req)
    assert valid_ssrf_response?(res)
    assert_includes(res['body'], "data1: #{junk1}")
    assert_includes(res['body'], "data2: #{junk2}")

    # cookies to URI
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:cookies_to_uri] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    cookie_name = "#{('a'..'z').to_a.sample(8).join}"
    cookie_value = "#{('a'..'z').to_a.sample(8).join}"
    req = "GET /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Cookie: #{cookie_name}=#{cookie_value}\n"
    req << "\n"
    res = ssrf.send_request(req)
    assert valid_ssrf_response?(res)
    assert_includes(res['body'], "#{cookie_name}: #{cookie_value}")

    req = "GET /submit?query HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Cookie: #{cookie_name}=#{cookie_value}\n"
    req << "\n"
    res = ssrf.send_request(req)
    assert valid_ssrf_response?(res)
    assert_includes(res['body'], "#{cookie_name}: #{cookie_value}")

    # ip encoding
    %w[int oct hex dotted_hex].each do |encoding|
      opts = SSRF_DEFAULT_OPTS.dup
      opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
      opts[:ip_encoding] = encoding
      ssrf = SSRFProxy::HTTP.new(opts)
      assert valid_ssrf?(ssrf)

      res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      assert valid_ssrf_response?(res)
      assert_equal('public', res['title'])

      res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      assert valid_ssrf_response?(res)
      assert_equal('401 Unauthorized', res['title'])
    end
  end
end
