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
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::Match.new(match: '<textarea>(.+)</textarea>')
    ]

    res = ssrf.send_uri("http://127.0.0.1:8088/", response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert(res['body'].start_with?('<html>'))
    refute_includes(res['body'], 'Response:')
    refute_includes(res['body'], '<textarea>')
  end

  #
  # @note test send_uri guess_mime
  # 
  def test_send_uri_guess_mine_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::GuessMime.new
    ]

    res = ssrf.send_uri("http://127.0.0.1:8088/#{('a'..'z').to_a.sample(8).join}.ico", response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Content-Type: image\/x\-icon$/i)
  end

  #
  # @note test send_uri guess_status
  # 
  def test_send_uri_guess_status_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::GuessStatus.new
    ]

    res = ssrf.send_uri('http://127.0.0.1:8088/auth', response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert_equal('HTTP/1.1 401 Unauthorized', res['status_line'])
  end

  #
  # @note test send_uri ask password
  # 
  def test_send_uri_ask_password_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::GuessStatus.new,
      SSRFProxy::Formatter::Response::AddAuthenticateHeader.new
    ]

    res = ssrf.send_uri('http://127.0.0.1:8088/auth', response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)
  end

  #
  # @note test send_uri detect redirect
  # 
  def test_send_uri_detect_redirect_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::GuessStatus.new,
      SSRFProxy::Formatter::Response::AddLocationHeader.new
    ]

    res = ssrf.send_uri('http://127.0.0.1:8088/redirect', response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Location: \/admin$/i)
  end

  #
  # @note test send_request GET method
  #
  def test_send_request_get_net_http
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
  end

  #
  # @note test send_request HEAD method
  #
  def test_send_request_head_net_http
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/net_http?url=xxURLxx'
    opts[:method] = 'HEAD'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
  end

  # 
  # @note test send_request POST method
  #
  def test_send_request_post_net_http
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
  end

  #
  # @note test send_request match
  #
  def test_send_request_match_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::Match.new(match: '<textarea>(.+)</textarea>')
    ]

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n", response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert(res['body'].start_with?('<html>'))
    refute_includes(res['body'], 'Response:')
    refute_includes(res['body'], '<textarea>')
  end

  #
  # @note test send_request guess mime
  # 
  def test_send_request_guess_mime_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::GuessMime.new
    ]

    res = ssrf.send_request("GET /#{('a'..'z').to_a.sample(8).join}.ico HTTP/1.1\nHost: 127.0.0.1:8088\n\n", response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Content-Type: image\/x\-icon$/i)
  end

  #
  # @note test send_request guess status
  # 
  def test_send_request_guess_status_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::GuessStatus.new
    ]

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n", response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert_equal('HTTP/1.1 401 Unauthorized', res['status_line'])
  end

  #
  # @note test send_request add authenticate header
  # 
  def test_send_request_add_authenticate_header_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::GuessStatus.new,
      SSRFProxy::Formatter::Response::AddAuthenticateHeader.new
    ]

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n", response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)
  end

  #
  # @note test send_request add location header
  # 
  def test_send_request_add_location_header_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)
   
    response_formatters = [
      SSRFProxy::Formatter::Response::GuessStatus.new,
      SSRFProxy::Formatter::Response::AddLocationHeader.new
    ]
   
    res = ssrf.send_request("GET /redirect HTTP/1.1\nHost: 127.0.0.1:8088\n\n", response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ %r{^Location: /admin$}i)
  end

  #
  # @note test send_request body to URI
  # 
  def test_send_request_body_to_uri_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    placeholder_formatters = [
      SSRFProxy::Formatter::Placeholder::AddBodyToURI.new
    ]

    junk1 = "#{('a'..'z').to_a.sample(8).join}"
    junk2 = "#{('a'..'z').to_a.sample(8).join}"
    data = "data1=#{junk1}&data2=#{junk2}"

    req = "POST /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Content-Length: #{data.length}\n"
    req << "\n"
    req << "#{data}"
    res = ssrf.send_request(req, placeholder_formatters: placeholder_formatters)
    assert valid_ssrf_response?(res)
    assert_includes(res['body'], "data1: #{junk1}")
    assert_includes(res['body'], "data2: #{junk2}")

    req = "POST /submit?query HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Content-Length: #{data.length}\n"
    req << "\n"
    req << "#{data}"
    res = ssrf.send_request(req, placeholder_formatters: placeholder_formatters)
    assert valid_ssrf_response?(res)
    assert_includes(res['body'], "data1: #{junk1}")
    assert_includes(res['body'], "data2: #{junk2}")
  end

  #
  # @note test send_request cookies to URI
  # 
  def test_send_request_cookies_to_uri_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    placeholder_formatters = [
      SSRFProxy::Formatter::Placeholder::AddCookiesToURI.new
    ]

    cookie_name = "#{('a'..'z').to_a.sample(8).join}"
    cookie_value = "#{('a'..'z').to_a.sample(8).join}"

    req = "GET /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Cookie: #{cookie_name}=#{cookie_value}\n"
    req << "\n"
    res = ssrf.send_request(req, placeholder_formatters: placeholder_formatters)
    assert valid_ssrf_response?(res)
    assert_includes(res['body'], "#{cookie_name}: #{cookie_value}")

    req = "GET /submit?query HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Cookie: #{cookie_name}=#{cookie_value}\n"
    req << "\n"
    res = ssrf.send_request(req, placeholder_formatters: placeholder_formatters)
    assert valid_ssrf_response?(res)
    assert_includes(res['body'], "#{cookie_name}: #{cookie_value}")
  end

  #
  # @note test send_request auth to URI
  # 
  def test_send_request_auth_to_uri_net_http
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8088/net_http?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    placeholder_formatters = [
      SSRFProxy::Formatter::Placeholder::AddAuthToURI.new
    ]

    # auth to URI - malformed
    req = "GET /auth HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Authorization: Basic NOTABASE64STRING\n"
    req << "\n"
    res = ssrf.send_request(req, placeholder_formatters: placeholder_formatters)
    assert valid_ssrf_response?(res)
    assert_equal('401 Unauthorized', res['title'])
  end
end
