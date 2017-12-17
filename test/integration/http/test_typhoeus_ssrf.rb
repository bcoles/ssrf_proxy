#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'
require './test/integration_test_helper.rb'

#
# @note SSRFProxy::HTTP integration tests
#
class TestIntegrationSSRFProxyHTTPTyphoeusSsrf < Minitest::Test
  parallelize_me!

  #
  # @note test send_uri with Typhoeus SSRF
  #
  def test_send_uri_typhoeus
    # http get
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
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

    # http head
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:method] = 'HEAD'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    assert valid_ssrf_response?(res)

    # http post
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus'
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

    # match
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:match] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/")
    assert valid_ssrf_response?(res)
    assert(res['body'].start_with?('<html>'))
    refute_includes(res['body'], 'Response:')
    refute_includes(res['body'], '<textarea>')

    # guess mime
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:guess_mime] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/#{('a'..'z').to_a.sample(8).join}.ico")
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    assert valid_ssrf_response?(res)
    assert_equal('HTTP/1.1 401 Unauthorized', res['status_line'])

    # ask password
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # detect redirect
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)
    
    res = ssrf.send_uri('http://127.0.0.1:8088/redirect')
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Location: \/admin$/i)

    # ip encoding
    %w[int oct hex dotted_hex].each do |encoding|
      opts = SSRF_DEFAULT_OPTS.dup
      opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
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
  # @note test send_request with Typhoeus SSRF
  #
  def test_send_request_typhoeus
    # http get
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
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
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:method] = 'HEAD'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)

    # http post
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus'
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
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
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
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:guess_mime] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET /#{('a'..'z').to_a.sample(8).join}.ico HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert_equal('HTTP/1.1 401 Unauthorized', res['status_line'])

    # ask password
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # detect redirect
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:guess_status] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)
      
    res = ssrf.send_uri('http://127.0.0.1:8088/redirect')
    assert valid_ssrf_response?(res)
    assert(res['headers'] =~ /^Location: \/admin$/i)

    # body to URI
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
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
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
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

    # auth to URI
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
    opts[:auth_to_uri] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    req = "GET /auth HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Authorization: Basic #{Base64.encode64('admin user:test password!@#$%^&*()_+-={}|\:";\'<>?,./').delete("\n")}\n"
    req << "\n"
    res = ssrf.send_request(req)
    assert valid_ssrf_response?(res)
    assert_equal('authentication successful', res['title'])

    req = "GET /auth HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Authorization: Basic #{Base64.encode64((0 .. 255).to_a.shuffle.pack('C*')).delete("\n")}\n"
    req << "\n"
    res = ssrf.send_request(req)
    assert valid_ssrf_response?(res)
    assert_equal('401 Unauthorized', res['title'])

    # auth to URI - malformed
    req = "GET /auth HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Authorization: Basic #{"#{('a'..'z').to_a.sample(8).join}"}\n"
    req << "\n"
    res = ssrf.send_request(req)
    assert valid_ssrf_response?(res)
    assert_equal('401 Unauthorized', res['title'])

    # ip encoding
    %w[int oct hex dotted_hex].each do |encoding|
      opts = SSRF_DEFAULT_OPTS.dup
      opts[:url] = 'http://127.0.0.1:8088/typhoeus?url=xxURLxx'
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
