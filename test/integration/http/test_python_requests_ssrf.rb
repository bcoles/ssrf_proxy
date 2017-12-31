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
class TestIntegrationSSRFProxyHTTPPythonRequestsSsrf < Minitest::Test
  parallelize_me!

  #
  # @note check for python executable
  #
  def setup
    skip 'Could not find python executable. Skipping Python tests...' unless python_path
  end

  #
  # @note test send_uri GET method
  #
  def test_send_uri_get_python_requests
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8086/requests?url=xxURLxx'
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
  # @note test send_uri match
  #
  def test_send_uri_match_python_requests
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = "http://127.0.0.1:8086/requests?url=xxURLxx"
    ssrf = SSRFProxy::HTTP.new(opts)
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::Match.new(match: '<textarea>(.+)</textarea>')
    ]

    res = ssrf.send_uri("http://127.0.0.1:8088/", response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert(res['body'].start_with?('HTTP'))
    refute_includes(res['body'], 'Response:')
    refute_includes(res['body'], '<textarea>')
  end

  #
  # @note test send_uri guess_mime
  #
  def test_send_uri_guess_mime_python_requests
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8086/requests?url=xxURLxx')
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
  def test_send_uri_guess_status_python_requests
    ssrf = SSRFProxy::HTTP.new(url: 'http://127.0.0.1:8086/requests?url=xxURLxx')
    assert valid_ssrf?(ssrf)

    response_formatters = [
      SSRFProxy::Formatter::Response::GuessStatus.new
    ]

    res = ssrf.send_uri('http://127.0.0.1:8088/auth', response_formatters: response_formatters)
    assert valid_ssrf_response?(res)
    assert_equal('HTTP/1.0 401 Unauthorized', res['status_line'])
  end

  #
  # @note test send_request with Python Requests SSRF
  #
  def test_send_request_get_python_requests
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8086/requests?url=xxURLxx'
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
end
