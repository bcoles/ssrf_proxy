#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper.rb'
require './test/integration_test_helper.rb'

#
# @note SSRFProxy::Server integration tests with TCPSocket client
#
class TestIntegrationSSRFProxyServerTCPSocketClient < Minitest::Test

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
  # @note test server with raw TCP socket
  #
  def test_server_tcpsocket_client
    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
    ssrf_opts[:timeout] = 2
    ssrf = SSRFProxy::HTTP.new(ssrf_opts)

    # Configure server options
    server_opts = SERVER_DEFAULT_OPTS.dup
    server_opts[:response_formatters] = [
      SSRFProxy::Formatter::Response::Match.new(match: '<textarea>(.*)</textarea>\z')
    ]

    # Start SSRF Proxy server and open connection
    start_server(ssrf, server_opts)

    # valid HTTP/1.0 request
    client = TCPSocket.new(server_opts[:interface], server_opts[:port])
    client.write("GET http://127.0.0.1:8088/ HTTP/1.0\n\n")
    res = client.readpartial(1024)
    client.close
    assert valid_http_response?(res)
    assert_includes(res, '<title>public</title>')

    # valid HTTP/1.1 request
    client = TCPSocket.new(server_opts[:interface], server_opts[:port])
    client.write("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    res = client.readpartial(1024)
    client.close
    assert valid_http_response?(res)
    assert_includes(res, '<title>public</title>')

    # invalid HTTP/1.0 request
    client = TCPSocket.new(server_opts[:interface], server_opts[:port])
    client.write("GET / HTTP/1.0\n\n")
    res = client.readpartial(1024)
    client.close
    assert valid_http_response?(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # invalid HTTP/1.1 request
    client = TCPSocket.new(server_opts[:interface], server_opts[:port])
    client.write("GET / HTTP/1.1\n\n")
    res = client.readpartial(1024)
    client.close
    assert valid_http_response?(res)
    assert(res =~ %r{\AHTTP/1\.0 502 Bad Gateway})

    # CONNECT tunnel
    client = TCPSocket.new(server_opts[:interface], server_opts[:port])
    client.write("CONNECT 127.0.0.1:8088 HTTP/1.0\n\n")
    res = client.readpartial(1024)
    assert valid_http_response?(res)
    assert(res =~ %r{\AHTTP/1\.0 200 Connection established\r\n\r\n\z})
    client.write("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    res = client.readpartial(1024)
    assert valid_http_response?(res)
    client.close
    assert_includes(res, '<title>public</title>')

    # CONNECT tunnel host unreachable
    client = TCPSocket.new(server_opts[:interface], server_opts[:port])
    client.write("CONNECT 10.99.88.77:80 HTTP/1.0\n\n")
    res = client.readpartial(1024)
    assert valid_http_response?(res)
    client.close
    assert(res =~ %r{\AHTTP/1\.0 504 Timeout})
  end

  #
  # @note test forwarding headers, method, body and cookies with TCP socket
  #
  def test_forwarding_tcpsocket_client
    # Configure SSRF options
    ssrf_opts = SSRF_DEFAULT_OPTS.dup
    ssrf_opts[:url] = 'http://127.0.0.1:8088/curl_proxy'
    ssrf_opts[:method] = 'GET'
    ssrf_opts[:post_data] = 'url=xxURLxx'
    ssrf_opts[:timeout] = 5
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

    # long request body
    client = TCPSocket.new(server_opts[:interface], server_opts[:port])
    junk = 'A' * 10_000
    body = "data=#{junk}"
    client.write("POST /submit HTTP/1.1\nHost: 127.0.0.1:8088\nContent-Length: #{body.length}\n\n#{body}")
    res = client.read
    client.close
    assert valid_http_response?(res)
    assert_includes(res, "<p>data: #{junk}</p>")

    # test forwarding method and headers with compression headers
    client = TCPSocket.new(server_opts[:interface], server_opts[:port])
    client.write("POST / HTTP/1.1\nHost: 127.0.0.1:8088\nContent-Length: 0\nAccept-Encoding: deflate, gzip\n\n")
    res = client.read
    client.close
    assert(res)
    assert_includes(res, '<title>public</title>')
  end
end
