# coding: utf-8
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require 'minitest/autorun'

class SSRFProxyHTTPTest < Minitest::Test

  require 'ssrf_proxy'
  require './test/common/constants.rb'
  require './test/common/http_server.rb'

  #
  # @note start http server
  #
  def setup
    @opts = SSRF_DEFAULT_OPTS.dup
    puts "Starting HTTP server..."
    Thread.new do
      begin
        @http_pid = Process.pid
        HTTPServer.new(
          'interface' => '127.0.0.1',
          'port' => '8088',
          'ssl' => false,
          'verbose' => false,
          'debug' => false)
      rescue => e
        puts "HTTP Server Error: #{e}"
      end
    end
    sleep 1
  end

  #
  # @note stop server
  #
  def teardown
    puts "Shutting down HTTP server..."
    Process.kill('TERM', @http_pid) if @http_pid
  end

  #
  # @note check a SSRFProxy::HTTP object is valid
  #
  def validate(ssrf)
    assert_equal(SSRFProxy::HTTP, ssrf.class)
    assert(ssrf.host)
    assert(ssrf.port)
    assert(ssrf.url)
    return true
  end

  #
  # @note check a HTTP response is valid
  #
  def validate_response(res)
    assert(res)
    assert(res =~ /\AHTTP\//)
    return true
  end

  #
  # @note test send_uri with Net::HTTP SSRF
  #
  def test_send_uri_net_http
    # http get
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # http post
    url = 'http://127.0.0.1:8088/net_http'
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['method'] = 'POST'
    opts['post_data'] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # match
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['match'] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/")
    validate_response(res)
    assert(res !~ /Response:/)
    assert(res !~ /<textarea>/)
    assert(res =~ /^<html>/)

    # guess mime
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_mime'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/#{('a'..'z').to_a.shuffle[0,8].join}.ico")
    validate_response(res)
    assert(res =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /\AHTTP\/\d\.\d 401 Unauthorized/)

    # ask password
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    opts['ask_password'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # ip encoding
    %w(int oct hex dotted_hex).each do |encoding|
      url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
      opts = @opts
      opts['rules'] = 'urlencode'
      opts['ip_encoding'] = encoding
      ssrf = SSRFProxy::HTTP.new(url, opts)
      validate(ssrf)

      res = ssrf.send_uri('http://127.0.0.1:8088/')
      validate_response(res)
      assert(res =~ /<title>public<\/title>/)

      res = ssrf.send_uri('http://127.0.0.1:8088/auth')
      validate_response(res)
      assert(res =~ /<title>401 Unauthorized<\/title>/)
    end
  end

  #
  # @note test send_uri with OpenURI SSRF
  #
  def test_send_uri_openuri
    # http get
    url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /401 Unauthorized/)

    # http post
    url = 'http://127.0.0.1:8088/openuri'
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['method'] = 'POST'
    opts['post_data'] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /401 Unauthorized/)

    # match
    url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['match'] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/")
    validate_response(res)
    assert(res !~ /Response:/)
    assert(res !~ /<textarea>/)
    assert(res =~ /^<html>/)

    # guess mime
    url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_mime'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/#{('a'..'z').to_a.shuffle[0,8].join}.ico")
    validate_response(res)
    assert(res =~ /^Content-Type: image\/x\-icon$/i)

    # ip encoding
    %w(int oct hex dotted_hex).each do |encoding|
      url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
      opts = @opts
      opts['rules'] = 'urlencode'
      opts['ip_encoding'] = encoding
      ssrf = SSRFProxy::HTTP.new(url, opts)
      validate(ssrf)

      res = ssrf.send_uri('http://127.0.0.1:8088/')
      validate_response(res)
      assert(res =~ /<title>public<\/title>/)

      res = ssrf.send_uri('http://127.0.0.1:8088/auth')
      validate_response(res)
      assert(res =~ /401 Unauthorized/)
    end
  end

  #
  # @note test send_uri with cURL SSRF
  #
  def test_send_uri_curl
    # http get
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # http post
    url = 'http://127.0.0.1:8088/curl'
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['method'] = 'POST'
    opts['post_data'] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # match
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['match'] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/")
    validate_response(res)
    assert(res !~ /Response:/)
    assert(res !~ /<textarea>/)
    assert(res =~ /^<html>/)

    # guess mime
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_mime'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/#{('a'..'z').to_a.shuffle[0,8].join}.ico")
    validate_response(res)
    assert(res =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /\AHTTP\/\d\.\d 401 Unauthorized/)

    # ask password
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    opts['ask_password'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # ip encoding
    %w(int oct hex dotted_hex).each do |encoding|
      url = "http://127.0.0.1:8088/curl?url=xxURLxx"
      opts = @opts
      opts['rules'] = 'urlencode'
      opts['ip_encoding'] = encoding
      ssrf = SSRFProxy::HTTP.new(url, opts)
      validate(ssrf)

      res = ssrf.send_uri('http://127.0.0.1:8088/')
      validate_response(res)
      assert(res =~ /<title>public<\/title>/)

      res = ssrf.send_uri('http://127.0.0.1:8088/auth')
      validate_response(res)
      assert(res =~ /<title>401 Unauthorized<\/title>/)
    end
  end

  #
  # @note test send_uri with Typhoeus SSRF
  #
  def test_send_uri_typhoeus
    # http get
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # http post
    url = "http://127.0.0.1:8088/typhoeus"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['method'] = 'POST'
    opts['post_data'] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/')
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # match
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['match'] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/")
    validate_response(res)
    assert(res !~ /Response:/)
    assert(res !~ /<textarea>/)
    assert(res =~ /^<html>/)

    # guess mime
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_mime'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri("http://127.0.0.1:8088/#{('a'..'z').to_a.shuffle[0,8].join}.ico")
    validate_response(res)
    assert(res =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /\AHTTP\/\d\.\d 401 Unauthorized/)

    # ask password
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    opts['ask_password'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_uri('http://127.0.0.1:8088/auth')
    validate_response(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # ip encoding
    %w(int oct hex dotted_hex).each do |encoding|
      url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
      opts = @opts
      opts['rules'] = 'urlencode'
      opts['ip_encoding'] = encoding
      ssrf = SSRFProxy::HTTP.new(url, opts)
      validate(ssrf)

      res = ssrf.send_uri('http://127.0.0.1:8088/')
      validate_response(res)
      assert(res =~ /<title>public<\/title>/)

      res = ssrf.send_uri('http://127.0.0.1:8088/auth')
      validate_response(res)
      assert(res =~ /<title>401 Unauthorized<\/title>/)
    end
  end

  #
  # @note test send_uri with invalid input
  #
  def test_send_uri_invalid
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    begin
      res = ssrf.send_uri(nil)
    rescue SSRFProxy::HTTP::Error::InvalidUriRequest => e
    end
    assert_equal(nil, res)
  end

  #
  # @note test send_request with Net:HTTP SSRF
  #
  def test_send_request_net_http
    # http get
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # http post
    url = 'http://127.0.0.1:8088/net_http'
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['method'] = 'POST'
    opts['post_data'] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # match
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['match'] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res !~ /Response:/)
    assert(res !~ /<textarea>/)
    assert(res =~ /^<html>/)

    # guess mime
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_mime'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /#{('a'..'z').to_a.shuffle[0,8].join}.ico HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /\AHTTP\/\d\.\d 401 Unauthorized/)

    # ask password
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    opts['ask_password'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # body to URI
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['body_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    data = "data=#{junk}"
    req = "POST /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Content-Length: #{data.length}\n"
    req << "\n"
    req << "#{data}"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # cookies to URI
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['cookies_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    req = "GET /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Cookie: data=#{junk}\n"
    req << "\n"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # ip encoding
    %w(int oct hex dotted_hex).each do |encoding|
      url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
      opts = @opts
      opts['rules'] = 'urlencode'
      opts['ip_encoding'] = encoding
      ssrf = SSRFProxy::HTTP.new(url, opts)
      validate(ssrf)

      res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      validate_response(res)
      assert(res =~ /<title>public<\/title>/)

      res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      validate_response(res)
      assert(res =~ /<title>401 Unauthorized<\/title>/)
    end
  end

  #
  # @note test send_request with OpenURI SSRF
  #
  def test_send_request_openuri
    # http get
    url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /401 Unauthorized/)

    # http post
    url = 'http://127.0.0.1:8088/openuri'
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['method'] = 'POST'
    opts['post_data'] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /401 Unauthorized/)

    # match
    url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['match'] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res !~ /Response:/)
    assert(res !~ /<textarea>/)
    assert(res =~ /^<html>/)

    # guess mime
    url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_mime'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /#{('a'..'z').to_a.shuffle[0,8].join}.ico HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /^Content-Type: image\/x\-icon$/i)

    # body to URI
    url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['body_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    data = "data=#{junk}"
    req = "POST /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Content-Length: #{data.length}\n"
    req << "\n"
    req << "#{data}"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # cookies to URI
    url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['cookies_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    req = "GET /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Cookie: data=#{junk}\n"
    req << "\n"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # ip encoding
    %w(int oct hex dotted_hex).each do |encoding|
      url = "http://127.0.0.1:8088/openuri?url=xxURLxx"
      opts = @opts
      opts['rules'] = 'urlencode'
      opts['ip_encoding'] = encoding
      ssrf = SSRFProxy::HTTP.new(url, opts)
      validate(ssrf)

      res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      validate_response(res)
      assert(res =~ /<title>public<\/title>/)

      res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      validate_response(res)
      assert(res =~ /401 Unauthorized/)
    end
  end

  #
  # @note test send_request with cURL SSRF
  #
  def test_send_request_curl
    # http get
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # post
    url = 'http://127.0.0.1:8088/curl'
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['method'] = 'POST'
    opts['post_data'] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # match
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['match'] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res !~ /Response:/)
    assert(res !~ /<textarea>/)
    assert(res =~ /^<html>/)

    # guess mime
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_mime'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /#{('a'..'z').to_a.shuffle[0,8].join}.ico HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /\AHTTP\/\d\.\d 401 Unauthorized/)

    # ask password
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    opts['ask_password'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # body to URI
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['body_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    data = "data=#{junk}"
    req = "POST /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Content-Length: #{data.length}\n"
    req << "\n"
    req << "#{data}"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # cookies to URI
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['cookies_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    req = "GET /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Cookie: data=#{junk}\n"
    req << "\n"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # auth to URI
    url = "http://127.0.0.1:8088/curl?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['auth_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    req = "GET /auth HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Authorization: Basic #{Base64.encode64('admin:test').gsub(/\n/, '')}\n"
    req << "\n"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<title>authentication successful<\/title>/)

    # ip encoding
    %w(int oct hex dotted_hex).each do |encoding|
      url = "http://127.0.0.1:8088/curl?url=xxURLxx"
      opts = @opts
      opts['rules'] = 'urlencode'
      opts['ip_encoding'] = encoding
      ssrf = SSRFProxy::HTTP.new(url, opts)
      validate(ssrf)

      res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      validate_response(res)
      assert(res =~ /<title>public<\/title>/)

      res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      validate_response(res)
      assert(res =~ /<title>401 Unauthorized<\/title>/)
    end
  end

  #
  # @note test send_request with Typhoeus SSRF
  #
  def test_send_request_typhoeus
    # http get
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # http post
    url = 'http://127.0.0.1:8088/typhoeus'
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['method'] = 'POST'
    opts['post_data'] = 'url=xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /<title>401 Unauthorized<\/title>/)

    # match
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['match'] = '<textarea>(.+)</textarea>'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res !~ /Response:/)
    assert(res !~ /<textarea>/)
    assert(res =~ /^<html>/)

    # guess mime
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_mime'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /#{('a'..'z').to_a.shuffle[0,8].join}.ico HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /\AHTTP\/\d\.\d 401 Unauthorized/)

    # ask password
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['guess_status'] = true
    opts['ask_password'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
    validate_response(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # body to URI
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['body_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    data = "data=#{junk}"
    req = "POST /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Content-Length: #{data.length}\n"
    req << "\n"
    req << "#{data}"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # cookies to URI
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['cookies_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    req = "GET /submit HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Cookie: data=#{junk}\n"
    req << "\n"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # auth to URI
    url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    opts['auth_to_uri'] = true
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    req = "GET /auth HTTP/1.1\n"
    req << "Host: 127.0.0.1:8088\n"
    req << "Authorization: Basic #{Base64.encode64('admin:test').gsub(/\n/, '')}\n"
    req << "\n"
    res = ssrf.send_request(req)
    validate_response(res)
    assert(res =~ /<title>authentication successful<\/title>/)

    # ip encoding
    %w(int oct hex dotted_hex).each do |encoding|
      url = "http://127.0.0.1:8088/typhoeus?url=xxURLxx"
      opts = @opts
      opts['rules'] = 'urlencode'
      opts['ip_encoding'] = encoding
      ssrf = SSRFProxy::HTTP.new(url, opts)
      validate(ssrf)

      res = ssrf.send_request("GET / HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      validate_response(res)
      assert(res =~ /<title>public<\/title>/)

      res = ssrf.send_request("GET /auth HTTP/1.1\nHost: 127.0.0.1:8088\n\n")
      validate_response(res)
      assert(res =~ /<title>401 Unauthorized<\/title>/)
    end
  end

  #
  # @note test send_request with invalid input
  #
  def test_send_request_invalid
    url = "http://127.0.0.1:8088/net_http?url=xxURLxx"
    opts = @opts
    opts['rules'] = 'urlencode'
    ssrf = SSRFProxy::HTTP.new(url, opts)
    validate(ssrf)

    urls = [
      'http://', 'ftp://', 'smb://', '://z', '://z:80',
      [], [[[]]], {}, {{}=>{}}, '', nil, 0x00, false, true,
      '://127.0.0.1/file.ext?query1=a&query2=b'
    ]
    urls.each do |url|
      res = ssrf.send_request("GET #{url} HTTP/1.0\n\n")
      validate_response(res)
      assert(res =~ / 501 Error/)
    end
  end
end
