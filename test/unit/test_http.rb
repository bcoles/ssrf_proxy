#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper'

class TestUnitSSRFProxyHTTP < Minitest::Test
  parallelize_me!

  #
  # @note check a SSRFProxy::HTTP object is valid
  #
  def validate(ssrf)
    assert_equal(SSRFProxy::HTTP, ssrf.class)
    assert(ssrf.url)
    true
  end

  #
  # @note test required arguments 'url' or 'file' are provided
  #
  def test_arg_required
    assert_raises ArgumentError do
      opts = SSRF_DEFAULT_OPTS.dup
      SSRFProxy::HTTP.new(opts)
    end
  end

  #
  # @note test 'url' and 'file' option mutual exclusivity
  #
  def test_arg_mutual_exclusivity
    assert_raises ArgumentError do
      opts = SSRF_DEFAULT_OPTS.dup
      opts[:url] = 'http://127.0.0.1/xxURLxx'
      opts[:file] = ('a'..'z').to_a.sample(8).join.to_s
      SSRFProxy::HTTP.new(opts)
    end
  end

  #
  # @note test creating SSRFProxy::HTTP object with file StringIO
  #
  def test_file_stringio
    opts = SSRF_DEFAULT_OPTS.dup
    http = <<-EOS
GET /curl?url=xxURLxx&xxJUNKxx HTTP/1.1
Host: 127.0.0.1:8088
Cookie: xxJUNKxx=xxJUNKxx; xxJUNKxx=xxJUNKxx
User-Agent: xxJUNKxx
xxJUNKxx: xxJUNKxx

EOS
    junk = ('a'..'z').to_a.sample(8).join.to_s
    http.gsub!('xxJUNKxx', junk)

    opts[:file] = StringIO.new(http)
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)
    assert_equal('http', ssrf.url.scheme)
    assert_equal('127.0.0.1', ssrf.url.host)
    assert_equal(8088, ssrf.url.port)
    assert_equal(junk, ssrf.headers['user-agent'])
    assert_equal("#{junk}=#{junk}; #{junk}=#{junk}", ssrf.headers['cookie'])
    assert_equal(junk, ssrf.headers[junk.downcase])
  end

  #
  # @note test creating SSRFProxy::HTTP object with file path string
  #
  def test_file_path
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:file] = "#{$root_dir}/test/common/http.request"
    ssrf = SSRFProxy::HTTP.new(opts)

    junk = 'xxJUNKxx'

    validate(ssrf)
    assert_equal('http://127.0.0.1:8088/curl?url=xxURLxx&xxJUNKxx', ssrf.url.to_s)
    assert_equal('http', ssrf.url.scheme)
    assert_equal('127.0.0.1', ssrf.url.host)
    assert_equal(8088, ssrf.url.port)
    assert_equal(junk, ssrf.headers['user-agent'])
    assert_equal("#{junk}=#{junk}; #{junk}=#{junk}", ssrf.headers['cookie'])
    assert_equal(junk, ssrf.headers[junk.downcase])
  end

  #
  # @note test creating SSRFProxy::HTTP object with file
  #       with invalid HTTP request
  #
  def test_file_does_not_exist
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:file] = 'doesnotexist'
    assert_raises SSRFProxy::HTTP::Error::InvalidSsrfRequest do
      SSRFProxy::HTTP.new(opts)
    end
  end

  #
  # @note test creating SSRFProxy::HTTP objects with GET method
  #
  def test_url_method_get
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)

    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    opts[:post_data] = 'xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)
  end

  #
  # @note test creating SSRFProxy::HTTP objects with HEAD method
  #
  def test_url_method_head
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    opts[:method] = 'HEAD'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)

    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/'
    opts[:method] = 'HEAD'
    opts[:post_data] = 'xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)
  end

  #
  # @note test creating SSRFProxy::HTTP objects with DELETE method
  #
  def test_url_method_delete
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    opts[:method] = 'DELETE'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)

    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/'
    opts[:method] = 'DELETE'
    opts[:post_data] = 'xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)
  end

  #
  # @note test creating SSRFProxy::HTTP objects with POST method
  #
  def test_url_method_post
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    opts[:method] = 'POST'
    ssrf = SSRFProxy::HTTP.new(opts)

    validate(ssrf)
    opts[:url] = 'http://127.0.0.1/'
    opts[:method] = 'POST'
    opts[:post_data] = 'xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)
  end

  #
  # @note test creating SSRFProxy::HTTP objects with PUT method
  #
  def test_url_method_put
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    opts[:method] = 'PUT'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)

    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/'
    opts[:method] = 'PUT'
    opts[:post_data] = 'xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)
  end

  #
  # @note test creating SSRFProxy::HTTP objects with OPTIONS method
  #
  def test_url_method_options
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    opts[:method] = 'OPTIONS'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)

    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/'
    opts[:method] = 'OPTIONS'
    opts[:post_data] = 'xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    validate(ssrf)
  end

  #
  # @note test creating SSRFProxy::HTTP objects with invalid URL
  #
  def test_url_invalid_url
    urls = [
      'http://', 'ftp://', 'smb://', '://z', '://z:80',
      [], [[[]]], {}, { {} => {} }, "\x00", false, true,
      'xxURLxx://127.0.0.1/file.ext?query1=a&query2=b',
      'ftp://127.0.0.1',
      'ftp://xxURLxx@127.0.0.1/file.ext?query1=a&query2=b',
      'ftp://xxURLxx/file.ext?query1=a&query2=b',
      'ftp://http:xxURLxx@localhost'
    ]
    urls.each do |url|
      ssrf = nil
      begin
        opts = SSRF_DEFAULT_OPTS.dup
        opts[:url] = URI.parse(url)
        assert_raises SSRFProxy::HTTP::Error::InvalidSsrfRequest do
          ssrf = SSRFProxy::HTTP.new(opts)
        end
      rescue URI::InvalidURIError
      end
      assert_nil(ssrf)
    end
  end

  #
  # @note test creating SSRFProxy::HTTP objects with invalid reqest method
  #
  def test_url_invalid_method
    url = 'http://127.0.0.1/xxURLxx'
    assert_raises SSRFProxy::HTTP::Error::InvalidSsrfRequestMethod do
      SSRFProxy::HTTP.new(url: url, method: ('a'..'z').to_a.sample(8).join.to_s)
    end
  end

  #
  # @note test xxURLxx placeholder with GET method
  #
  def test_url_xxurlxx_placeholder_get
    urls = [
      'http://127.0.0.1',
      'http://xxURLxx@127.0.0.1/file.ext?query1=a&query2=b',
      'http://xxURLxx/file.ext?query1=a&query2=b',
      'http://http:xxURLxx@localhost'
    ]
    urls.each do |url|
      opts = SSRF_DEFAULT_OPTS.dup
      opts[:url] = URI.parse(url)
      assert_raises SSRFProxy::HTTP::Error::NoUrlPlaceholder do
        SSRFProxy::HTTP.new(opts)
      end
    end
  end

  #
  # @note test xxURLxx placeholder with POST method
  #
  def test_url_xxurlxx_placeholder_post
    urls = [
      'http://127.0.0.1/'
    ]
    urls.each do |url|
      ssrf = SSRFProxy::HTTP.new(url: url, method: 'POST', post_data: 'xxURLxx')
      validate(ssrf)
    end
  end

  #
  # @note test the xxURLxx placeholder regex parser
  #
  def test_url_xxurlxx_invalid
    (0..255).each do |i|
      buf = [i.to_s(16)].pack('H*')
      begin
        opts = SSRF_DEFAULT_OPTS.dup
        opts[:url] = "http://127.0.0.1/file.ext?query1=a&query2=xx#{buf}URLxx"
        ssrf = SSRFProxy::HTTP.new(opts)
      rescue SSRFProxy::HTTP::Error::NoUrlPlaceholder, SSRFProxy::HTTP::Error::InvalidSsrfRequest
      end
      assert_nil(ssrf) unless buf == 'x'
    end
  end

  #
  # @note test force SSL URL scheme
  #
  def test_url_ssl
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    opts[:ssl] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    assert('https', ssrf.url.scheme)
    assert(80, ssrf.url.port)
  end

  #
  # @note test invalid IP encoding
  #
  def test_ip_encoding_invalid
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    opts[:ip_encoding] = ('a'..'z').to_a.sample(8).join.to_s
    assert_raises SSRFProxy::HTTP::Error::InvalidIpEncoding do
      ssrf = SSRFProxy::HTTP.new(opts)
      validate(ssrf)
    end
  end

  #
  # @note test upstream proxy
  #
  def test_upstream_proxy_invalid
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'

    opts[:proxy] = '://127.0.0.1:8080'
    assert_raises SSRFProxy::HTTP::Error::InvalidUpstreamProxy do
      SSRFProxy::HTTP.new(opts)
    end
    opts[:proxy] = 'http://'
    assert_raises SSRFProxy::HTTP::Error::InvalidUpstreamProxy do
      SSRFProxy::HTTP.new(opts)
    end
    opts[:proxy] = 'http:127.0.0.1:8080'
    assert_raises SSRFProxy::HTTP::Error::InvalidUpstreamProxy do
      SSRFProxy::HTTP.new(opts)
    end
    opts[:proxy] = 'socks://127.0.0.1/'
    assert_raises SSRFProxy::HTTP::Error::InvalidUpstreamProxy do
      SSRFProxy::HTTP.new(opts)
    end
    opts[:proxy] = 'tcp://127.0.0.1/'
    assert_raises SSRFProxy::HTTP::Error::InvalidUpstreamProxy do
      SSRFProxy::HTTP.new(opts)
    end
    opts[:proxy] = 'tcp://127.0.0.1:1234/'
    assert_raises SSRFProxy::HTTP::Error::InvalidUpstreamProxy do
      SSRFProxy::HTTP.new(opts)
    end
  end

  #
  # @note test send_request method with nil request
  #
  def test_send_request_nil
    url = 'http://127.0.0.1/xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url: url)
    validate(ssrf)

    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      ssrf.send_request(nil)
    end
  end

  #
  # @note test send_request method with no host (HTTP/1.0)
  #
  def test_send_request_no_host_http1_0
    url = 'http://127.0.0.1/xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url: url)
    validate(ssrf)

    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      ssrf.send_request("GET / HTTP/1.0\n\n")
    end
  end

  #
  # @note test send_request method with no host (HTTP/1.1)
  #
  def test_send_request_no_host_http1_1
    url = 'http://127.0.0.1/xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url: url)
    validate(ssrf)

    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      ssrf.send_request("GET / HTTP/1.1\n\n")
    end
  end

  #
  # @note test send_request method with no path
  #
  def test_send_request_no_path
    url = 'http://127.0.0.1/xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url: url)
    validate(ssrf)

    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      ssrf.send_request("GET http://127.0.0.1 HTTP/1.1\n\n")
    end
  end

  #
  # @note test send_request method with invalid HTTP verb
  #
  def test_send_request_invalid_method
    url = 'http://127.0.0.1/xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url: url)
    validate(ssrf)

    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      method = ('a'..'z').to_a.sample(8).join.to_s
      ssrf.send_request("#{method} / HTTP/1.1\nHost: 127.0.0.1\n\n")
    end
  end

  #
  # @note test send_request method with a request body but no Content-Length header
  #
  def test_send_request_body_with_no_content_length
    url = 'http://127.0.0.1/xxURLxx'
    ssrf = SSRFProxy::HTTP.new(url: url)
    validate(ssrf)

    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      body = ('a'..'z').to_a.sample(8).join.to_s
      ssrf.send_request("POST / HTTP/1.1\nHost: 127.0.0.1\n\n#{body}")
    end
  end

  #
  # @note test send_uri method with invalid URL
  #
  def test_send_uri_invalid_url
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      ssrf = SSRFProxy::HTTP.new(opts)
      validate(ssrf)
      ssrf.send_uri(nil)
      ssrf.send_uri([])
      ssrf.send_uri({})
      ssrf.send_uri([[]])
      ssrf.send_uri([{}])
    end
  end

  #
  # @note test send_uri method with invalid forwarded HTTP verb
  #
  def test_send_uri_invalid_forwarded_method
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    opts[:forward_method] = true
    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      ssrf = SSRFProxy::HTTP.new(opts)
      validate(ssrf)
      method = ('a'..'z').to_a.sample(8).join.to_s
      ssrf.send_uri('http://127.0.0.1/', method: method)
    end
  end

  #
  # @note test send_uri method with invalid headers
  #
  def test_send_uri_invalid_headers
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      ssrf = SSRFProxy::HTTP.new(opts)
      validate(ssrf)
      junk = ('a'..'z').to_a.sample(8).join.to_s
      headers = { junk => nil }
      ssrf.send_uri('http://127.0.0.1/', headers: headers)
    end
  end

  #
  # @note test send_uri method with upgrade WebSocket header
  #
  def test_send_uri_upgrade_websocket_header
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    assert_raises SSRFProxy::HTTP::Error::InvalidClientRequest do
      ssrf = SSRFProxy::HTTP.new(opts)
      validate(ssrf)
      headers = { 'Upgrade' => 'WebSocket' }
      ssrf.send_uri('http://127.0.0.1/', headers: headers)
    end
  end

  #
  # @note test logger
  #
  def test_logger
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1/xxURLxx'
    ssrf = SSRFProxy::HTTP.new(opts)
    assert_equal('2', ssrf.logger.level.to_s)
    ssrf.logger.level = Logger::INFO
    assert_equal('1', ssrf.logger.level.to_s)
    ssrf.logger.level = Logger::DEBUG
    assert_equal('0', ssrf.logger.level.to_s)
  end

  #
  # @note test accessors
  #
  def test_accessors
    assert_equal(true, SSRFProxy::HTTP.public_method_defined?(:logger))
    assert_equal(true, SSRFProxy::HTTP.public_method_defined?(:url))
    assert_equal(true, SSRFProxy::HTTP.public_method_defined?(:proxy))
    assert_equal(true, SSRFProxy::HTTP.public_method_defined?(:method))
    assert_equal(true, SSRFProxy::HTTP.public_method_defined?(:headers))
    assert_equal(true, SSRFProxy::HTTP.public_method_defined?(:post_data))
  end

  #
  # @note test public methods
  #
  def test_public_methods
    assert_equal(true, SSRFProxy::HTTP.public_method_defined?(:send_uri))
    assert_equal(true, SSRFProxy::HTTP.public_method_defined?(:send_request))
  end

  #
  # @note test private methods
  #
  def test_private_methods
    assert_equal(true, SSRFProxy::HTTP.private_method_defined?(:parse_http_request))
    assert_equal(true, SSRFProxy::HTTP.private_method_defined?(:send_http_request))
    assert_equal(true, SSRFProxy::HTTP.private_method_defined?(:run_rules))
    assert_equal(true, SSRFProxy::HTTP.private_method_defined?(:encode_ip))
    assert_equal(true, SSRFProxy::HTTP.private_method_defined?(:guess_status))
    assert_equal(true, SSRFProxy::HTTP.private_method_defined?(:guess_mime))
    assert_equal(true, SSRFProxy::HTTP.private_method_defined?(:sniff_mime))
  end
end
