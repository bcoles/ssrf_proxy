#
# Copyright (c) 2015 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE' for copying permission
#
require 'minitest/autorun'

class SSRFProxyTest < MiniTest::Unit::TestCase

  require 'ssrf_proxy'

  # configure ssrf
  def setup

    # ssrf defaults
    url = nil
    rules = ''
    ip_encoding = ''
    method = 'GET'
    post_data = ''
    match = "\\A(.+)\\z"
    strip = ''
    guess_mime = false
    guess_status = false
    forward_cookies = false
    post_to_uri = false
    auth_to_uri = false

    # http connection defaults
    cookie = ''
    timeout = 10
    upstream_proxy = nil
    user_agent = 'Mozilla/5.0'

    # logging
    log_level = ::Logger::WARN
 
    # set SSRF options
    @opts = {
      'proxy'          => "#{upstream_proxy}",
      'method'         => "#{method}",
      'post_data'      => "#{post_data}",
      'rules'          => "#{rules}",
      'ip_encoding'    => "#{ip_encoding}",
      'match'          => "#{match}",
      'strip'          => "#{strip}",
      'guess_mime'     => "#{guess_mime}",
      'guess_status'   => "#{guess_status}",
      'forward_cookies'=> "#{forward_cookies}",
      'post_to_uri'    => "#{post_to_uri}",
      'auth_to_uri'    => "#{auth_to_uri}",
      'cookie'         => "#{cookie}",
      'timeout'        => "#{timeout}",
      'user_agent'     => "#{user_agent}" }
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
  # @note test creating SSRFProxy::HTTP objects with valid params
  #
  def test_ssrf_good
    ssrf = SSRFProxy::HTTP.new('http://127.0.0.1/xxURLxx', @opts)
    validate(ssrf)
    assert_equal(SSRFProxy::HTTP, ssrf.class)
    ssrf = SSRFProxy::HTTP.new(URI::parse('http://127.0.0.1/file.ext?query1=a&query2=b&query3=xxURLxx'), @opts)
    validate(ssrf)
    assert_equal(SSRFProxy::HTTP, ssrf.class)
  end
  
  #
  # @note test creating SSRFProxy::HTTP objects with invalid URL
  #
  def test_ssrf_invalid
    urls = [
      'http://', 'ftp://', 'smb://', '://z', '://z:80',
      [], [[[]]], {}, {{}=>{}}, '', nil, 0x00, false, true,
      'xxURLxx://127.0.0.1/file.ext?query1=a&query2=b',
      'ftp://127.0.0.1',
      'ftp://xxURLxx@127.0.0.1/file.ext?query1=a&query2=b',
      'ftp://xxURLxx/file.ext?query1=a&query2=b',
      'ftp://http:xxURLxx@localhost'
  
    ]
    urls.each do |url|
      begin
        ssrf = SSRFProxy::HTTP.new(url, @opts)
      rescue SSRFProxy::HTTP::Error::InvalidSsrfRequest
      end
      assert_equal(nil, ssrf)
      begin
        ssrf = SSRFProxy::HTTP.new(url, {})
      rescue SSRFProxy::HTTP::Error::InvalidSsrfRequest
      end
      assert_equal(nil, ssrf)
      begin
        ssrf = SSRFProxy::HTTP.new(URI::parse(url), @opts)
      rescue SSRFProxy::HTTP::Error::InvalidSsrfRequest, URI::InvalidURIError
      end
      assert_equal(nil, ssrf)
      begin
        ssrf = SSRFProxy::HTTP.new(URI::parse(url), {})
      rescue SSRFProxy::HTTP::Error::InvalidSsrfRequest, URI::InvalidURIError
      end
      assert_equal(nil, ssrf)
    end
  end

  #
  # @note test xxURLxx placeholder with GET method
  #
  def test_xxurlxx_placeholder_get
    urls = [
      'http://127.0.0.1',
      'http://xxURLxx@127.0.0.1/file.ext?query1=a&query2=b',
      'http://xxURLxx/file.ext?query1=a&query2=b',
      'http://http:xxURLxx@localhost'
    ]
    urls.each do |url|
      begin
        ssrf = SSRFProxy::HTTP.new(url, @opts)
      rescue SSRFProxy::HTTP::Error::NoUrlPlaceholder
      end
      assert_equal(nil, ssrf)
      begin
        ssrf = SSRFProxy::HTTP.new(URI::parse(url), @opts)
      rescue SSRFProxy::HTTP::Error::NoUrlPlaceholder
      end
      assert_equal(nil, ssrf)
      begin
        ssrf = SSRFProxy::HTTP.new(url, {})
      rescue SSRFProxy::HTTP::Error::NoUrlPlaceholder
      end
      assert_equal(nil, ssrf)
      begin
        ssrf = SSRFProxy::HTTP.new(URI::parse(url), {})
      rescue SSRFProxy::HTTP::Error::NoUrlPlaceholder
      end
      assert_equal(nil, ssrf)
    end
  end

  #
  # @note test xxURLxx placeholder with POST method
  #
  def test_xxurlxx_placeholder_post
    urls = [
      'http://127.0.0.1',
      'http://xxURLxx@127.0.0.1/file.ext?query1=a&query2=b',
      'http://xxURLxx/file.ext?query1=a&query2=b',
      'http://http:xxURLxx@localhost'
    ]
    urls.each do |url|
      begin
        ssrf = SSRFProxy::HTTP.new(url, {'method' => 'POST', 'post_data' => 'xxURLxx'})
      rescue SSRFProxy::HTTP::Error::NoUrlPlaceholder
      end
      assert_equal(nil, ssrf)
    end
  end

  #
  # @note test the xxURLxx placeholder regex parser
  #
  def test_xxurlxx_regex
    (0..255).each do |i|
      buf = [i.to_s(16)].pack('H*')
      begin
        ssrf = SSRFProxy::HTTP.new("http://127.0.0.1/file.ext?query1=a&query2=xx#{buf}URLxx", @opts)
      rescue SSRFProxy::HTTP::Error::NoUrlPlaceholder, SSRFProxy::HTTP::Error::InvalidSsrfRequest
      end
      assert_equal(nil, ssrf) unless buf == 'x'
    end
  end

  # 
  # @note test options
  #
  def test_options_nil
    url = 'http://127.0.0.1/xxURLxx'
    begin
      ssrf = SSRFProxy::HTTP.new( url, {'proxy' => nil} )
      validate(ssrf)
    rescue SSRFProxy::HTTP::Error::InvalidUpstreamProxy
    end
    begin
      ssrf = SSRFProxy::HTTP.new( url, {'method' => nil} )
      validate(ssrf)
    rescue SSRFProxy::HTTP::Error::InvalidRequestMethod
    end
    begin
      ssrf = SSRFProxy::HTTP.new( url, {'ip_encoding' => nil} )
      validate(ssrf)
    rescue SSRFProxy::HTTP::Error::InvalidIpEncoding
    end
  end

  #
  # @note test send_request method
  #
  def test_send_request_invalid
    url = 'http://127.0.0.1/xxURLxx'
    begin
      ssrf = SSRFProxy::HTTP.new( url )
      validate(ssrf)
      response = ssrf.send_request(nil)
      assert_equal('501 Error', response.scan(/501 Error/).first)
    rescue SSRFProxy::HTTP::Error::InvalidHttpRequest
    end
  end

  #
  # @note test send_uri method
  #
  def test_send_uri_invalid
    url = 'http://127.0.0.1/xxURLxx'
    begin
      ssrf = SSRFProxy::HTTP.new( url )
      validate(ssrf)
      response = ssrf.send_uri(nil)
      assert_equal('501 Error', response.scan(/501 Error/).first)
    rescue SSRFProxy::HTTP::Error::InvalidUriRequest
    end
  end

  #
  # @note test logger
  #
  def test_logger
    ssrf = SSRFProxy::HTTP.new('http://127.0.0.1/xxURLxx', @opts)
    assert_equal('2', ssrf.logger.level.to_s)
    ssrf.logger.level = Logger::INFO
    assert_equal('1', ssrf.logger.level.to_s)
    ssrf.logger.level = Logger::DEBUG
    assert_equal('0', ssrf.logger.level.to_s)
  end

end

