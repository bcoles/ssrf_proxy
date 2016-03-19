#
# Copyright (c) 2015 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require 'minitest/autorun'

class SSRFProxyServerTest < Minitest::Test

  require 'ssrf_proxy'
  require "./test/common/constants.rb"
  require "./test/common/http_server.rb"

  #
  # @note start test HTTP server and SSRF Proxy
  #
  def setup
    puts "Starting SSRF Proxy..."
    @ssrf_proxy = fork do
      cmd = ['ssrf-proxy',
       '-u', 'http://127.0.0.1:8088/curl?url=xxURLxx',
       '--interface', '127.0.0.1',
       '--port', '8081',
       '--rules', 'urlencode',
       '--guess-mime',
       '--guess-status',
       '--ask-password',
       '--forward-cookies',
       '--body-to-uri',
       '--auth-to-uri',
       '--cookies-to-uri'
      ]
      res = IO.popen(cmd, 'r+').read.to_s
    end
    Process.detach(@ssrf_proxy)
    puts "Starting HTTP server..."
    Thread.new do
      begin
        @http_pid = Process.pid
        HTTPServer.new({
          'interface' => '127.0.0.1',
          'port' => '8088',
          'ssl' => false,
          'verbose' => false,
          'debug' => false })
      rescue => e
        puts "HTTP Server Error: #{e}"
      end
    end
    sleep 3
  end

  #
  # @note stop servers
  #
  def teardown
    if @http_pid
      puts "Shutting down HTTP server [pid: #{@http_pid}]"
      Process.kill('TERM', @http_pid)
    end
    if @ssrf_proxy
      puts "Shutting down SSRF Proxy [pid: #{@ssrf_proxy}]"
      begin
        Process.kill('INT', @ssrf_proxy)
      rescue Errno::ESRCH => e
        `killall ssrf-proxy`
      end
    end
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
  # @note test proxy with Net:HTTP
  #
  def test_proxy_net_http
    http = Net::HTTP::Proxy('127.0.0.1', '8081').new('127.0.0.1', '8088')
    http.open_timeout = 10
    http.read_timeout = 10

    # get request
    res = http.request Net::HTTP::Get.new('/', {})
    assert(res)
    assert(res.body =~ /<title>public<\/title>/)

    # post request
    res = http.request Net::HTTP::Post.new('/', {})
    assert(res)
    assert(res.body =~ /<title>public<\/title>/)

    # body to URI
    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    url = "/submit"
    headers = {}
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = Net::HTTP::Post.new(url, headers.to_hash)
    req.body = "data=#{junk}"
    res = http.request req
    assert(res)
    assert(res.body =~ /<p>#{junk}<\/p>/)

    # auth to URI
    url = "/auth"
    headers = {}
    headers['Authorization'] = "Basic #{Base64.encode64('admin:test').gsub(/\n/, '')}"
    res = http.request Net::HTTP::Get.new(url, headers.to_hash)
    assert(res)
    assert(res.body =~ /<title>authentication successful<\/title>/)

    # cookies to URI
    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    url = "/submit"
    headers = {}
    headers['Cookie'] = "data=#{junk}"
    res = http.request Net::HTTP::Get.new(url, headers.to_hash)
    assert(res)
    assert(res.body =~ /<p>#{junk}<\/p>/)

    # ask password
    url = "/auth"
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal('Basic realm="127.0.0.1:8088"', res.header['WWW-Authenticate'])

    # guess mime
    url = "/#{('a'..'z').to_a.shuffle[0,8].join}.ico"
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal('image/x-icon', res.header['Content-Type'])

    # guess status
    url = "/auth"
    res = http.request Net::HTTP::Get.new(url, {})
    assert(res)
    assert_equal(401, res.code.to_i)
  end

  #
  # @note test proxy with curl
  #
  def test_proxy_curl

    # get request
    cmd = ['curl', '-isk',
      '-X', 'GET',
      '--proxy', "127.0.0.1:8081",
      "http://127.0.0.1:8088/" ]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    # post request
    cmd = ['curl', '-isk',
      '-X', 'POST',
      '--proxy', "127.0.0.1:8081",
      "http://127.0.0.1:8088/" ]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /<title>public<\/title>/)

    # body to URI
    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    cmd = ['curl', '-isk',
      '-X', 'POST',
      '-d', "data=#{junk}",
      '--proxy', "127.0.0.1:8081",
      "http://127.0.0.1:8088/submit" ]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # auth to URI
    cmd = ['curl', '-isk',
      '--proxy', "127.0.0.1:8081",
      '-u', 'admin:test',
      "http://127.0.0.1:8088/auth" ]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /<title>authentication successful<\/title>/)

    # cookies to URI
    junk = "#{('a'..'z').to_a.shuffle[0,8].join}"
    cmd = ['curl', '-isk',
      '--cookie', "data=#{junk}",
      '--proxy', "127.0.0.1:8081",
      "http://127.0.0.1:8088/submit" ]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /<p>#{junk}<\/p>/)

    # ask password
    cmd = ['curl', '-isk',
      '--proxy', "127.0.0.1:8081",
      "http://127.0.0.1:8088/auth" ]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /^WWW-Authenticate: Basic realm="127\.0\.0\.1:8088"$/i)

    # guess mime
    cmd = ['curl', '-isk',
      '--proxy', "127.0.0.1:8081",
      "http://127.0.0.1:8088/#{('a'..'z').to_a.shuffle[0,8].join}.ico" ]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /^Content-Type: image\/x\-icon$/i)

    # guess status
    cmd = ['curl', '-isk',
      '--proxy', "127.0.0.1:8081",
      "http://127.0.0.1:8088/auth" ]
    res = IO.popen(cmd, 'r+').read.to_s
    validate_response(res)
    assert(res =~ /\AHTTP\/\d\.\d 401 Unauthorized/)
  end

end

