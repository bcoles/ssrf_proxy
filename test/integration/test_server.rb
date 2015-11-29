#
# Copyright (c) 2015 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE' for copying permission
#
require 'minitest/autorun'

class SSRFProxyServerTest < MiniTest::Unit::TestCase

  require 'ssrf_proxy'
  require "./test/common/constants.rb"
  require "./test/common/http_server.rb"

  #
  # @note start http server
  #
  def setup
    @ssrf_opts = SSRF_DEFAULT_OPTS
    @server_opts = SERVER_DEFAULT_OPTS
    @opts = @ssrf_opts.merge(@server_opts)
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

end

