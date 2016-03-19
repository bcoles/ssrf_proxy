#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require 'minitest/autorun'

class SSRFProxyServerStressTest < Minitest::Test
  require 'ssrf_proxy'
  require './test/common/constants.rb'
  require './test/common/http_server.rb'

  #
  # @note stress test HTTP server and SSRF Proxy with ApacheBench
  #
  def setup
    # Check for ApacheBench
    if File.file?('/usr/sbin/ab')
      @ab_path = '/usr/sbin/ab'
    elsif File.file?('/usr/bin/ab')
      @ab_path = '/usr/bin/ab'
    else
      puts "Error: Could not find ApacheBench executable"
      exit 1
    end

    # Start proxy
    @opts = SSRF_DEFAULT_OPTS.dup
    puts 'Starting SSRF Proxy...'
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
             '--cookies-to-uri']
      IO.popen(cmd, 'r+').read.to_s
    end
    Process.detach(@ssrf_proxy)

    # Start test HTTP server
    puts 'Starting HTTP server...'
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
    sleep 3
  end

  #
  # @note stop server
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
      rescue Errno::ESRCH
        `killall ssrf-proxy`
      end
    end
  end

  #
  # @note test with ApacheBench
  #
  def test_stress
    results = []

    requests = 1000
    concurrency = 1
    cmd = [@ab_path,
          '-n', requests.to_s,
          '-c', concurrency.to_s,
          '-X', '127.0.0.1:8081',
          'http://127.0.0.1:8088/']
    puts 'Starting ApacheBench...'
    res = IO.popen(cmd, 'r+').read.to_s
    assert(res)
    if res =~ /Time taken for tests:\s*([\d\.]+ seconds)/
      results << "requests: #{requests}, concurrency: #{concurrency}, time: #{$1}"
    end

    requests = 1000
    concurrency = 10
    cmd = [@ab_path,
          '-n', requests.to_s,
          '-c', concurrency.to_s,
          '-X', '127.0.0.1:8081',
          'http://127.0.0.1:8088/']
    puts 'Starting ApacheBench...'
    res = IO.popen(cmd, 'r+').read.to_s
    assert(res)
    if res =~ /Time taken for tests:\s*([\d\.]+ seconds)/
      results << "requests: #{requests}, concurrency: #{concurrency}, time: #{$1}"
    end

    requests = 1000
    concurrency = 20
    cmd = [@ab_path,
          '-n', requests.to_s,
          '-c', concurrency.to_s,
          '-X', '127.0.0.1:8081',
          'http://127.0.0.1:8088/']
    puts 'Starting ApacheBench...'
    res = IO.popen(cmd, 'r+').read.to_s
    assert(res)
    if res =~ /Time taken for tests:\s*([\d\.]+ seconds)/
      results << "requests: #{requests}, concurrency: #{concurrency}, time: #{$1}"
    end

    puts '-' * 80
    puts results.join("\n")
    puts '-' * 80
  end
end
