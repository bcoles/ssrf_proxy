# coding: utf-8
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require "minitest/autorun"

class SSRFProxyServerStressTest < Minitest::Test
  require 'ssrf_proxy'
  require './test/common/constants.rb'
  require './test/common/http_server.rb'

  #
  # @note start test HTTP server
  #
  puts "Starting HTTP server..."
  Thread.new do
    begin
      HTTPServer.new(
        'interface' => '127.0.0.1',
        'port' => '8088',
        'ssl' => false,
        'verbose' => false,
        'debug' => false)
    rescue => e
      puts "Error: Could not start test HTTP server: #{e}"
    end
  end
  puts 'Waiting for HTTP server to start...'
  sleep 1

  #
  # @note start Celluloid before tasks
  #
  def before_setup
    Celluloid.shutdown
    Celluloid.boot
  end

  #
  # @note stress test HTTP server and SSRF Proxy with ApacheBench
  #
  def setup
    # Check for ApacheBench
    if File.file?('/usr/sbin/ab')
      @ab_path = '/usr/sbin/ab'
    elsif File.file?('/usr/bin/ab')
      @ab_path = '/usr/bin/ab'
    end
    assert(@ab_path, 'Could not find ApacheBench executable. Skipping stress tests...')

    puts 'Starting SSRF Proxy server...'
    @server_opts = SERVER_DEFAULT_OPTS.dup
    @ssrf_opts = SSRF_DEFAULT_OPTS.dup

    @ssrf_opts['rules'] = 'urlencode'
    @ssrf_opts['guess_mime'] = true
    @ssrf_opts['guess_status'] = true
    @ssrf_opts['ask_password'] = true
    @ssrf_opts['forward_cookies'] = true
    @ssrf_opts['body_to_uri'] = true
    @ssrf_opts['auth_to_uri'] = true
    @ssrf_opts['cookies_to_uri'] = true

    # setup ssrf
    ssrf = SSRFProxy::HTTP.new('http://127.0.0.1:8088/curl?url=xxURLxx', @ssrf_opts)
    ssrf.logger.level = ::Logger::WARN

    # start proxy server
    Thread.new do
      begin
        ssrf_proxy = SSRFProxy::Server.new(ssrf, @server_opts['interface'], @server_opts['port'])
        ssrf_proxy.logger.level = ::Logger::WARN
        ssrf_proxy.serve
      rescue => e
        puts "Error: Could not start SSRF Proxy server: #{e.message}"
      end
    end
    puts 'Waiting for SSRF Proxy server to start...'
    sleep 1
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
