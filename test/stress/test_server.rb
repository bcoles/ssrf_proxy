#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require 'minitest/autorun'
require 'terminal-table'

class TestStressSSRFProxyServer < Minitest::Test
  require 'ssrf_proxy'
  require './test/common/constants.rb'
  require './test/common/http_server.rb'

  #
  # @note start test HTTP server
  #
  puts 'Starting HTTP server...'
  Thread.new do
    begin
      HTTPServer.new(
        'interface' => '127.0.0.1',
        'port' => '8088',
        'ssl' => false,
        'verbose' => false,
        'debug' => false
      )
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
    else
      skip 'Could not find ApacheBench executable. Skipping stress tests...'
    end

    puts 'Starting SSRF Proxy server...'

    # setup ssrf
    opts = SSRF_DEFAULT_OPTS.dup
    opts[:url] = 'http://127.0.0.1:8088/curl?url=xxURLxx'
    opts[:guess_mime] = true
    opts[:guess_status] = true
    opts[:forward_cookies] = true
    opts[:body_to_uri] = true
    opts[:auth_to_uri] = true
    opts[:cookies_to_uri] = true
    ssrf = SSRFProxy::HTTP.new(opts)
    ssrf.logger.level = ::Logger::WARN

    # start proxy server
    server_opts = SERVER_DEFAULT_OPTS.dup
    Thread.new do
      begin
        ssrf_proxy = SSRFProxy::Server.new(ssrf, server_opts['interface'], server_opts['port'])
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
  # Run ApacheBench
  #
  def run_ab(requests, concurrency)
    results = []
    cmd = [@ab_path,
          '-n', requests.to_s,
          '-c', concurrency.to_s,
          '-X', '127.0.0.1:8081',
          'http://127.0.0.1:8088/']
    5.times do
      puts "Starting ApacheBench (requests: #{requests}, threads: #{concurrency})..."
      res = IO.popen(cmd, 'r+').read.to_s
      duration = res.scan(/Time taken for tests:\s*([\d\.]+) seconds/).flatten.first
      req_rate = res.scan(/Requests per second:\s*([\d\.]+)/ ).flatten.first
      time_per_request = res.scan(/Time per request:\s*([\d\.]+) \[ms\]/).flatten.first
      xfer_rate = res.scan(/Transfer rate:\s*([\d\.]+) \[Kbytes\/sec\] received/).flatten.first
      results << [requests,
                  concurrency,
                  duration,
                  req_rate,
                  time_per_request,
                  xfer_rate]
    end
    results
  end

  #
  # Stress test with ApacheBench via curl SSRF
  #
  def test_stress
    results = []

    requests = 100
    results.concat(run_ab(requests, 1))
    results.concat(run_ab(requests, 10))
    results.concat(run_ab(requests, 20))

    headings = ['Requests',
                "Concurrent\nRequests",
                "Duration\n(s)",
                "Rate\n(req/s)",
                "Time / Request\n(ms)",
                "Xfer Rate\n(Kbytes/sec)"]
    table = Terminal::Table.new(:headings => headings, :rows => results)

    puts
    puts table
  end
end
