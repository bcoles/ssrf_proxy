#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require 'simplecov'
require 'coveralls'
if ENV['COVERALLS']
  SimpleCov.formatter = Coveralls::SimpleCov::Formatter
end
SimpleCov.start do
  add_filter 'test/common/'
  add_filter 'test/unit/'
  add_filter 'test/integration/'
end

require 'minitest/autorun'
require 'minitest/reporters'
Minitest::Reporters.use! [
  Minitest::Reporters::SpecReporter.new(:color => true),
  Minitest::Reporters::MeanTimeReporter.new
]

require 'ssrf_proxy'

$root_dir = File.join(File.expand_path(File.dirname(File.realpath(__FILE__))), '..')

#
# @note check for cURL executable
#
def curl_path
  ['/usr/sbin/curl', '/usr/bin/curl'].each do |path|
    return path if File.executable?(path)
  end
  nil
end

#
# @note start SSRF Proxy server
#
def start_server(ssrf_opts, server_opts)
  puts 'Starting SSRF Proxy server...'

  # setup ssrf
  ssrf = SSRFProxy::HTTP.new(ssrf_opts)
  ssrf.logger.level = ::Logger::WARN

  # start proxy server
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
# @note start upstream HTTP proxy server
#
def start_proxy_server(interface, port)
  puts 'Starting HTTP proxy server...'
  t = Thread.new do
    begin
      ProxyServer.new.run('127.0.0.1', port.to_i)
    rescue => e
      puts "Error: Could not start HTTP proxy server: #{e}"
    end
  end
  puts 'Waiting for HTTP proxy server to start...'
  sleep 1
  t
end

