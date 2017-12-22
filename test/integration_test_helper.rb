#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

require './test/common/http_server.rb'
require './test/common/proxy_server.rb'

#
# @note check for cURL executable
#
def curl_path
  ['/usr/sbin/curl',
   '/usr/bin/curl',
   '/usr/local/bin/curl'].each do |path|
    return path if File.executable?(path)
  end
  nil
end

#
# @note check for PHP executable
#
def php_path
  ['/usr/bin/php'].each do |path|
    return path if File.executable?(path)
  end
  nil
end

#
# @note check for proxychains executable
#
def proxychains_path
  ['/usr/bin/proxychains',
   '/usr/bin/proxychains4'].each do |path|
    return path if File.executable?(path)
  end
  nil
end

#
# @note check if a local TCP port is listening
#
def local_port_open?(port)
  sock = Socket.new(Socket::Constants::AF_INET, Socket::Constants::SOCK_STREAM, 0)
  sock.bind(Socket.pack_sockaddr_in(port, '127.0.0.1'))
  sock.close
  false
rescue Errno::EADDRINUSE
  true
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
# @note check if required TCP ports are available
#
[
  8008, # test HTTP proxy server port
  8081, # SSRF Proxy server port
  8087, # test PHP HTTP server port
  8088, # test HTTP server port
  8089  # test HTTPS server port
].each do |port|
  if local_port_open? port
    puts "Error: Could not set up test environment. Port #{port} is already in use."
    exit 1
  end
end

#
# @note start upstream HTTP proxy server
#
puts 'Starting HTTP proxy test server...'
Thread.new do
  interface = '127.0.0.01'
  port = 8008
  begin
    ProxyServer.new.run(interface, port.to_i)
  rescue => e
    puts "Error: Could not start HTTP proxy server: #{e}"
  end
end

#
# @note start test HTTP server
#
puts 'Starting HTTP test server...'
begin
  Thread.new do
    HTTPServer.new(
      'interface' => '127.0.0.1',
      'port' => '8088',
      'ssl' => false,
      'verbose' => false,
      'debug' => false)
  end
rescue => e
  puts "Error: Could not start test HTTP server: #{e}"
end

#
# @note start test HTTPS server
#
puts 'Starting HTTPS test server...'
begin
  Thread.new do
    HTTPServer.new(
     'interface' => '127.0.0.1',
     'port' => '8089',
     'ssl' => true,
     'verbose' => false,
     'debug' => false)
  end
rescue => e
  puts "Error: Could not start test HTTPS server: #{e}"
end

#
# @note start test PHP HTTP server
#
if php_path
  puts 'Starting PHP HTTP test server...'
  begin
    Thread.new do
      cmd = %w[php -S 127.0.0.1:8087 -t]
      cmd << "#{$root_dir}/test/common/php/"
      @php_http_server = IO.popen(cmd, 'r+')
    end
  rescue => e
    puts "Error: Could not start test PHP HTTP server: #{e}"
  end
end

puts 'Waiting for test servers to start...'
sleep 1

#
# @note kill PHP server
#
Minitest.after_run do
  Process.kill('HUP', @php_http_server.pid) unless @php_http_server.nil?
end
