# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ssrf_proxy/version'

Gem::Specification.new do |spec|
  spec.name          = "ssrf_proxy"
  spec.version       = SSRFProxy::VERSION
  spec.date          = '2015-10-02'
  spec.authors       = ["Brendan Coles"]
  spec.email         = ["bcoles@gmail.com"]

  spec.summary       = %q{SSRF Proxy facilitates tunneling HTTP communications through servers vulnerable to SSRF.}
  spec.description   = %q{SSRF Proxy is a multi-threaded HTTP proxy server designed to tunnel client HTTP traffic through HTTP servers vulnerable to HTTP Server-Side Request Forgery (SSRF).}
  spec.homepage      = "https://github.com/bcoles/ssrf_proxy"
  spec.license       = "MIT"

  spec.files         = ["lib/ssrf_proxy.rb", "lib/ssrf_proxy/http.rb", "lib/ssrf_proxy/server.rb", "lib/ssrf_proxy/version.rb"]
  spec.bindir        = 'bin'
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.executables   = ['ssrf-proxy', 'ssrf-scan']
  spec.require_paths = ['lib']

  spec.required_ruby_version = ">= 1.9.3"
  spec.add_development_dependency "bundler", "~> 1.8"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "bundler-audit"

  spec.add_dependency 'logger'
  spec.add_dependency 'colorize'
  spec.add_dependency 'webrick'
  spec.add_dependency 'celluloid', '~> 0.17.1.2'
  spec.add_dependency 'celluloid-io'
  spec.add_dependency 'ipaddress'
end
