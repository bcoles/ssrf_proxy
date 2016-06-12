# coding: utf-8
require './lib/ssrf_proxy/version'

Gem::Specification.new do |spec|
  spec.name          = 'ssrf_proxy'
  spec.version       = SSRFProxy::VERSION
  spec.date          = '2015-10-02'
  spec.authors       = ['Brendan Coles']
  spec.email         = ['bcoles@gmail.com']

  spec.summary       = 'SSRF Proxy facilitates tunneling HTTP ' \
                       'communications through servers vulnerable to SSRF.'
  spec.description   = 'SSRF Proxy is a multi-threaded HTTP proxy server ' \
                       'designed to tunnel client HTTP traffic through HTTP ' \
                       'servers vulnerable to HTTP Server-Side Request ' \
                       'Forgery (SSRF).'
  spec.homepage      = 'https://github.com/bcoles/ssrf_proxy'
  spec.license       = 'MIT'

  spec.files         = Dir.glob('*.md') +
                       Dir.glob('lib/**/*') +
                       Dir.glob('bin/**/*')
  spec.bindir        = 'bin'
  spec.test_files    = spec.files.grep(%r{^(test)/})
  spec.executables   = ['ssrf-proxy']
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 1.9.3'
  spec.add_development_dependency 'bundler', '~> 1.12'
  spec.add_development_dependency 'rake', '~> 11.0'
  spec.add_development_dependency 'minitest', '~> 5.0'
  spec.add_development_dependency 'bundler-audit', '~> 0.5'
  spec.add_development_dependency 'typhoeus', '~> 1.0'
  spec.add_development_dependency 'rubocop', '~> 0.40.0'
  spec.add_development_dependency 'rdoc', '~> 4.2'
  spec.add_development_dependency 'yard', '~> 0.8'
  spec.add_development_dependency 'simplecov', '~> 0.11'
  spec.add_development_dependency 'coveralls', '~> 0.8'
  spec.add_development_dependency 'terminal-table', '~> 1.6'

  spec.add_dependency 'logger', '~> 1.2'
  spec.add_dependency 'colorize', '~> 0.7'
  spec.add_dependency 'webrick', '~> 1.3'
  spec.add_dependency 'celluloid', '~> 0.17.3'
  spec.add_dependency 'celluloid-io', '~> 0.17.3'
  spec.add_dependency 'ipaddress', '~> 0.8'
  spec.add_dependency 'base32', '~> 0.3'
  spec.add_dependency 'htmlentities', '~> 4.3'
  spec.add_dependency 'socksify', '~> 1.7'
end
