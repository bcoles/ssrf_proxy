#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './lib/ssrf_proxy/version'

Gem::Specification.new do |spec|
  spec.name          = 'ssrf_proxy'
  spec.version       = SSRFProxy::VERSION
  spec.date          = '2017-12-22'
  spec.authors       = ['Brendan Coles']
  spec.email         = ['bcoles@gmail.com']

  spec.summary       = 'SSRF Proxy facilitates tunneling HTTP ' \
                       'communications through servers vulnerable to SSRF.'
  spec.description   = 'SSRF Proxy is a multi-threaded HTTP proxy server ' \
                       'designed to tunnel client HTTP traffic through HTTP ' \
                       'servers vulnerable to Server-Side Request Forgery.'
  spec.homepage      = 'https://github.com/bcoles/ssrf_proxy'
  spec.license       = 'MIT'

  spec.files         = Dir.glob('*.md') +
                       Dir.glob('lib/**/*') +
                       Dir.glob('bin/**/*')
  spec.bindir        = 'bin'
  spec.executables   = ['ssrf-proxy']
  spec.require_paths = ['lib']

  spec.has_rdoc = true
  spec.extra_rdoc_files = %w{README.md LICENSE.md}
  spec.rdoc_options << '--title' << 'SSRF Proxy' <<
                       '--main'  << 'README.md' <<
                       '--line-numbers'

  spec.required_ruby_version = '>= 2.2.2'
  spec.add_development_dependency 'bundler', '~> 1.0'
  spec.add_development_dependency 'coveralls', '~> 0.8.21'
  spec.add_development_dependency 'minitest', '~> 5.0'
  spec.add_development_dependency 'minitest-reporters', '~> 1.1'
  spec.add_development_dependency 'rake', '~> 12.0'
  spec.add_development_dependency 'rdoc', '~> 6.0'
  spec.add_development_dependency 'rubocop', '~> 0.52'
  spec.add_development_dependency 'simplecov', '~> 0.14'
  spec.add_development_dependency 'terminal-table', '~> 1.6'
  spec.add_development_dependency 'typhoeus', '~> 1.3'
  spec.add_development_dependency 'yard', '~> 0.9'

  spec.add_dependency 'base32', '~> 0.3'
  spec.add_dependency 'celluloid', '~> 0.17', '>= 0.17.3'
  spec.add_dependency 'celluloid-io', '~> 0.17', '>= 0.17.3'
  spec.add_dependency 'colorize', '~> 0.8'
  spec.add_dependency 'htmlentities', '~> 4.3'
  spec.add_dependency 'ipaddress', '~> 0.8'
  spec.add_dependency 'logger', '~> 1.2'
  spec.add_dependency 'mimemagic', '~> 0.3'
  spec.add_dependency 'socksify', '~> 1.7'
  spec.add_dependency 'webrick', '~> 1.3', '>= 1.3.0'
end
