#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

require 'bundler/gem_tasks'
require 'rake/testtask'
require 'rubocop/rake_task'
require 'yard'

task default: :all
task test: :all

Rake::TestTask.new(:all) do |t|
  t.description = 'Run unit and integration tests'
  t.test_files = FileList['test/unit/test_*.rb', 'test/integration/test_*.rb']
end

Rake::TestTask.new(:unit) do |t|
  t.description = 'Run unit tests'
  t.test_files = FileList['test/unit/**/test_*.rb']
end

Rake::TestTask.new(:integration) do |t|
  t.description = 'Run integration tests'
  t.test_files = FileList['test/integration/**/test_*.rb']
end

namespace :integration do
  Rake::TestTask.new(:http) do |t|
    t.description = 'Run SSRFProxy::HTTP tests'
    t.test_files = FileList['test/integration/test_http.rb']
  end

  Rake::TestTask.new(:server) do |t|
    t.description = 'Run SSRFProxy::Server tests'
    t.test_files = FileList['test/integration/test_server.rb']
  end

  Rake::TestTask.new(:executable) do |t|
    t.description = 'Run bin/ssrf-proxy tests'
    t.test_files = FileList['test/integration/test_executable.rb']
  end
end

Rake::TestTask.new(:stress) do |t|
  t.description = 'Run stress tests'
  t.test_files = FileList['test/stress/test_server.rb']
end

desc 'Generate API documentation to doc/rdocs/index.html'
task :rdoc do
  Rake::Task['rdoc:rerdoc'].invoke
end

desc 'Run bundle-audit'
task :bundle_audit do
  Rake::Task['bundle_audit:update'].invoke
  Rake::Task['bundle_audit:check'].invoke
end

desc 'Open an irb session preloaded with ssrf_proxy'
task :console do
  sh 'irb -rubygems -I lib -r ssrf_proxy.rb'
end

RuboCop::RakeTask.new(:rubocop) do |t|
  t.options = ['--display-cop-names']
end

YARD::Rake::YardocTask.new

############################################################
# rdoc
############################################################
namespace :rdoc do
  require 'rdoc/task'

  desc 'Generate documentation to doc/rdocs/index.html'
  Rake::RDocTask.new do |rd|
    rd.title = 'SSRF Proxy'
    rd.rdoc_dir = 'doc/rdocs'
    rd.main = 'README.md'
    rd.rdoc_files.include(
      'lib/*\.rb',
      'lib/ssrf_proxy/*\.rb'
    )
    rd.options << '--line-numbers'
    rd.options << '--all'
  end
end

############################################################
# fuzz
############################################################
namespace :fuzz do
  Rake::TestTask.new(:hamms) do |t|
    t.description = 'Fuzz proxy with Hamms'
    t.test_files = FileList['test/fuzz/hamms.rb']
  end
end

############################################################
# help2man
############################################################
namespace :help2man do
  desc 'Generate man page to doc/ssrf-proxy.1'
  task :generate do
    if File.file?('/usr/local/bin/help2man')
      path = '/usr/local/bin/help2man'
    elsif File.file?('/usr/bin/help2man')
      path = '/usr/bin/help2man'
    else
      puts '[-] Error: could not find help2man'
      exit 1
    end
    Dir.mkdir('doc') unless File.directory?('doc')
    IO.popen([path, './bin/ssrf-proxy', '--output', 'doc/ssrf-proxy.1'], 'r+').read.to_s
  end

  desc 'Generate and install man page'
  task :install do
    Rake::Task['help2man:generate'].invoke
    IO.popen(['/bin/mv', 'doc/ssrf-proxy.1', '/usr/local/share/man/man1/ssrf-proxy.1'], 'r+').read.to_s
    IO.popen(['/usr/bin/mandb'], 'r+').read.to_s
  end
end

############################################################
# bundle-audit
############################################################
namespace :bundle_audit do
  require 'bundler/audit/cli'

  desc 'Update bundle-audit database'
  task :update do
    Bundler::Audit::CLI.new.update
  end

  desc 'Check gems for vulns using bundle-audit'
  task :check do
    Bundler::Audit::CLI.new.check
  end
end
