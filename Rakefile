#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
$DEBUG = true
$VERBOSE = true
require 'bundler/gem_tasks'
require 'rake/testtask'
require 'rubocop/rake_task'

desc 'Run all tests'
task :all do
  puts 'Running unit tests'
  Rake::Task['unit'].invoke
  puts 'Running integration tests'
  Rake::Task['integration'].invoke
end

task :default => :unit

Rake::TestTask.new(:unit) do |t|
  t.description = 'Run unit tests'
  t.test_files = FileList['test/unit/test_ssrfproxy.rb', 'test/unit/test_http.rb', 'test/unit/test_server.rb']
end

Rake::TestTask.new(:integration) do |t|
  t.description = 'Run integration tests'
  t.test_files = FileList['test/integration/test_http.rb', 'test/integration/test_server.rb']
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

RuboCop::RakeTask.new

############################################################
# integration tests
############################################################
namespace :integration do
  Rake::TestTask.new(:http) do |t|
    t.description = 'Run SSRFProxy::HTTP tests'
    t.test_files = FileList['test/integration/test_http.rb']
  end

  Rake::TestTask.new(:server) do |t|
    t.description = 'Run SSRFProxy::Server tests'
    t.test_files = FileList['test/integration/test_server.rb']
  end
end

############################################################
# rdoc
############################################################
namespace :rdoc do
  require 'rdoc/task'

  desc 'Generate API documentation to doc/rdocs/index.html'
  Rake::RDocTask.new do |rd|
    rd.rdoc_dir = 'doc/rdocs'
    rd.main = 'README.md'
    rd.rdoc_files.include(
      'bin/ssrf-proxy',
      'lib/*\.rb',
      'lib/ssrf_proxy/*\.rb')
    rd.options << '--line-numbers'
    rd.options << '--all'
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
