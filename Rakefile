#
# Copyright (c) 2015 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE' for copying permission
#
require 'bundler/gem_tasks'
require 'rake/testtask'

@gem_version = '0.0.3.pre'

desc "Run all tests"
task :all do
  puts 'Running unit tests'
  Rake::Task['unit'].invoke
  puts 'Running integration tests'
  Rake::Task['integration'].invoke
  puts 'Checking ruby gems for known vulnerabilities'
  Rake::Task['bundle_audit'].invoke
  puts 'Generating documentation'
  Rake::Task['rdoc:rerdoc'].invoke
end

desc "Run unit tests"
task :default => :unit
Rake::TestTask.new(:unit) do |t|
  t.test_files = FileList['test/unit/test_http.rb']
end

desc "Run integration tests"
Rake::TestTask.new(:integration) do |t|
  t.test_files = FileList['test/integration/test_http.rb']
  t.test_files = FileList['test/integration/test_server.rb']
end

desc "Run stress tests"
Rake::TestTask.new(:stress) do |t|
  t.test_files = FileList['test/stress/test_server.rb']
end

desc "Generate API documentation to doc/rdocs/index.html"
task :rdoc do
  Rake::Task['rdoc:rerdoc'].invoke
end

desc "Run bundle-audit"
task :bundle_audit do
  Rake::Task['bundle_audit:update'].invoke
  Rake::Task['bundle_audit:check'].invoke
end

desc "Open an irb session preloaded with ssrf_proxy"
task :console do
  sh "irb -rubygems -I lib -r ssrf_proxy.rb"
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
    rd.rdoc_files.include("bin/ssrf-proxy", "bin/ssrf-scan",
      "lib/*\.rb", "lib/ssrf_proxy/*\.rb")
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

