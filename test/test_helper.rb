# coding: utf-8
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
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
require 'celluloid/current'
require 'ssrf_proxy'
