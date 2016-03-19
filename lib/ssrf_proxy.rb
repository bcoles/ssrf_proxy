#!/usr/bin/env ruby
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy

  # ouput
  require 'logger'
  require 'colorize'

  # proxy server
  require 'socket'

  # threading
  require 'celluloid/current'
  require 'celluloid/io'

  # command line option parsing
  require 'getoptlong'

  # url parsing
  require 'net/http'
  require 'uri'
  require 'cgi'

  # client http request parsing
  require 'webrick'
  require 'stringio'

  # rules
  require 'digest'
  require 'base32'
  require 'base64'

  # ip encoding
  require 'ipaddress'

  # gem libs
  require 'ssrf_proxy/version'
  require 'ssrf_proxy/http'
  require 'ssrf_proxy/server'

end

