#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

# ouput
require 'logger'
require 'colorize'

# proxy server socket
require 'socket'

# threading
require 'celluloid/current'
require 'celluloid/io'

# command line
require 'getoptlong'

# http requests
require 'net/http'
require 'socksify/http'

# http parsing
require 'uri'
require 'cgi'
require 'webrick'
require 'stringio'
require 'base64'
require 'stringio'
require 'htmlentities'
require 'mimemagic'

# client request url modification
require 'digest'
require 'base32'

# ip encoding
require 'ipaddress'

#
# SSRF Proxy is a multi-threaded HTTP proxy server
# designed to tunnel client HTTP traffic through HTTP
# servers vulnerable to Server-Side Request Forgery.
#
module SSRFProxy
  String.disable_colorization = false

  require 'ssrf_proxy/version'
  require 'ssrf_proxy/banner'
  require 'ssrf_proxy/logging'
  require 'ssrf_proxy/ssrf'
  require 'ssrf_proxy/ssrf/error'
  require 'ssrf_proxy/http'
  require 'ssrf_proxy/server'
  require 'ssrf_proxy/server/error'

  # Load formatters
  Dir[File.join(File.dirname(__FILE__), 'ssrf_proxy', 'formatters', '**', '*.rb')].each do |file|
    require file
  end
end
