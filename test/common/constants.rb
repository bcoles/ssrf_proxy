#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

SSRF_DEFAULT_OPTS = {
  url:             nil,
  file:            nil,
  proxy:           nil,
  ssl:             false,
  placeholder:     'xxURLxx',
  method:          'GET',
  post_data:       nil,
  cookie:          nil,
  user:            nil,
  timeout:         10,
  user_agent:      nil,
  insecure:        false
}.freeze

SERVER_DEFAULT_OPTS = {
  interface: '127.0.0.1',
  port: 8081,
  placeholder_formatters: [],
  request_formatters: [],
  response_formatters: []
}.freeze
