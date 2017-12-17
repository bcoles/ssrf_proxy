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
  rules:           nil,
  no_urlencode:    false,
  ip_encoding:     nil,
  match:           '\A(.*)\z',
  strip:           nil,
  decode_html:     false,
  guess_mime:      false,
  sniff_mime:      false,
  guess_status:    false,
  forward_method:  false,
  forward_headers: false,
  forward_body:    false,
  forward_cookies: false,
  body_to_uri:     false,
  auth_to_uri:     false,
  cookies_to_uri:  false,
  cache_buster:    false,
  cookie:          nil,
  timeout:         10,
  user_agent:      nil,
  insecure:        false
}.freeze

SERVER_DEFAULT_OPTS = {
  'interface' => '127.0.0.1',
  'port' => 8081
}.freeze
