#!/usr/bin/env ruby
#
# Copyright (c) 2015-2016 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

SSRF_DEFAULT_OPTS = {
  'proxy'           => '',
  'method'          => 'GET',
  'post_data'       => '',
  'rules'           => '',
  'ip_encoding'     => '',
  'match'           => '\\A(.+)\\z',
  'strip'           => '',
  'guess_mime'      => false,
  'guess_status'    => false,
  'ask_password'    => false,
  'forward_cookies' => false,
  'body_to_uri'     => false,
  'auth_to_uri'     => false,
  'cookies_to_uri'  => false,
  'cookie'          => '',
  'timeout'         => 10,
  'user_agent'      => 'Mozilla/5.0',
  'insecure'        => false
}.freeze

SERVER_DEFAULT_OPTS = {
  'interface' => '127.0.0.1',
  'port' => 8081
}.freeze
