# SSRF Proxy

<a href="https://github.com/bcoles/ssrf_proxy" target="_blank">
  <img src="https://img.shields.io/badge/version-0.0.4.pre-brightgreen.svg"/>
</a>
<a href="https://travis-ci.org/bcoles-ci/ssrf_proxy" target="_blank">
  <img src="https://api.travis-ci.org/bcoles-ci/ssrf_proxy.svg?branch=master"/>
</a>
<a href="https://www.versioneye.com/ruby/ssrf_proxy/" target="_blank">
  <img src="https://img.shields.io/versioneye/d/ruby/ssrf_proxy.svg"/>
</a>
<a href="https://hakiri.io/github/bcoles-ci/ssrf_proxy/master/" target="_blank">
  <img src="https://hakiri.io/github/bcoles-ci/ssrf_proxy/master.svg"/>
</a>
<a href="https://codeclimate.com/github/bcoles/ssrf_proxy" target="_blank">
  <img src="https://codeclimate.com/github/bcoles/ssrf_proxy/badges/gpa.svg"/>
</a>
<a href="https://coveralls.io/github/bcoles-ci/ssrf_proxy?branch=master" target="_blank">
  <img src="https://coveralls.io/repos/github/bcoles-ci/ssrf_proxy/badge.svg?branch=master"/>
</a>
<a href="https://inch-ci.org/github/bcoles/ssrf_proxy" target="_blank">
  <img src="https://inch-ci.org/github/bcoles/ssrf_proxy.svg?branch=master"/>
</a>
<a href="https://github.com/bcoles/ssrf_proxy/blob/master/LICENSE.md" target="_blank">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen.svg"/>
</a>

**SSRF Proxy** is a multi-threaded HTTP proxy server designed
to tunnel client HTTP traffic through HTTP servers vulnerable
to HTTP Server-Side Request Forgery (SSRF).

Once configured, SSRF Proxy attempts to format client HTTP
requests appropriately for the vulnerable server. Likewise,
the server's response is parsed and formatted for the client.

By correctly formatting the client request and stripping
unwanted junk from the response it is possible to use
SSRF Proxy as a HTTP proxy for web browsers and scanning
tools such as sqlmap and nikto.

SSRF Proxy also assists with leveraging blind SSRF
vulnerabilities to perform time-based attacks, such
as blind time-based SQL injection with sqlmap.

<table>
  <tr>
    <th>Version</th>
    <td>0.0.4.pre</td>
  </tr>
  <tr>
    <th>Github</th>
    <td>
      <a href="https://github.com/bcoles/ssrf_proxy">https://github.com/bcoles/ssrf_proxy</a>
    </td>
  </tr>
  <tr>
    <th>Wiki</th>
    <td><a href="https://github.com/bcoles/ssrf_proxy/wiki">https://github.com/bcoles/ssrf_proxy/wiki</a></td>
  </tr>
  <tr>
    <th>Documentation</th>
    <td>
      <a href="http://www.rubydoc.info/github/bcoles/ssrf_proxy" target="_blank">http://www.rubydoc.info/github/bcoles/ssrf_proxy</a>
    </td>
  </tr>
  <tr>
    <th>Author</th>
    <td>Brendan Coles</td>
  </tr>
  <tr>
    <th>Copyright</th>
    <td>2015-2016 Brendan Coles</td>
  </tr>
  <tr>
    <th>License</th>
    <td>MIT - (see <a href="https://github.com/bcoles/ssrf_proxy/blob/master/LICENSE.md">LICENSE.md</a> file)</td>
  </tr>
</table>


## Requirements

Ruby 1.9.3 or newer

Ruby Gems:

- celluloid-io
- webrick
- logger
- colorize
- ipaddress
- base32
- htmlentities
- socksify

## Installation

```
$ gem install ssrf_proxy
```

## Usage (command line)

```
Usage:   ssrf-proxy [options] -u <SSRF URL>
Example: ssrf-proxy -u http://target/?url=xxURLxx
Options:

   -h, --help             Help
   -v, --verbose          Verbose output
   -d, --debug            Debugging output

  Server options:
   -p, --port=PORT        Listen port (Default: 8081)
       --interface=IP     Listen interface (Default: 127.0.0.1)

  SSRF request options:
   -u, --url=URL          SSRF URL with 'xxURLxx' placeholder
       --method=METHOD    HTTP method (GET/HEAD/DELETE/POST/PUT)
                          (Default: GET)
       --post-data=DATA   HTTP post data
       --cookie=COOKIE    HTTP cookies (separated by ';')
       --user-agent=AGENT HTTP user-agent (Default: Mozilla/5.0)
       --rules=RULES      Rules for parsing client request for xxURLxx
                          (separated by ',') (Default: none)

  SSRF connection options:
       --proxy=PROXY      Use a proxy to connect to the server.
                          (Supported proxies: http, https, socks)
       --insecure         Skip server SSL certificate validation.
       --timeout=SECONDS  Connection timeout in seconds (Default: 10)

  HTTP response modification:
       --match=REGEX      Regex to match response body content.
                          (Default: \A(.*)\z)
       --strip=HEADERS    Headers to remove from the response.
                          (separated by ',') (Default: none)
       --decode-html      Decode HTML entities in response body.
       --unescape         Unescape special characters in response body.
       --guess-status     Replaces response status code and message
                          headers (determined by common strings in the
                          response body, such as 404 Not Found.)
       --guess-mime       Replaces response content-type header with the
                          appropriate mime type (determined by the file
                          extension of the requested resource.)
       --timeout-ok       Replaces timeout HTTP status code 504 with 200.
       --ask-password     Prompt for password on authentication failure.
                          Adds a 'WWW-Authenticate' HTTP header to the
                          response if the response code is 401.

  Client request modification:
       --forward-method   Forward client request method.
       --forward-headers  Forward all client request headers.
       --forward-body     Forward client request body.
       --forward-cookies  Forward client request cookies.
       --cookies-to-uri   Add client request cookies to URI query.
       --body-to-uri      Add client request body to URI query.
       --auth-to-uri      Use client request basic authentication
                          credentials in request URI.
       --ip-encoding=MODE Encode client request host IP address.
                          (Modes: int, ipv6, oct, hex, dotted_hex)


```


## Usage (ruby)

First, load the library and create a new SSRFProxy::HTTP object:

```
  # Load SSRF Proxy
  require 'ssrf_proxy'

  # Set the SSRF URL with 'xxURLxx' placeholder
  url = 'http://example.local/index.php?url=xxURLxx'

  # configuration
  opts = {
    'proxy'          => '',
    'method'         => 'GET',
    'post_data'      => '',
    'rules'          => '',
    'ip_encoding'    => '',
    'match'          => "\\A(.*)\\z",
    'strip'          => '',
    'decode_html'    => false,
    'unescape'       => false,
    'guess_mime'     => false,
    'guess_status'   => false,
    'timeout_ok'     => false,
    'ask_password'   => false,
    'forward_method' => false,
    'forward_headers'=> false,
    'forward_body'   => false,
    'forward_cookies'=> false,
    'body_to_uri'    => false,
    'auth_to_uri'    => false,
    'cookies_to_uri' => false,
    'cookie'         => '',
    'timeout'        => 10,
    'user_agent'     => 'Mozilla/5.0',
    'insecure'       => false
  }

  # create SSRFProxy::HTTP object
  ssrf = SSRFProxy::HTTP.new(url, opts)

  # set log level (optional)
  ssrf.logger.level = Logger::DEBUG
```

Then send HTTP requests via the SSRF:

```
  # fetch http://127.0.0.1/ via SSRF
  uri = 'http://127.0.0.1/'
  method = 'GET'
  headers = {}
  body = ''
  ssrf.send_uri(uri, method, headers, body)

  # fetch http://127.0.0.1/ via SSRF using a raw HTTP request
  http = "GET http://127.0.0.1/ HTTP/1.1\n\n"
  ssrf.send_request(http)
```

## Documentation

Refer to the wiki for more information and example usage:
https://github.com/bcoles/ssrf_proxy/wiki

Refer to RubyDoc for code documentation:
http://www.rubydoc.info/github/bcoles/ssrf_proxy
