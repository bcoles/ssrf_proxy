# SSRF Proxy

<a href="https://github.com/bcoles/ssrf_proxy" target="_blank">
  <img alt="Version 0.0.4" src="https://img.shields.io/badge/version-0.0.4-brightgreen.svg"/>
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
  <img alt="MIT License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg"/>
</a>


**SSRF Proxy** is a multi-threaded HTTP proxy server designed
to tunnel client HTTP traffic through HTTP servers vulnerable
to Server-Side Request Forgery (SSRF).

Once configured, SSRF Proxy attempts to format client HTTP
requests appropriately for the vulnerable server. Likewise,
the server's response is parsed and formatted for the client.

By correctly formatting the client request and stripping
unwanted junk from the response it is possible to use
SSRF Proxy as a HTTP proxy for web browsers, proxychains,
and scanning tools such as sqlmap, nmap, dirb and nikto.

SSRF Proxy also assists with leveraging blind SSRF
vulnerabilities to perform time-based attacks, such
as blind time-based SQL injection with sqlmap.

<table>
  <tr>
    <th>Version</th>
    <td>
      <a href="https://github.com/bcoles/ssrf_proxy" target="_blank">
        <img alt="Version 0.0.4" src="https://img.shields.io/badge/version-0.0.4-brightgreen.svg"/>
      </a>
    </td>
  </tr>
  <tr>
    <th>Github</th>
    <td>
      <a href="https://github.com/bcoles/ssrf_proxy">https://github.com/bcoles/ssrf_proxy</a>
    </td>
  </tr>
  <tr>
    <th>Wiki</th>
    <td>
      <a href="https://github.com/bcoles/ssrf_proxy/wiki">https://github.com/bcoles/ssrf_proxy/wiki</a>
    </td>
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
    <td>2015-2017 Brendan Coles</td>
  </tr>
  <tr>
    <th>License</th>
    <td>
      <a href="https://github.com/bcoles/ssrf_proxy/blob/master/LICENSE.md" target="_blank">
        <img alt="MIT License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg"/>
      </a>
    </td>
  </tr>
</table>


## Requirements

Ruby 2.2.2 or newer.

Ruby Gems:

- celluloid-io
- webrick
- logger
- colorize
- ipaddress
- base32
- htmlentities
- socksify
- mimemagic

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
       --version          Display version

  Output options:
   -v, --verbose          Verbose output
   -d, --debug            Debugging output
       --no-color         Disable colored output

  Server options:
   -p, --port=PORT        Listen port (Default: 8081)
       --interface=IP     Listen interface (Default: 127.0.0.1)

  SSRF request options:
   -u, --url=URL          Target URL vulnerable to SSRF.
   -f, --file=FILE        Load HTTP request from a file.
       --placeholder=STR  Placeholder indicating SSRF insertion point.
                          (Default: xxURLxx)
       --method=METHOD    HTTP method (GET/HEAD/DELETE/POST/PUT/OPTIONS)
                          (Default: GET)
       --post-data=DATA   HTTP post data
       --cookie=COOKIE    HTTP cookies (separated by ';')
       --user=USER[:PASS] HTTP basic authentication credentials.
       --user-agent=AGENT HTTP user-agent (Default: none)
       --rules=RULES      Rules for parsing client request
                          (separated by ',') (Default: none)
       --no-urlencode     Do not URL encode client request

  SSRF connection options:
       --ssl              Connect using SSL/TLS.
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
       --sniff-mime       Replaces response content-type header with the
                          appropriate mime type (determined by magic bytes
                          in the response body.)
       --timeout-ok       Replaces timeout HTTP status code 504 with 200.
       --detect-headers   Replaces response headers if response headers
                          are identified in the response body.
       --fail-no-content  Return HTTP status 502 if the response body
                          is empty.
       --cors             Adds a 'Access-Control-Allow-Origin: *' header.

  Client request modification:
       --forward-method   Forward client request method.
       --forward-headers  Forward all client request headers.
       --forward-body     Forward client request body.
       --forward-cookies  Forward client request cookies.
       --cookies-to-uri   Add client request cookies to URI query string.
       --body-to-uri      Add client request body to URI query string.
       --auth-to-uri      Use client request basic authentication
                          credentials in request URI.
       --ip-encoding=MODE Encode client request host IP address.
                          (Modes: int, ipv6, oct, hex, dotted_hex)
       --cache-buster     Append a random value to the client request
                          query string.

```


## Usage (ruby)

Load the ```ssrf_proxy``` library:

```ruby
  require 'ssrf_proxy'
```

Initialize the `SSRFProxy::HTTP` object:

```ruby
  # Initialize with a URL containing 'xxURLxx' placeholder
  ssrf = SSRFProxy::HTTP.new(url: 'http://example.local/?url=xxURLxx')

  # Or, provide the placeholder elsewhere in the request
  ssrf = SSRFProxy::HTTP.new(url: 'http://example.local/', method: 'POST', post_data: 'xxURLxx')

  # Alternatively, the object can be initialized
  # with a file containing a raw HTTP request:
  ssrf = SSRFProxy::HTTP.new(file: 'ssrf.txt')

  # Or, initialized with a StringIO object containing a raw HTTP request:
  http = StringIO.new("GET http://example.local/?url=xxURLxx HTTP/1.1\n\n")
  ssrf = SSRFProxy::HTTP.new(file: http)
```

Refer to the documentation for additional configuration options.

Once initialized, the `SSRFProxy::HTTP` object can be used to send HTTP
requests via the SSRF using the ```send_uri``` and ```send_request``` methods.

```ruby
  # GET via SSRF
  ssrf.send_uri('http://127.0.0.1/')

  # POST via SSRF
  ssrf.send_uri('http://127.0.0.1/', method: 'POST', headers: {}, body: '')

  # GET via SSRF (using a raw HTTP request)
  ssrf.send_request("GET http://127.0.0.1/ HTTP/1.1\n\n")
```

Refer to the documentation for additional request options.


## Documentation

Refer to the wiki for more information and example usage:
https://github.com/bcoles/ssrf_proxy/wiki

Refer to RubyDoc for code documentation:
http://www.rubydoc.info/github/bcoles/ssrf_proxy

