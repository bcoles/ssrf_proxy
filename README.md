```
               ___                         
   ___ ___ ___|  _|    ___ ___ ___ _ _ _ _ 
  |_ -|_ -|  _|  _|   | . |  _| . |_'_| | |
  |___|___|_| |_|     |  _|_| |___|_,_|_  |
                      |_|             |___|

               SSRF Proxy v0.0.1
    https://github.com/bcoles/ssrf_proxy
```

# SSRF Proxy

## Description

SSRF Proxy is a multi-threaded HTTP proxy server designed to
tunnel client HTTP traffic through HTTP servers vulnerable
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

Refer to the wiki for more information:
https://github.com/bcoles/ssrf_proxy/wiki


## Requirements

Ruby

Ruby Gems:
- celluloid-io
- webrick
- logger
- colorize
- ipaddress


## Installation

```
$ rake install
```

## Usage (command line)

```
$ ssrf-proxy -h

_______________________________________________
                ___                            
    ___ ___ ___|  _|    ___ ___ ___ _ _ _ _    
   |_ -|_ -|  _|  _|   | . |  _| . |_'_| | |   
   |___|___|_| |_|     |  _|_| |___|_,_|_  |   
                       |_|             |___|   

                SSRF Proxy v0.0.1
      https://github.com/bcoles/ssrf_proxy

_______________________________________________

Usage:   ssrf-proxy [options] -u <SSRF URL>
Example: ssrf-proxy -u http://target/?url=xxURLxx
Options:

   -h, --help             Help
   -v, --verbose          Verbose output
   -d, --debug            Debugging output

  Server options:
   -p, --port=PORT        Listen port (Default: 8081)
       --interface=IP     Listen interface (Default: 127.0.0.1)
       --proxy=PROXY      Upstream HTTP proxy

  SSRF request options:
   -u, --url=URL          SSRF URL with 'xxURLxx' placeholder
       --method=METHOD    HTTP method (GET/POST/HEAD) (Default: GET)
       --post-data=DATA   HTTP post data
       --cookie=COOKIE    HTTP cookies (seperated by ';')
       --user-agent=AGENT HTTP user-agent (Default: Mozilla/5.0)
       --timeout=SECONDS  Connection timeout in seconds (Default: 10)
       --ip-encoding=MODE Encode IP address for blacklist evasion.
                          (Modes: int, ipv6, oct, hex) (Default: none)
       --rules=RULES      Rules for parsing client request for xxURLxx
                          (seperated by ',') (Default: none)

  HTTP response modification:
       --match=REGEX      Regex to match response body content.
                          (Default: \A(.+)\z)
       --strip=HEADERS    Headers to remove from the response.
                          (seperated by ',') (Default: none)
       --guess-status     Replaces response status code and message
                          headers (determined by common strings in the
                          response body, such as 404 Not Found.)
       --guess-mime       Replaces response content-type header with the
                          appropriate mime type (determined by the file
                          extension of the requested resource.)

  Client request modification:
       --forward-cookies  Forward client HTTP cookies through proxy to
                          SSRF server.
       --body-to-uri      Convert POST parameters to GET parameters.
       --auth-to-uri      Move HTTP basic authentication credentials
                          to URI. (Example: http://[user:pass]@host/)

```


## Usage (ruby)

First, create a new SSRFProxy::HTTP object:

```
  # SSRF URL with 'xxURLxx' placeholder
  url = 'http://example.local/index.php?url=xxURLxx'
  # options
  opts = {
    'proxy'          => "",
    'method'         => "GET",
    'post_data'      => "",
    'rules'          => "",
    'ip_encoding'    => "",
    'match'          => "\\A(.+)\\z",
    'strip'          => "",
    'guess_mime'     => false,
    'guess_status'   => false,
    'forward_cookies'=> false,
    'post_to_uri'    => false,
    'auth_to_uri'    => false,
    'cookie'         => "",
    'timeout'        => 10,
    'user_agent'     => "Mozilla/5.0"
  }
  # create SSRFProxy::HTTP object
  ssrf = SSRFProxy::HTTP.new(url, opts)
  # set log level
  ssrf.logger.level = Logger::DEBUG
```

Then send HTTP requests via the SSRF:

```
  # fetch http://127.0.0.1/ via SSRF by String
  uri = 'http://127.0.0.1/'
  ssrf.send_uri(uri)


  # fetch http://127.0.0.1/ via SSRF by URI
  uri = URI::parse('http://127.0.0.1/')
  ssrf.send_uri(uri)


  # fetch http://127.0.0.1/ via SSRF using a raw HTTP request
  http = "GET http://127.0.0.1/ HTTP/1.1\n\n"
  ssrf.send_request(http)
```

