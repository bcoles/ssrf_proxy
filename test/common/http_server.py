#!/usr/bin/env python
#
# Python HTTP server
#
# ./server.py <interface> <port>
#
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import urlparse, parse_qs
import time
import requests

class ServerHandler(BaseHTTPRequestHandler):
  def _set_headers(self):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()

  def do_GET(self):
    """Respond to a GET request."""
    self._set_headers()
    path = urlparse(self.path).path
    if path == '/':
      self.wfile.write("<html><head><title>public</title></head><body><p></p></body></html>")
    elif path == '/admin':
      self.wfile.write("<html><head><title>administration</title></head><body><p></p></body></html>")
    elif path == '/requests':
      query = urlparse(self.path).query
      query_components = parse_qs(urlparse(self.path).query)
      self.wfile.write("Response:<br/>\n<textarea>")
      r = requests.get(query_components['url'][0])
      self.wfile.write('HTTP/1.1 ' + str(r.status_code) + '\n')
      self.wfile.write('\n'.join('{}: {}'.format(k, v) for k, v in r.headers.items()))
      self.wfile.write(r.text)
      self.wfile.write("</textarea></html>")
    else:
      self.wfile.write("<html><head><title>Not Found</title></head><body></body></html>")

  def do_HEAD(self):
    """Respond to a HEAD request."""
    self._set_headers()
        
  def do_POST(self):
    """Respond to a POST request."""
    path = urlparse(self.path).path
    if path == '/':
      self.wfile.write("<html><head><title>public</title></head><body><p></p></body></html>")
    elif path == '/submit':
      content_length = int(self.headers['Content-Length'])
      post_data = self.rfile.read(content_length)
      self._set_headers()
      self.wfile.write("<html><head><title>submit</title></head>\n<body>\n<textarea>\n")
      self.wfile.write("Data:" + post_data)
      self.wfile.write("</textarea>\n</body></html>")
    else:
      self.wfile.write("<html><head><title>Not Found</title></head><body></body></html>")

def run(server_class=HTTPServer, handler_class=ServerHandler, interface='127.0.0.1', port=80):
  server_address = ('127.0.0.1', port)
  httpd = server_class(server_address, handler_class)
  print time.asctime(), " -- Server listening on %s:%s" % (interface, port)
  httpd.serve_forever()
  httpd.server_close()

if __name__ == '__main__':
  from sys import argv

  if len(argv) == 3:
    run(interface = argv[1], port = int(argv[2]))
  else:
    run()

