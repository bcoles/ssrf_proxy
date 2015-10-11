#!/usr/bin/env ruby
#
# Copyright (c) 2015 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE' for copying permission
#

require "ssrf_proxy"

module SSRFProxy
#
# @note SSRFProxy::HTTP
#
class HTTP
  attr_accessor = :logger

  # @note output status messages
  def print_status(msg='')
    puts '[*] '.blue + msg
  end

  # @note output progress messages
  def print_good(msg='')
    puts '[+] '.green + msg
  end

  # url parsing
  require 'net/http'
  require 'uri'
  require 'cgi'

  # client http request parsing
  require 'webrick'
  require 'stringio'

  # rules
  require 'digest'
  require 'base64'

  # ip encoding
  require 'ipaddress'

  # @note logger
  def logger
    @logger || ::Logger.new(STDOUT).tap do |log|
      log.progname = 'ssrf-proxy'
      log.level = ::Logger::WARN
      log.datetime_format = '%Y-%m-%d %H:%M:%S '
    end
  end

  #
  # @note SSRFProxy:HTTP errors
  #
  module Error
    # custom errors
    class Error < StandardError; end
    exceptions = %w(
      NoUrlPlaceholder
      InvalidSsrfRequest
      InvalidRequestMethod
      InvalidUpstreamProxy
      InvalidIpEncoding
      InvalidHttpRequest
      InvalidUriRequest )
    exceptions.each { |e| const_set(e, Class.new(Error)) }
  end

  #
  # @note SSRFProxy::HTTP
  #
  # @options
  # - url - String - SSRF URL with 'xxURLxx' placeholder
  # - opts - Hash - SSRF and HTTP connection options:
  #   - 'proxy'          => String
  #   - 'method'         => String
  #   - 'post_data'      => String
  #   - 'rules'          => String
  #   - 'ip_encoding'    => String
  #   - 'match'          => Regex
  #   - 'strip'          => String
  #   - 'guess_status'   => Boolean
  #   - 'guess_mime'     => Boolean
  #   - 'forward_cookies'=> Boolean
  #   - 'post_to_uri'    => Boolean
  #   - 'auth_to_uri'    => Boolean
  #   - 'cookie'         => String
  #   - 'timeout'        => Integer
  #   - 'user_agent'     => String
  #
  def initialize(url='', opts={})
    @logger = ::Logger.new(STDOUT).tap do |log|
      log.progname = 'ssrf-proxy'
      log.level = ::Logger::WARN
      log.datetime_format = '%Y-%m-%d %H:%M:%S '
    end
    begin
      @ssrf_url = URI::parse(url.to_s)
    rescue URI::InvalidURIError
      raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
        "Invalid SSRF request specified."
    end
    if @ssrf_url.scheme.nil? || @ssrf_url.host.nil? || @ssrf_url.port.nil?
      raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
        "Invalid SSRF request specified."
    end
    if @ssrf_url.scheme !~ /\Ahttps?\z/
      raise SSRFProxy::HTTP::Error::InvalidSsrfRequest.new,
        "Invalid SSRF request specified. Scheme must be http(s)."
    end
    if @ssrf_url.request_uri !~ /xxURLxx/ && @post_data.to_s !~ /xxURLxx/ 
      raise SSRFProxy::HTTP::Error::NoUrlPlaceholder.new,
        "You must specify a URL placeholder with 'xxURLxx' in the SSRF request"
    end

    # SSRF options
    @upstream_proxy = nil
    @method = 'GET'
    @post_data = ''
    @ip_encoding = nil
    @rules = []
    @forward_cookies = false
    @post_to_uri = false
    @auth_to_uri = false
    opts.each do |option, value|
      next if value.eql?('')
      case option
      when 'proxy'
        begin
          @upstream_proxy = URI::parse(value)
        rescue URI::InvalidURIError => e
          raise SSRFProxy::HTTP::Error::InvalidUpstreamProxy.new,
            "Invalid upstream HTTP proxy specified."
        end
        if @upstream_proxy.scheme !~ /\Ahttps?\z/
          raise SSRFProxy::HTTP::Error::InvalidUpstreamProxy.new,
            "Invalid upstream HTTP proxy specified."
        end
      when 'method'
        if @method !~ /\A(get|post|head)+?\z/i
          raise SSRFProxy::HTTP::Error::InvalidRequestMethod.new,
            "Invalid SSRF request method specified. Method must be GET/POST/HEAD."
        end
        @method = 'GET'  if value =~ /\Aget\z/i
        @method = 'POST' if value =~ /\Apost\z/i
        @method = 'HEAD' if value =~ /\Ahead\z/i
      when 'post_data'
        @post_data = value.to_s
      when 'ip_encoding'
        if value.to_s !~ /\A[a-z0-9]+\z/i
          raise SSRFProxy::HTTP::Error::InvalidIpEncoding.new,
            "Invalid IP encoding method specified."
        end
        @ip_encoding = value.to_s
      when 'rules'
        @rules = value.to_s.split(/,/)
      when 'forward_cookies'
        @forward_cookies = true if value
      when 'post_to_uri'
        @post_to_uri = true if value
      when 'auth_to_uri'
        @auth_to_uri = true if value
      end
    end

    # HTTP connection options
    @cookie = nil
    @timeout = 10
    @user_agent = 'Mozilla/5.0'
    opts.each do |option, value|
      next if value.eql?('')
      case option
      when 'cookie'
        @cookie = value.to_s
      when 'timeout'
        @timeout = value.to_i
      when 'user_agent'
        @user_agent = value.to_s
      end
    end

    # HTTP response modification options
    @match_regex = "\\A(.+)\\z"
    @strip = []
    @guess_status = false
    @guess_mime = false
    opts.each do |option, value|
      next if value.eql?('')
      case option
      when 'match'
        @match_regex = value.to_s
      when 'strip'
        @strip = value.to_s.split(/,/)
      when 'guess_status'
        @guess_status = true if value
      when 'guess_mime'
        @guess_mime = true if value
      end
    end

  end

  #
  # @note URL accessor
  #
  # @returns - String - SSRF URL
  #
  def url
    @ssrf_url
  end

  #
  # @note Host accessor
  #
  # @returns - String - SSRF host
  #
  def host
    @ssrf_url.host
  end

  #
  # @note Port accessor
  #
  # @returns - String - SSRF port
  #
  def port
    @ssrf_url.port
  end

  #
  # @note Cookie accessor
  #
  # @returns - String - SSRF request cookie
  #
  def cookie
    @cookie
  end

  #
  # @note Upstream proxy accessor
  #
  # @returns - String - Upstream proxy
  #
  def proxy
    @upstream_proxy
  end

  #
  # @note Encode IP address of a given URL
  #
  # @options
  # - url - String - target url
  # - mode - String - encoding (int, ipv6)
  #
  # @returns - String - encoded ip address
  #
  def encode_ip(url, mode)
    return if url.nil?
    new_host = nil
    host = URI::parse(url.to_s.split('?').first).host.to_s
    begin
      ip = IPAddress.parse(host)
    rescue
      logger.warn("Could not parse requested host as IP address: #{host}")
      return
    end
    case mode
    when 'int'
      new_host = url.to_s.gsub!(host, ip.to_u32.to_s).to_s
    when 'ipv6'
      new_host = url.to_s.gsub!(host, ip.to_ipv6.to_s).to_s 
    else
      logger.warn("Invalid IP encoding: #{mode}")
    end
    new_host
  end

  #
  # @note Run a specified URL through SSRF rules
  #
  # @options
  # - url - String - request URL
  # - rules - String - comma seperated list of rules
  #
  # @returns - String - modified request URL
  #
  def run_rules(url, rules)
    str = url.to_s
    return str if rules.nil?
    rules.each do |rule|
      case rule
      when 'noproto'
        str = str.gsub(/^https?:\/\//, '')
      when 'nossl', 'http'
        str = str.gsub(/^https:\/\//, 'http://')
      when 'ssl', 'https'
        str = str.gsub(/^http:\/\//, 'https://')
      when 'base64'
        str = Base64.encode64(str).chomp
      when 'md4'
        str = OpenSSL::Digest::MD4.hexdigest(str)
      when 'md5'
        md5 = Digest::MD5.new
        md5.update str
        str = md5.hexdigest
      when 'sha1'
        str = Digest::SHA1.hexdigest(str)
      when 'reverse'
        str = str.reverse
      when 'urlencode'
        str = CGI.escape(str)
      when 'urldecode'
        str = CGI.unescape(str)
      else
        logger.warn("Unknown rule: #{rule}")
      end
    end
    str
  end

  #
  # @note Format a HTTP request as a URL and request via SSRF
  #
  # @options
  # - request - String - raw HTTP request
  #
  # @returns String - raw HTTP response headers and body 
  #
  def send_request(request)
    if request.to_s =~ /\ACONNECT ([^\s]+) .*$/
      logger.warn("CONNECT tunneling is not supported: #{$1}")
      return "HTTP\/1.1 501 Error\nServer: SSRF Proxy\nContent-Length: 0\n\n"
    end
    opts = {}
    begin
      # append '/' if no path is specified
      request = request.gsub!(/ HTTP\//, '/ HTTP/') if request =~ /\A.*:[0-9]+ HTTP\//
      # change POST to GET if the request body is empty
      if request.to_s =~ /\APOST /
        request = request.gsub!(/\APOST /, 'GET ') if request.split(/\r?\n\r?\n/)[1].nil?
      end 
      # parse request
      req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
      req.parse(StringIO.new(request))
      if req.to_s =~ /^Upgrade: WebSocket/
        logger.warn("WebSocket tunneling is not supported: #{req.host}:#{req.port}")
        return "HTTP\/1.1 501 Error\nServer: SSRF Proxy\nContent-Length: 0\n\n"
      end
      uri = req.request_uri
      raise SSRFProxy::HTTP::Error::InvalidHttpRequest if uri.nil?
    rescue => e
      logger.info("Received malformed client HTTP request.")
      return "HTTP\/1.1 501 Error\nServer: SSRF Proxy\nContent-Length: 0\n\n"
    end

    # parse post data and move to uri
    if @post_to_uri && !req.body.nil?
      logger.debug "Parsing request body: #{req.body}"
      begin
        new_query = URI.decode_www_form(req.body)
        if req.query_string.nil?
          uri = "#{uri}?#{URI.encode_www_form(new_query)}"
        else
          URI.decode_www_form(req.query_string).each { |p| new_query << p }
          uri = "#{uri}&#{URI.encode_www_form(new_query)}"
        end
      rescue
        logger.warn "Could not parse request POST data"
      end
    end

    # move basic authentication credentials to uri
    if @auth_to_uri && !req.header.nil?
      req.header['authorization'].each do |header|
        next unless header.split(' ').first =~ /^basic$/i
        begin
          creds = header.split(' ')[1]
          user = Base64.decode64(creds).chomp
          logger.info "Using basic authentication credentials: #{user}"
          uri = uri.to_s.gsub!(/:(\/\/)/, "://#{user}@")
        rescue
          logger.warn "Could not parse request authorization header: #{header}"
        end
        break
      end
    end

    # forward client cookies
    new_cookie = []
    new_cookie << @cookie unless @cookie.nil?
    if @forward_cookies
      req.cookies.each do |c|
        new_cookie << "#{c}"
      end
    end
    unless new_cookie.empty?
      opts['cookie'] = new_cookie.uniq.join('; ').to_s
      logger.info "Using cookie: #{opts['cookie']}"
    end
    send_uri(uri, opts)
  end

  #
  # @note Fetch a URI via SSRF
  #
  # @options
  # - uri - URI - URI to fetch
  # - opts - Hash - request options (keys: cookie)
  #
  # @returns String - raw HTTP response headers and body 
  #
  def send_uri(uri, opts={})
    raise SSRFProxy::HTTP::Error::InvalidUriRequest if uri.nil?

    # convert ip
    if @ip_encoding
      encoded_url = encode_ip(uri, @ip_encoding)
      uri = encoded_url unless encoded_url.nil?
    end

    # send request
    status_msg  = "Request  -> #{@method}"
    status_msg << " -> PROXY[#{@upstream_proxy.host}:#{@upstream_proxy.port}]" unless @upstream_proxy.nil?
    status_msg << " -> SSRF[#{@ssrf_url.host}:#{@ssrf_url.port}] -> URI[#{uri}]"
    print_status(status_msg)
    response = send_http_request(uri, opts)
    response = parse_http_response(response) unless response.class == Hash
    body = response["body"]||''
    headers = response["headers"]

    # handle HTTP response
    if response["status"] == 'fail'
      status_msg  = "Response <- #{response["code"]}"
      status_msg << " <- PROXY[#{@upstream_proxy.host}:#{@upstream_proxy.port}]" unless @upstream_proxy.nil?
      status_msg << " <- SSRF[#{@ssrf_url.host}:#{@ssrf_url.port}] <- URI[#{uri}]"
      print_status(status_msg)
      return "#{response['headers']}#{response['body']}"
    end

    # guess mime type and add content-type header
    if @guess_mime
      content_type = guess_mime(File.extname(uri.to_s.split('?').first))
      unless content_type.nil?
        logger.info "Using content-type: #{content_type}"
        if headers =~ /^content\-type:.*$/i
          headers.gsub!(/^content\-type:.*$/i, "Content-Type: #{content_type}")
        else
          headers.gsub!(/\n\n\z/, "\nContent-Type: #{content_type}\n\n")
        end
      end
    end

    # match response content
    unless @match_regex.nil?
      matches = body.scan(/#{@match_regex}/m)
      if matches.length
        body = matches.flatten.first.to_s
        logger.info "Response matches pattern '#{@match_regex}'"
      else
        logger.warn "Response does not match pattern"
      end
    end

    # set content length
    content_length = body.to_s.length
    if headers =~ /^content\-length:.*$/i
      headers.gsub!(/^content\-length:.*$/i, "Content-Length: #{content_length}")
    else
      headers.gsub!(/\n\n\z/, "\nContent-Length: #{content_length}\n\n")
    end

    # return HTTP response
    logger.debug("Response:\n#{headers}#{body}")
    status_msg = "Response <- #{response["code"]}"
    status_msg << " <- PROXY[#{@upstream_proxy.host}:#{@upstream_proxy.port}]" unless @upstream_proxy.nil?
    status_msg << " <- SSRF[#{@ssrf_url.host}:#{@ssrf_url.port}] <- URI[#{uri}]"
    status_msg << " -- TITLE[#{$1}]" if body[0..1024] =~ /<title>([^<]*)<\/title>/im
    status_msg << " -- SIZE[#{body.size} bytes]"
    print_good(status_msg)
    return "#{headers}#{body}"
  end

  #
  # @note Send HTTP request
  #
  # @options
  # - url - String - URI to fetch
  # - opts - Hash - request options (keys: cookie)
  #
  # @returns Hash of HTTP response (status, code, headers, body)
  #
  def send_http_request(url, opts={})
    # use upstream proxy
    if @upstream_proxy.nil?
      http = Net::HTTP.new(@ssrf_url.host, @ssrf_url.port)
    else
      http = Net::HTTP::Proxy(@upstream_proxy.host, @upstream_proxy.port).new(@ssrf_url.host, @ssrf_url.port)
    end
    # run target url through rules
    target = run_rules(url, @rules)
    # replace xxURLxx placeholder in SSRF HTTP GET parameters
    ssrf_url = "#{@ssrf_url.path}?#{@ssrf_url.query}".gsub(/xxURLxx/, "#{target}")
    # replace xxURLxx placeholder in SSRF HTTP POST parameters
    post_data = @post_data.gsub(/xxURLxx/, "#{target}") unless @post_data.nil?
    if @ssrf_url.scheme == 'https'
      http.use_ssl     = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE #PEER
    end
    # set socket options
    http.open_timeout = @timeout
    http.read_timeout = @timeout
    # set request headers
    headers = {}
    headers['User-Agent'] = @user_agent unless @user_agent.nil?
    headers['Cookie'] = opts['cookie'].to_s unless opts['cookie'].nil?
    headers['Content-Type'] = 'application/x-www-form-urlencoded' if @method == 'POST'
    response = {}
    # send http request
    begin
      if @method == 'GET'
        response = http.request Net::HTTP::Get.new(ssrf_url, headers.to_hash)
      elsif @method == 'HEAD'
        response = http.request Net::HTTP::Head.new(ssrf_url, headers.to_hash)
      elsif @method == 'POST'
        request = Net::HTTP::Post.new(ssrf_url, headers.to_hash)
        request.body = post_data
        response = http.request(request)
      else
        logger.info("Client request method not implemented - METHOD[#{@method}]")
        response["status"]  = 'fail'
        response["code"]    = 501
        response["message"] = 'Error'
        response["headers"] = "HTTP\/1.1 501 Error\nServer: SSRF Proxy\nContent-Length: 0\n\n"
      end
    rescue Timeout::Error,Errno::ETIMEDOUT
      logger.warn("Connection timeout - TIMEOUT[#{@timeout}] - URI[#{url}]\n")
      response["status"]  = 'fail'
      response["code"]    = 504
      response["message"] = 'Timeout'
      response["headers"] = "HTTP\/1.1 504 Error\nServer: SSRF Proxy\nContent-Length: 0\n\n"
    rescue => e
      response["status"]  = 'fail'
      response["code"]    = 500
      response["message"] = 'Error'
      response["headers"] = "HTTP\/1.1 500 Error\nServer: SSRF Proxy\nContent-Length: 0\n\n"
      logger.error("Unhandled exception: #{e.message}: #{e}")
    end
    return response
  end

  #
  # @note Parse HTTP response
  #
  # @options
  # - response - Net::HTTPResponse - HTTP response object
  #
  # @returns - Hash - HTTP response object
  #
  def parse_http_response(response)
    return response if response.class == Hash
    result = {}
    begin
      result["status"]       = 'complete'
      result["http_version"] = response.http_version
      result["code"]         = response.code
      result["message"]      = response.message
      if @guess_status
        head = response.body[0..4096]
        if head =~ />401 Unauthorized</
          result["code"] = 401
          result["message"] = 'Unauthorized'
        elsif head =~ />403 Forbidden</
          result["code"] = 403
          result["message"] = 'Forbidden'
        elsif head =~ />404 Not Found</
          result["code"] = 404
          result["message"] = 'Not Found'
        elsif head =~ />500 Internal Server Error</
          result["code"] = 500
          result["message"] = 'Internal Server Error'
        end
        logger.info "Using HTTP response code: #{result["code"]}"
      end
      result["headers"] = "HTTP\/#{response.http_version} #{response.code} #{response.message}\n"
      response.each_header do |header_name, header_value|
        if @strip.include?(header_name.downcase)
          logger.info "Removed response header: #{header_name}"
          next
        end
        result["headers"] << "#{header_name}: #{header_value}\n"
      end
      result["headers"]   << "\n"
      result["body"] = "#{response.body}" unless response.body.nil?
    rescue => e
      logger.info("Malformed HTTP response from server")
      result["status"]  = 'fail'
      result["code"]    = 502
      result["message"] = 'Error'
      result["headers"] = "HTTP\/1.1 502 Error\nServer: SSRF Proxy\nContent-Length: 0\n\n"
    end
    return result
  end

  #
  # @note Guess content type based on file extension
  # - List from: https://stackoverflow.com/questions/1029740/get-mime-type-from-filename-extension
  #
  # @options
  # - ext - String - File extension [with dots] (Example: '.png')
  #
  # @returns String - content-type value
  #
  def guess_mime(ext)
    content_types = %w(
      323,text/h323,
      3g2,video/3gpp2,
      3gp,video/3gpp,
      3gp2,video/3gpp2,
      3gpp,video/3gpp,
      7z,application/x-7z-compressed,
      aa,audio/audible,
      AAC,audio/aac,
      aaf,application/octet-stream,
      aax,audio/vnd.audible.aax,
      ac3,audio/ac3,
      aca,application/octet-stream,
      accda,application/msaccess.addin,
      accdb,application/msaccess,
      accdc,application/msaccess.cab,
      accde,application/msaccess,
      accdr,application/msaccess.runtime,
      accdt,application/msaccess,
      accdw,application/msaccess.webapplication,
      accft,application/msaccess.ftemplate,
      acx,application/internet-property-stream,
      AddIn,text/xml,
      ade,application/msaccess,
      adobebridge,application/x-bridge-url,
      adp,application/msaccess,
      ADT,audio/vnd.dlna.adts,
      ADTS,audio/aac,
      afm,application/octet-stream,
      ai,application/postscript,
      aif,audio/x-aiff,
      aifc,audio/aiff,
      aiff,audio/aiff,
      air,application/vnd.adobe.air-application-installer-package+zip,
      amc,application/x-mpeg,
      application,application/x-ms-application,
      art,image/x-jg,
      asa,application/xml,
      asax,application/xml,
      ascx,application/xml,
      asd,application/octet-stream,
      asf,video/x-ms-asf,
      ashx,application/xml,
      asi,application/octet-stream,
      asm,text/plain,
      asmx,application/xml,
      aspx,application/xml,
      asr,video/x-ms-asf,
      asx,video/x-ms-asf,
      atom,application/atom+xml,
      au,audio/basic,
      avi,video/x-msvideo,
      axs,application/olescript,
      bas,text/plain,
      bcpio,application/x-bcpio,
      bin,application/octet-stream,
      bmp,image/bmp,
      c,text/plain,
      cab,application/octet-stream,
      caf,audio/x-caf,
      calx,application/vnd.ms-office.calx,
      cat,application/vnd.ms-pki.seccat,
      cc,text/plain,
      cd,text/plain,
      cdda,audio/aiff,
      cdf,application/x-cdf,
      cer,application/x-x509-ca-cert,
      chm,application/octet-stream,
      class,application/x-java-applet,
      clp,application/x-msclip,
      cmx,image/x-cmx,
      cnf,text/plain,
      cod,image/cis-cod,
      config,application/xml,
      contact,text/x-ms-contact,
      coverage,application/xml,
      cpio,application/x-cpio,
      cpp,text/plain,
      crd,application/x-mscardfile,
      crl,application/pkix-crl,
      crt,application/x-x509-ca-cert,
      cs,text/plain,
      csdproj,text/plain,
      csh,application/x-csh,
      csproj,text/plain,
      css,text/css,
      csv,text/csv,
      cur,application/octet-stream,
      cxx,text/plain,
      dat,application/octet-stream,
      datasource,application/xml,
      dbproj,text/plain,
      dcr,application/x-director,
      def,text/plain,
      deploy,application/octet-stream,
      der,application/x-x509-ca-cert,
      dgml,application/xml,
      dib,image/bmp,
      dif,video/x-dv,
      dir,application/x-director,
      disco,text/xml,
      dll,application/x-msdownload,
      dll.config,text/xml,
      dlm,text/dlm,
      doc,application/msword,
      docm,application/vnd.ms-word.document.macroEnabled.12,
      docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document,
      dot,application/msword,
      dotm,application/vnd.ms-word.template.macroEnabled.12,
      dotx,application/vnd.openxmlformats-officedocument.wordprocessingml.template,
      dsp,application/octet-stream,
      dsw,text/plain,
      dtd,text/xml,
      dtsConfig,text/xml,
      dv,video/x-dv,
      dvi,application/x-dvi,
      dwf,drawing/x-dwf,
      dwp,application/octet-stream,
      dxr,application/x-director,
      eml,message/rfc822,
      emz,application/octet-stream,
      eot,application/octet-stream,
      eps,application/postscript,
      etl,application/etl,
      etx,text/x-setext,
      evy,application/envoy,
      exe,application/octet-stream,
      exe.config,text/xml,
      fdf,application/vnd.fdf,
      fif,application/fractals,
      filters,Application/xml,
      fla,application/octet-stream,
      flr,x-world/x-vrml,
      flv,video/x-flv,
      fsscript,application/fsharp-script,
      fsx,application/fsharp-script,
      generictest,application/xml,
      gif,image/gif,
      group,text/x-ms-group,
      gsm,audio/x-gsm,
      gtar,application/x-gtar,
      gz,application/x-gzip,
      h,text/plain,
      hdf,application/x-hdf,
      hdml,text/x-hdml,
      hhc,application/x-oleobject,
      hhk,application/octet-stream,
      hhp,application/octet-stream,
      hlp,application/winhlp,
      hpp,text/plain,
      hqx,application/mac-binhex40,
      hta,application/hta,
      htc,text/x-component,
      htm,text/html,
      html,text/html,
      htt,text/webviewhtml,
      hxa,application/xml,
      hxc,application/xml,
      hxd,application/octet-stream,
      hxe,application/xml,
      hxf,application/xml,
      hxh,application/octet-stream,
      hxi,application/octet-stream,
      hxk,application/xml,
      hxq,application/octet-stream,
      hxr,application/octet-stream,
      hxs,application/octet-stream,
      hxt,text/html,
      hxv,application/xml,
      hxw,application/octet-stream,
      hxx,text/plain,
      i,text/plain,
      ico,image/x-icon,
      ics,application/octet-stream,
      idl,text/plain,
      ief,image/ief,
      iii,application/x-iphone,
      inc,text/plain,
      inf,application/octet-stream,
      inl,text/plain,
      ins,application/x-internet-signup,
      ipa,application/x-itunes-ipa,
      ipg,application/x-itunes-ipg,
      ipproj,text/plain,
      ipsw,application/x-itunes-ipsw,
      iqy,text/x-ms-iqy,
      isp,application/x-internet-signup,
      ite,application/x-itunes-ite,
      itlp,application/x-itunes-itlp,
      itms,application/x-itunes-itms,
      itpc,application/x-itunes-itpc,
      IVF,video/x-ivf,
      jar,application/java-archive,
      java,application/octet-stream,
      jck,application/liquidmotion,
      jcz,application/liquidmotion,
      jfif,image/pjpeg,
      jnlp,application/x-java-jnlp-file,
      jpb,application/octet-stream,
      jpe,image/jpeg,
      jpeg,image/jpeg,
      jpg,image/jpeg,
      js,application/x-javascript,
      json,application/json,
      jsx,text/jscript,
      jsxbin,text/plain,
      latex,application/x-latex,
      library-ms,application/windows-library+xml,
      lit,application/x-ms-reader,
      loadtest,application/xml,
      lpk,application/octet-stream,
      lsf,video/x-la-asf,
      lst,text/plain,
      lsx,video/x-la-asf,
      lzh,application/octet-stream,
      m13,application/x-msmediaview,
      m14,application/x-msmediaview,
      m1v,video/mpeg,
      m2t,video/vnd.dlna.mpeg-tts,
      m2ts,video/vnd.dlna.mpeg-tts,
      m2v,video/mpeg,
      m3u,audio/x-mpegurl,
      m3u8,audio/x-mpegurl,
      m4a,audio/m4a,
      m4b,audio/m4b,
      m4p,audio/m4p,
      m4r,audio/x-m4r,
      m4v,video/x-m4v,
      mac,image/x-macpaint,
      mak,text/plain,
      man,application/x-troff-man,
      manifest,application/x-ms-manifest,
      map,text/plain,
      master,application/xml,
      mda,application/msaccess,
      mdb,application/x-msaccess,
      mde,application/msaccess,
      mdp,application/octet-stream,
      me,application/x-troff-me,
      mfp,application/x-shockwave-flash,
      mht,message/rfc822,
      mhtml,message/rfc822,
      mid,audio/mid,
      midi,audio/mid,
      mix,application/octet-stream,
      mk,text/plain,
      mmf,application/x-smaf,
      mno,text/xml,
      mny,application/x-msmoney,
      mod,video/mpeg,
      mov,video/quicktime,
      movie,video/x-sgi-movie,
      mp2,video/mpeg,
      mp2v,video/mpeg,
      mp3,audio/mpeg,
      mp4,video/mp4,
      mp4v,video/mp4,
      mpa,video/mpeg,
      mpe,video/mpeg,
      mpeg,video/mpeg,
      mpf,application/vnd.ms-mediapackage,
      mpg,video/mpeg,
      mpp,application/vnd.ms-project,
      mpv2,video/mpeg,
      mqv,video/quicktime,
      ms,application/x-troff-ms,
      msi,application/octet-stream,
      mso,application/octet-stream,
      mts,video/vnd.dlna.mpeg-tts,
      mtx,application/xml,
      mvb,application/x-msmediaview,
      mvc,application/x-miva-compiled,
      mxp,application/x-mmxp,
      nc,application/x-netcdf,
      nsc,video/x-ms-asf,
      nws,message/rfc822,
      ocx,application/octet-stream,
      oda,application/oda,
      odc,text/x-ms-odc,
      odh,text/plain,
      odl,text/plain,
      odp,application/vnd.oasis.opendocument.presentation,
      ods,application/oleobject,
      odt,application/vnd.oasis.opendocument.text,
      one,application/onenote,
      onea,application/onenote,
      onepkg,application/onenote,
      onetmp,application/onenote,
      onetoc,application/onenote,
      onetoc2,application/onenote,
      orderedtest,application/xml,
      osdx,application/opensearchdescription+xml,
      p10,application/pkcs10,
      p12,application/x-pkcs12,
      p7b,application/x-pkcs7-certificates,
      p7c,application/pkcs7-mime,
      p7m,application/pkcs7-mime,
      p7r,application/x-pkcs7-certreqresp,
      p7s,application/pkcs7-signature,
      pbm,image/x-portable-bitmap,
      pcast,application/x-podcast,
      pct,image/pict,
      pcx,application/octet-stream,
      pcz,application/octet-stream,
      pdf,application/pdf,
      pfb,application/octet-stream,
      pfm,application/octet-stream,
      pfx,application/x-pkcs12,
      pgm,image/x-portable-graymap,
      pic,image/pict,
      pict,image/pict,
      pkgdef,text/plain,
      pkgundef,text/plain,
      pko,application/vnd.ms-pki.pko,
      pls,audio/scpls,
      pma,application/x-perfmon,
      pmc,application/x-perfmon,
      pml,application/x-perfmon,
      pmr,application/x-perfmon,
      pmw,application/x-perfmon,
      png,image/png,
      pnm,image/x-portable-anymap,
      pnt,image/x-macpaint,
      pntg,image/x-macpaint,
      pnz,image/png,
      pot,application/vnd.ms-powerpoint,
      potm,application/vnd.ms-powerpoint.template.macroEnabled.12,
      potx,application/vnd.openxmlformats-officedocument.presentationml.template,
      ppa,application/vnd.ms-powerpoint,
      ppam,application/vnd.ms-powerpoint.addin.macroEnabled.12,
      ppm,image/x-portable-pixmap,
      pps,application/vnd.ms-powerpoint,
      ppsm,application/vnd.ms-powerpoint.slideshow.macroEnabled.12,
      ppsx,application/vnd.openxmlformats-officedocument.presentationml.slideshow,
      ppt,application/vnd.ms-powerpoint,
      pptm,application/vnd.ms-powerpoint.presentation.macroEnabled.12,
      pptx,application/vnd.openxmlformats-officedocument.presentationml.presentation,
      prf,application/pics-rules,
      prm,application/octet-stream,
      prx,application/octet-stream,
      ps,application/postscript,
      psc1,application/PowerShell,
      psd,application/octet-stream,
      psess,application/xml,
      psm,application/octet-stream,
      psp,application/octet-stream,
      pub,application/x-mspublisher,
      pwz,application/vnd.ms-powerpoint,
      qht,text/x-html-insertion,
      qhtm,text/x-html-insertion,
      qt,video/quicktime,
      qti,image/x-quicktime,
      qtif,image/x-quicktime,
      qtl,application/x-quicktimeplayer,
      qxd,application/octet-stream,
      ra,audio/x-pn-realaudio,
      ram,audio/x-pn-realaudio,
      rar,application/octet-stream,
      ras,image/x-cmu-raster,
      rat,application/rat-file,
      rc,text/plain,
      rc2,text/plain,
      rct,text/plain,
      rdlc,application/xml,
      resx,application/xml,
      rf,image/vnd.rn-realflash,
      rgb,image/x-rgb,
      rgs,text/plain,
      rm,application/vnd.rn-realmedia,
      rmi,audio/mid,
      rmp,application/vnd.rn-rn_music_package,
      roff,application/x-troff,
      rpm,audio/x-pn-realaudio-plugin,
      rqy,text/x-ms-rqy,
      rtf,application/rtf,
      rtx,text/richtext,
      ruleset,application/xml,
      s,text/plain,
      safariextz,application/x-safari-safariextz,
      scd,application/x-msschedule,
      sct,text/scriptlet,
      sd2,audio/x-sd2,
      sdp,application/sdp,
      sea,application/octet-stream,
      searchConnector-ms,application/windows-search-connector+xml,
      setpay,application/set-payment-initiation,
      setreg,application/set-registration-initiation,
      settings,application/xml,
      sgimb,application/x-sgimb,
      sgml,text/sgml,
      sh,application/x-sh,
      shar,application/x-shar,
      shtml,text/html,
      sit,application/x-stuffit,
      sitemap,application/xml,
      skin,application/xml,
      sldm,application/vnd.ms-powerpoint.slide.macroEnabled.12,
      sldx,application/vnd.openxmlformats-officedocument.presentationml.slide,
      slk,application/vnd.ms-excel,
      sln,text/plain,
      slupkg-ms,application/x-ms-license,
      smd,audio/x-smd,
      smi,application/octet-stream,
      smx,audio/x-smd,
      smz,audio/x-smd,
      snd,audio/basic,
      snippet,application/xml,
      snp,application/octet-stream,
      sol,text/plain,
      sor,text/plain,
      spc,application/x-pkcs7-certificates,
      spl,application/futuresplash,
      src,application/x-wais-source,
      srf,text/plain,
      SSISDeploymentManifest,text/xml,
      ssm,application/streamingmedia,
      sst,application/vnd.ms-pki.certstore,
      stl,application/vnd.ms-pki.stl,
      sv4cpio,application/x-sv4cpio,
      sv4crc,application/x-sv4crc,
      svc,application/xml,
      swf,application/x-shockwave-flash,
      t,application/x-troff,
      tar,application/x-tar,
      tcl,application/x-tcl,
      testrunconfig,application/xml,
      testsettings,application/xml,
      tex,application/x-tex,
      texi,application/x-texinfo,
      texinfo,application/x-texinfo,
      tgz,application/x-compressed,
      thmx,application/vnd.ms-officetheme,
      thn,application/octet-stream,
      tif,image/tiff,
      tiff,image/tiff,
      tlh,text/plain,
      tli,text/plain,
      toc,application/octet-stream,
      tr,application/x-troff,
      trm,application/x-msterminal,
      trx,application/xml,
      ts,video/vnd.dlna.mpeg-tts,
      tsv,text/tab-separated-values,
      ttf,application/octet-stream,
      tts,video/vnd.dlna.mpeg-tts,
      txt,text/plain,
      u32,application/octet-stream,
      uls,text/iuls,
      user,text/plain,
      ustar,application/x-ustar,
      vb,text/plain,
      vbdproj,text/plain,
      vbk,video/mpeg,
      vbproj,text/plain,
      vbs,text/vbscript,
      vcf,text/x-vcard,
      vcproj,Application/xml,
      vcs,text/plain,
      vcxproj,Application/xml,
      vddproj,text/plain,
      vdp,text/plain,
      vdproj,text/plain,
      vdx,application/vnd.ms-visio.viewer,
      vml,text/xml,
      vscontent,application/xml,
      vsct,text/xml,
      vsd,application/vnd.visio,
      vsi,application/ms-vsi,
      vsix,application/vsix,
      vsixlangpack,text/xml,
      vsixmanifest,text/xml,
      vsmdi,application/xml,
      vspscc,text/plain,
      vss,application/vnd.visio,
      vsscc,text/plain,
      vssettings,text/xml,
      vssscc,text/plain,
      vst,application/vnd.visio,
      vstemplate,text/xml,
      vsto,application/x-ms-vsto,
      vsw,application/vnd.visio,
      vsx,application/vnd.visio,
      vtx,application/vnd.visio,
      wav,audio/wav,
      wave,audio/wav,
      wax,audio/x-ms-wax,
      wbk,application/msword,
      wbmp,image/vnd.wap.wbmp,
      wcm,application/vnd.ms-works,
      wdb,application/vnd.ms-works,
      wdp,image/vnd.ms-photo,
      webarchive,application/x-safari-webarchive,
      webtest,application/xml,
      wiq,application/xml,
      wiz,application/msword,
      wks,application/vnd.ms-works,
      WLMP,application/wlmoviemaker,
      wlpginstall,application/x-wlpg-detect,
      wlpginstall3,application/x-wlpg3-detect,
      wm,video/x-ms-wm,
      wma,audio/x-ms-wma,
      wmd,application/x-ms-wmd,
      wmf,application/x-msmetafile,
      wml,text/vnd.wap.wml,
      wmlc,application/vnd.wap.wmlc,
      wmls,text/vnd.wap.wmlscript,
      wmlsc,application/vnd.wap.wmlscriptc,
      wmp,video/x-ms-wmp,
      wmv,video/x-ms-wmv,
      wmx,video/x-ms-wmx,
      wmz,application/x-ms-wmz,
      wpl,application/vnd.ms-wpl,
      wps,application/vnd.ms-works,
      wri,application/x-mswrite,
      wrl,x-world/x-vrml,
      wrz,x-world/x-vrml,
      wsc,text/scriptlet,
      wsdl,text/xml,
      wvx,video/x-ms-wvx,
      x,application/directx,
      xaf,x-world/x-vrml,
      xaml,application/xaml+xml,
      xap,application/x-silverlight-app,
      xbap,application/x-ms-xbap,
      xbm,image/x-xbitmap,
      xdr,text/plain,
      xht,application/xhtml+xml,
      xhtml,application/xhtml+xml,
      xla,application/vnd.ms-excel,
      xlam,application/vnd.ms-excel.addin.macroEnabled.12,
      xlc,application/vnd.ms-excel,
      xld,application/vnd.ms-excel,
      xlk,application/vnd.ms-excel,
      xll,application/vnd.ms-excel,
      xlm,application/vnd.ms-excel,
      xls,application/vnd.ms-excel,
      xlsb,application/vnd.ms-excel.sheet.binary.macroEnabled.12,
      xlsm,application/vnd.ms-excel.sheet.macroEnabled.12,
      xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,
      xlt,application/vnd.ms-excel,
      xltm,application/vnd.ms-excel.template.macroEnabled.12,
      xltx,application/vnd.openxmlformats-officedocument.spreadsheetml.template,
      xlw,application/vnd.ms-excel,
      xml,text/xml,
      xmta,application/xml,
      xof,x-world/x-vrml,
      XOML,text/plain,
      xpm,image/x-xpixmap,
      xps,application/vnd.ms-xpsdocument,
      xrm-ms,text/xml,
      xsc,application/xml,
      xsd,text/xml,
      xsf,text/xml,
      xsl,text/xml,
      xslt,text/xml,
      xsn,application/octet-stream,
      xss,application/xml,
      xtp,application/octet-stream,
      xwd,image/x-xwindowdump,
      z,application/x-compress,
      zip,application/x-zip-compressed )
    content_types.each do |type_info|
      if ext == ".#{type_info.split(',').first}"
        content_type = type_info.split(',')[1]
        return content_type
      end
    end
    nil
  end

  private :parse_http_response,:send_http_request,:run_rules,:encode_ip,:guess_mime

end
end
