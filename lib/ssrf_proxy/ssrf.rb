#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
module SSRFProxy
  #
  # SSRFProxy::SSRF object takes information required to connect
  # to a server vulnerable to Server-Side Request Forgery (SSRF).
  #
  class SSRF
    include Logging

    # @return [String] SSRF service host
    attr_reader :host
    # @return [Integer] SSRF service port
    attr_reader :port
    # @return [URI] upstream proxy
    attr_reader :proxy
    # @return [Integer] connection timeout
    attr_reader :timeout
    # @return [Boolean] use SSL/TLS
    attr_reader :tls
    # @return [Boolean] skip SSL/TLS verification
    attr_reader :insecure

    #
    # SSRFProxy::SSRF specifies SSRF connection details,
    # such as host, port, connection timeout and whether to
    # connect using transport layer security.
    #
    # @param [String] host Network host vulnerable to SSRF
    #
    # @param [String] port Network port vulnerable to SSRF
    #
    # @param [String] proxy Use a proxy to connect to the server.
    # (Supported proxies: http, https, socks)
    #
    # @param [Integer] timeout Connection timeout in seconds (Default: 10)
    #
    # @param [Boolean] tls Connect using SSL/TLS
    #
    # @param [Boolean] insecure Skip server SSL certificate validation
    #
    def initialize(host:, port:, proxy:, timeout:, tls: false, insecure: false)
      @host = host.freeze
      @port = port.freeze
      @timeout = timeout.freeze
      @tls = tls.freeze
      @insecure = insecure.freeze

      if proxy
        begin
          @proxy = URI.parse(proxy.to_s).freeze
        rescue URI::InvalidURIError
          raise SSRFProxy::SSRF::Error::InvalidUpstreamProxy.new,
                'Invalid upstream proxy specified.'
        end
        if @proxy.host.nil? || @proxy.port.nil?
          raise SSRFProxy::SSRF::Error::InvalidUpstreamProxy.new,
                'Invalid upstream proxy specified.'
        end
        if @proxy.scheme !~ /\A(socks|https?)\z/
          raise SSRFProxy::SSRF::Error::InvalidUpstreamProxy.new,
                'Unsupported upstream proxy specified. ' \
                'Scheme must be http(s) or socks.'
        end
      else
        @proxy = nil
      end
    end
  end
end
