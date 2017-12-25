#
# Copyright (c) 2015-2017 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
module SSRFProxy
  class SSRF
    # @return [Logger] logger
    attr_reader :logger
    # @return [String] SSRF prtocol
    attr_reader :protocol
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
    # SSRFProxy::SSRF errors
    #
    module Error
      # SSRFProxy::SSRF errors
      class Error < StandardError; end
      exceptions = %w[InvalidProtocol]
      exceptions.each { |e| const_set(e, Class.new(Error)) }
    end

    def initialize(protocol:, host:, port:, proxy:, timeout:, tls: false, insecure: false)
      @SUPPORTED_IP_ENCODINGS = %w[int ipv6 oct hex dotted_hex].freeze

      @logger = ::Logger.new(STDOUT).tap do |log|
        log.progname = 'ssrf-proxy'
        log.level = ::Logger::WARN
        log.datetime_format = '%Y-%m-%d %H:%M:%S '
      end

      if protocol.eql?('tcp') || protocol.eql?('udp')
        @protocol = protocol.freeze
      else
        raise SSRFProxy::SSRF::Error::InvalidProtocol.new,
              "Invalid protocol specified : #{protocol.inspect}"
      end

      @host = host.freeze
      @port = port.freeze
      @proxy = proxy.freeze
      @timeout = timeout.freeze
      @tls = tls.freeze
      @insecure = insecure.freeze
    end

    #
    # Encode IP address
    #
    # @param [String] host target host IP address
    # @param [String] mode encoding (int, ipv6, oct, hex, dotted_hex)
    #
    # @return [String] encoded IP address
    #
    def encode_ip(host, mode)
      return if host.nil?

      unless @SUPPORTED_IP_ENCODINGS.include?(mode)
        logger.warn("Invalid IP encoding: #{mode}".yellow)
        return
      end

      begin
        ip = IPAddress::IPv4.new(host)
      rescue
        logger.warn("Could not parse requested host as IPv4 address: #{host}".yellow)
        return
      end

      case mode
      when 'int'
        ip.to_u32.to_s
      when 'ipv6'
        "[#{ip.to_ipv6}]"
      when 'oct'
        "0#{ip.to_u32.to_s(8)}"
      when 'hex'
        "0x#{ip.to_u32.to_s(16)}"
      when 'dotted_hex'
        ip.octets.map { |i| "0x#{i.to_s(16).rjust(2, '0')}" }.join('.').to_s
      else
        logger.warn("Invalid IP encoding: #{mode}".yellow)
        nil
      end
    end
  end
end
