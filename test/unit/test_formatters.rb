#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#
require './test/test_helper'

class TestUnitSSRFProxyFormatter < Minitest::Test
  parallelize_me!

  #
  # @note test placeholder formatters
  #
  def test_placeholder
    SSRFProxy::Formatter::Placeholder::AddAuthToURI.new
    SSRFProxy::Formatter::Placeholder::AddBodyToURI.new
    SSRFProxy::Formatter::Placeholder::AddCacheBusterToURI.new
    SSRFProxy::Formatter::Placeholder::AddCookiesToURI.new
    SSRFProxy::Formatter::Placeholder::AppendHash.new
    SSRFProxy::Formatter::Placeholder::AppendMethodGet.new
    SSRFProxy::Formatter::Placeholder::Base32.new
    SSRFProxy::Formatter::Placeholder::Base64.new
    SSRFProxy::Formatter::Placeholder::Downcase.new
    SSRFProxy::Formatter::Placeholder::EncodeIpDottedHex.new
    SSRFProxy::Formatter::Placeholder::EncodeIpHex.new
    SSRFProxy::Formatter::Placeholder::EncodeIpInteger.new
    SSRFProxy::Formatter::Placeholder::EncodeIpIpv6.new
    SSRFProxy::Formatter::Placeholder::EncodeIpOctal.new
    SSRFProxy::Formatter::Placeholder::MD5.new
    SSRFProxy::Formatter::Placeholder::NoProto.new
    SSRFProxy::Formatter::Placeholder::NoSSL.new
    SSRFProxy::Formatter::Placeholder::Reverse.new
    SSRFProxy::Formatter::Placeholder::Rot13.new
    SSRFProxy::Formatter::Placeholder::SHA1.new
    SSRFProxy::Formatter::Placeholder::SSL.new
    SSRFProxy::Formatter::Placeholder::URLDecode.new
    SSRFProxy::Formatter::Placeholder::URLEncode.new
    SSRFProxy::Formatter::Placeholder::Upcase.new
  end

  #
  # @note test request formatters
  #
  def test_request
    SSRFProxy::Formatter::Request::ForwardBody.new
    SSRFProxy::Formatter::Request::ForwardCookies.new
    SSRFProxy::Formatter::Request::ForwardHeaders.new
    SSRFProxy::Formatter::Request::ForwardMethod.new
  end

  #
  # @note test response formatters
  #
  def test_response
    SSRFProxy::Formatter::Response::AddAuthenticateHeader.new
    SSRFProxy::Formatter::Response::AddCorsHeader.new
    SSRFProxy::Formatter::Response::AddLocationHeader.new
    SSRFProxy::Formatter::Response::DecodeHTML.new
    SSRFProxy::Formatter::Response::DetectHeaders.new
    SSRFProxy::Formatter::Response::FailNoContent.new
    SSRFProxy::Formatter::Response::GuessMime.new
    SSRFProxy::Formatter::Response::GuessStatus.new
    SSRFProxy::Formatter::Response::Match.new
    SSRFProxy::Formatter::Response::SniffMime.new
    SSRFProxy::Formatter::Response::StripHeaders.new
    SSRFProxy::Formatter::Response::TimeoutOk.new
    SSRFProxy::Formatter::Response::Unescape.new
  end
end
