#
# Copyright (c) 2015-2018 Brendan Coles <bcoles@gmail.com>
# SSRF Proxy - https://github.com/bcoles/ssrf_proxy
# See the file 'LICENSE.md' for copying permission
#

module SSRFProxy
  #
  # Logging
  #
  module Logging
    def logger
      Logging.logger
    end

    def self.logger
      @logger ||= ::Logger.new(STDOUT).tap do |log|
        log.progname = 'ssrf-proxy'
        log.level = ::Logger::WARN
        log.datetime_format = '%Y-%m-%d %H:%M:%S '
        log.formatter = proc do |severity, datetime, progname, msg|
          case severity
          when 'FATAL'
            "[F] [#{datetime}]  #{severity} -- #{progname}: #{msg}\n".red.bold
          when 'ERROR'
            "[E] [#{datetime}]  #{severity} -- #{progname}: #{msg}\n".red
          when 'WARN'
            "[W] [#{datetime}]  #{severity} -- #{progname}: #{msg}\n".yellow
          when 'INFO'
            "[I] [#{datetime}]  #{severity} -- #{progname}: #{msg}\n".light_black
          when 'DEBUG'
            "[D] [#{datetime}]  #{severity} -- #{progname}: #{msg}\n".light_black
          else
            "[?] [#{datetime}]  #{severity} -- #{progname}: #{msg}\n"
          end
        end
      end
    end
  end
end
