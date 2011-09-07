class RemoteSyslog
  def initialize(host, port)
    @logger = RemoteSyslogLogger.new(host, port, {:program => 'cuddy'})
  end

  def info(msg)
    @logger.info(msg)
  end
  def error(msg)
    @logger.error(msg)
  end
  def warn(msg)
    @logger.warn(msg)
  end

  def write(str)
    @logger.info(str)
  end
end