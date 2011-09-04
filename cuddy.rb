# encoding : utf-8
require "rubygems"
require "bundler/setup"

# get all the gems in
Bundler.require(:default)
require "digest/sha1"
require "yaml"
require "fileutils"
require 'remote_syslog_logger'
require 'socket'

@current_path = File.expand_path(File.dirname(__FILE__))

def is_mac?
  RUBY_PLATFORM.downcase.include?("darwin")
end

def is_linux?
   RUBY_PLATFORM.downcase.include?("linux")
end

def environment
  return "development" if is_mac?
  return "production" if is_linux?
end

def generate_token
  arh = Array.new
  (1..9).each { |i| arh << i.to_s }
  ("a".."z").each { |i| arh << i }
  ("A".."Z").each { |i| arh << i }
  4.times { arh.shuffle! }
  init_token = ""
  42.times { init_token += arh[rand(arh.size - 1)]}
  return Digest::SHA1.hexdigest(init_token)
end

class SimpleLogger
  require "syslog"
  attr_accessor :log_file
  def initialize(file_path)
    @log_file = File.open(file_path, "a")
  end

  def info(msg)
    log_file.puts("I :: #{Time.now.to_s } :: INFO : #{msg}")
  end
  def error(msg)
    log_file.puts("E :: #{Time.now.to_s } :: ERROR : #{msg}")
  end
  def warn(msg)
    log_file.puts("W :: #{Time.now.to_s } :: WARN : #{msg}")
  end
end

@init_config = YAML.load_file("#{@current_path}/config.yml")

# generate uniq token if not present
@cuddy_token = @init_config[environment]['cuddy_token']
if @cuddy_token == nil
  @init_config[environment]['cuddy_token'] = generate_token
  File.open("#{@current_path}/config.yml", 'w' ) do |out|
    YAML.dump( @init_config, out )
  end
  @cuddy_token = @init_config[environment]['cuddy_token']
end

hostname = Socket.gethostbyname(Socket.gethostname).first
@identity = {"hostname" => hostname, "token" => @cuddy_token}
@config = @init_config[environment]
@redis = Redis.new(:host => @config['redis']['host'], :port => @config['redis']['port'], :password => @config['redis']['password'], :db => @config['redis']['database'])

if environment == "production"
  require_relative 'lib/remote_syslog'
  @logger = RemoteSyslogLogger.new(config["remote_log_host"],config["remote_log_port"])
else
  Dir.mkdir(@current_path + "/log") unless File.exist?(@current_path + "/log")
  @logger = SimpleLogger.new(@current_path + "/log/development.log")
end

# this one does care about db config
def normal_start(app)
  begin
    name = app['name']
    version = app['version']
    logger("info", "starting deployment for #{name} #{version}")
    status = JSON.parse(@redis.get(name)) if (@redis.get(name) != nil)
    start_time = status['started_at']
    # stop the app
    stop_log = `/etc/init.d/unicorn_cuddy stop`
    @logger.info("stopping old unicorn #{name} #{version}")
    status = {"status" => "starting", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => "", "backtrace" => ""}, "identity" => @identity}.to_json
    @redis.set(name, status)

    # point the current dir to the right version
    FileUtils.rm("/var/www/current") if File.exist?("/var/www/current")
    FileUtils.ln_s("/var/www/#{name}/#{version}", "/var/www/current")

    # putting the db config in place
    File.open("/var/www/config/database.yml", "w") do |config_file|
      config_file.puts("production:")
      config_file.puts("\tadapter: postgres")
      config_file.pust("\thost: #{app['config']['db']["hostname"]}")
      config_file.puts("\tdatabase: #{app['config']['db']['database']}")
      config_file.puts("\tusername: #{app['config']['db']['username']}")
      password = Digest::SHA1.hexdigest(@config['secret_salt'] + app['config']['db']['token'])
      config_file.puts("\tpassword: #{password}")
      config_file.puts("\tpool: 5\n\ttimeout: 5000\n")
    end

    # unicorn config
    File.open("/var/www/config/unicorn-config.rb", "w") do |config_file|
      config_file.puts("listen 8080")
      config_file.puts("worker_processes #{app['config']['unicorn']['workers']}")
      config_file.puts("pid /var/run/unicorn_#{name}.pid")
      # need to be replaced by syslog
      config_file.puts("stderr_path /var/log/unicorn/stderr.log")
      config_file.puts("stdout_path /var/log/unicorn/stdout.log")
      config_file.puts("working_directory /var/www/current")
      config_file.puts("user cuddy, www-data")
    end

    # start the unicorn using init
    start_log = `/etc/init.d/unicorn_cuddy start`
    @logger.info("started new unicorn #{name} #{version}")
  rescue => e
    p e.message
    p e.backtrace
    @logger.error(e.message)
    status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
    @redis.set(repository, status)
  end
  @logger.info("finished deployment for #{name} #{version}")
  status = {"status" => "started", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => "", "backtrace" => ""}, "identity" => @identity}.to_json
  @redis.set(name, status)
end

# this one doesn't care about the db config
def backoffice_start(app)
  begin
    name = app['name']
    version = app['version']
    logger("info", "starting deployment for #{name} #{version}")
    status = JSON.parse(@redis.get(name)) if (@redis.get(name) != nil)
    start_time = status['started_at']
    deploy_to = "/var/www/#{name}"
    # stop the app
    unicorn_pid = `cat /var/www/shared/pids/unicorn-#{name}.pid`
    stop_log = `kill -QUIT #{unicorn_pid}`
    @logger.info("stopping old unicorn #{name} #{version}")
    status = {"status" => "starting", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => "", "backtrace" => ""}, "identity" => @identity}.to_json
    @redis.set(name, status)
    
    # point the current dir to the right version
    FileUtils.rm("#{deploy_to}/current") if File.exist?("#{deploy_to}/current")
    FileUtils.ln_s("#{deploy_to}/#{version}", "#{deploy_to}/current")

    # start the unicorn using init
    start_log = `cd #{deploy_to}/current && bundle exec unicorn -c #{deploy_to}/current/config/unicorn.rb -D -E production #{deploy_to}/current/config.ru`
    @logger.info("started new unicorn #{name} #{version}")
  rescue => e
    p e.message
    p e.backtrace
    @logger.error(e.message)
    status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
    @redis.set(repository, status)
  end
  @logger.info("finished deployment for #{name} #{version}")
  status = {"status" => "started", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => "", "backtrace" => ""}, "identity" => @identity}.to_json
  @redis.set(name, status)
end

# expect hash :
#  {"version" => integer,      # the version number
#   "name" => string,           # the name of the app
#   "status" => string,         # starts with "waiting"
#   "started_at" => datetime,   # the time when the app was added in the queue
#   "finished_at" => datetime,  # the time when the app was properly deployed
#   "backoffice" => boolean     # hoy
#   "config" => { "unicorn" => { "workers" => integer },
#     "db" => {"hostname" => string, "database" => string, "username" => string, "token" => string}
#   }
# }
def deploy(app)
  begin
    # get the file from cloudfiles
    img = "#{app['name']}-#{app['version']}.tgz"
    name = app['name']
    version = app['version']
    logger("info", "starting deployment for #{name} #{version}")
    status = JSON.parse(@redis.get(name)) if (@redis.get(name) != nil)
    start_time = status['started_at']

    status = {"status" => "deploying", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => "", "backtrace" => ""}, "identity" => @identity}.to_json
    @redis.set(name, status)
    rs_dor = ""
    if is_linux?
      rs_dir = "sqshed_apps"
    elsif is_mac?
      rs_dir = "sqshed_apps_test"
    end

    storage = Fog::Storage.new(:provider => 'Rackspace', :rackspace_auth_url => @config["rackspace_auth_url"], :rackspace_api_key => @config["rackspace_api_key"], :rackspace_username => @config['rackspace_username'])
    directory = storage.directories.get(rs_dir)
    img_file = directory.files.get(img)
    File.open("/tmp/#{img}", "w") { |f| f.write(img_file.body) }
    @logger.info("downloaded file #{img}")

    # extract
    Dir.chdir("/var/www/#{app['name']}")
    extract_log = `tar -xzf /tmp/#{img}`
    if $?.to_i == 0
      logger("info", "downloaded file #{img}")
    else
      raise SystemCallError, "extraction of #{img} failed"
    end

    # starting the app stuff
    if app['backoffice']
      backoffice_start(app)
    else
      normal_start(app)
    end
  rescue => e
    p e.message
    p e.backtrace
    @logger.error(e.message)
    status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
    @redis.set(repository, status)
  end
end

while true
  # TODO : change, check a key in redis equal to uniq token of the cuddy node
  queue = JSON.parse(@redis.get(@cuddy_token))
  while queue.size > 0
    app = queue.pop
    deploy(app)
    @redis.set(@cuddy_token, queue.to_json)
  end
end
