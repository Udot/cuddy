# encoding : utf-8
require "rubygems"
require "redis"
require "json"
require "fog"
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
  def initialize(file)
    @log_file = file
  end

  def info(msg)
    write("info",msg)
  end
  def warn(msg)
    write("warn",msg)
  end
  def error(msg)
    write("error",msg)
  end
  def write(level, msg)
    File.open(@log_file, "a") { |f| f.puts "#{level[0].capitalize} :: #{Time.now.to_s} : #{msg}"}
  end
end

@current_path = File.expand_path(File.dirname(__FILE__))

@init_config = YAML.load_file("#{@current_path}/config.yml")
hostname = Socket.gethostbyname(Socket.gethostname).first
@first_run = true

# generate uniq token if not present
@cuddy_token = @init_config[environment]['cuddy_token']
if @cuddy_token == nil
  @init_config[environment]['cuddy_token'] = generate_token
  File.open("#{@current_path}/config.yml", 'w' ) do |out|
    YAML.dump( @init_config, out )
  end
  @cuddy_token = @init_config[environment]['cuddy_token']
else
  @first_run = false
end

require "#{@current_path}/lib/remote_syslog"
@config = YAML.load_file("#{@current_path}/config.yml")[environment]
LOGGER = RemoteSyslog.new(@config["remote_log_host"],@config["remote_log_port"]) if environment == "production"
LOGGER = SimpleLogger.new("sinatra.log") if environment == "development"
# queue in
@redis = Redis.new(:host => @config['redis']['host'], :port => @config['redis']['port'], :password => @config['redis']['password'], :db => @config['redis']['db'])
# global status db
@redis_global = Redis.new(:host => @config['redis']['host'], :port => @config['redis']['port'], :password => @config['redis']['password'], :db => @config['redis']['global_db'])

# should send token to front with hostname
@identity = {"hostname" => hostname, "token" => @cuddy_token}

# if set to true then part of the config will not be done (unicorn)
@config['backoffice'] ? @backoffice = true : @backoffice = false

def logger
  LOGGER
end

module EggApi
  require 'net/http'
  require "net/https"
  extend self
  def unicorn_config(app_name)
    code, body = get("config?app_name=#{app_name}")
    return JSON.parse(body) unless code.to_i != 200
    return nil
  end

  def register(register_json)
    return post("/api/web/register",register_json)
  end
  private
  def get(request)
    config = YAML.load_file("#{SRC_DIR}/config/config.yml")
    http_r = Net::HTTP.new(@config['egg_api']['host'], @config['egg_api']['port'])
    http_r.use_ssl = @config['egg_api']['ssl']
    response = nil
    begin
      http_r.start() do |http|
        req = Net::HTTP::Get.new('/api/web/' + request)
        req.add_field("USERNAME", @config['egg_api']['username'])
        req.add_field("TOKEN", @config['egg_api']['token'])
        response = http.request(req)
      end
      return [response.code, response.body]
    rescue Errno::ECONNREFUSED
      @logger.error("front server didn't answer !")
      return [503, "unavailable"]
    end
  end
  def post(request,payload)
    http_r = Net::HTTP.new(@config['egg_api']['host'], @config['egg_api']['port'])
    http_r.use_ssl = config['egg_api']['ssl']
    response = nil
    begin
      http_r.start() do |http|
        req = Net::HTTP::Post.new(request, initheader = {'Content-Type' =>'application/json'})
        req.add_field("USERNAME", @config['egg_api']['username'])
        req.add_field("TOKEN", @config['egg_api']['token'])
        req.body = payload
        req.set_form_data(payload)
        response = http.request(req)
      end
    rescue Errno::ECONNREFUSED
      return [503, "unavailable"]
    end
    return [response.code, response.body]
  end
end

class Deploy
  attr_accessor :name, :version, :db_string, :database_yml, :start_time
  def initialize(name, version, db_string = nil)
    @name = name
    @version = version
    @db_string = db_string
    @database_yml = ""
    @start_time = Time.now
  end

  def start_time_from_redis
    node = @redis_global.get(name)
    if node != nil
      self.start_time = JSON.parse(node)['started_at']
      return start_time
    end
    return Time.now
  end

  def deploy_to
    return "/var/www/hosts/#{name}"
  end

  def shared
    return "#{deploy_to}/shared"
  end

  def download
    begin
      # get the file from cloudfiles
      img = "#{name}-#{version}.tar.gz"
      @logger.info("starting deployment for #{name} #{version}")

      start_time = start_time_from_redis
      status = {"status" => "deploying", "version" => version, "started_at" => start_time, "finished_at" => "", "error" => {"message" => "", "backtrace" => ""}, "identity" => @identity}.to_json
      @redis_global.set(name, status)
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
      @logger.info("downloaded file #{name} #{version}") if File.exist?("/tmp/#{img}")
    rescue => e
      p e.message
      p e.backtrace
      @logger.error(e.message)
      status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
      @redis_global.set(name, status)
    end
  end

  def extract
    begin
      # extract
      FileUtils.mkdir(deploy_to) unless File.exist?(deploy_to)
      Dir.chdir(deploy_to)
      extract_log = `tar -xzf /tmp/#{img}`
      if $?.to_i == 0
        @logger.info("extracted #{name} #{version}") if File.exist?("/var/www/hosts/#{name}/#{version}")
        raise SystemCallError, "extraction of #{img} for #{name} #{version} failed" unless File.exist?("/var/www/hosts/#{name}/#{version}")
      else
        raise SystemCallError, "extraction of #{img} for #{name} #{version} failed"
      end
      FileUtils.rm("/tmp/#{img}") if File.exist?("/tmp/#{img}")
    rescue => e
      p e.message
      p e.backtrace
      @logger.error(e.message)
      status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
      @redis_global.set(name, status)
    end
  end

  # make sure the env is there ready
  def setup_init
    begin
      # stop the app
      FileUtils.mkdir_p("#{shared}/log") unless File.exist?("#{shared}/log")
      FileUtils.mkdir_p("#{shared}/pids") unless File.exist?("#{shared}/pids")
    rescue => e
      p e.message
      p e.backtrace
      @logger.error(e.message)
      status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
      @redis_global.set(name, status)
    end
  end

  # stop the previous 
  def stop_previous
    begin
      if File.exist?("#{shared}/pids/unicorn-#{name}.pid")
        unicorn_pid = `cat #{shared}/pids/unicorn-#{name}.pid`
        stop_log = `kill -QUIT #{unicorn_pid}`
        #ab = system("kill -0 95252")
        # checking if the process is still running
        sleep(5) # gives 5 seconds to the process to die peacefully
        is_running = system("kill -0 #{unicorn_pid}")
        raise SystemCallError, "process #{unicorn_pid} for #{name} still exist"
        FileUtils.rm("#{shared}/pids/unicorn-#{name}.pid") if File.exist?("#{shared}/pids/unicorn-#{name}.pid")
        @logger.info("stopped old unicorn #{name} #{version}")
      end
    rescue => e
      p e.message
      p e.backtrace
      @logger.error(e.message)
      status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
      @redis_global.set(name, status)
    end
  end

  def database_yml    
    return nil if (db_string == (nil || ""))
    self.database_yml += "production:\n"
    self.database_yml += "\tadapter: postgres\n"
    self.database_yml += "\thost: #{app['config']['db']["hostname"]}\n"
    self.database_yml += "\tdatabase: #{app['config']['db']['database']}\n"
    self.database_yml += "\tusername: #{app['config']['db']['username']}\n"
    password = Digest::SHA1.hexdigest(db_string + @config['db_token'])
    self.database_yml += "\tpassword: #{password}\n"
    self.database_yml += "\tpool: 5\n\ttimeout: 5000\n"
  end

  def unicorn_dummy_config
    shared = "/var/www/hosts/#{name}/shared/"
    config_file = ""
    config_file += "listen 8080, :tcp_nopush => true\n"
    config_file += "worker_processes 2\n"
    config_file += "user cuddy, www-data\n"
    config_file += "working_directory /var/www/hosts/#{name}/current\n"
    config_file += "pid #{shared}/unicorn_#{git_repository.path}.pid\n"
    config_file += "stderr_path #{shared}/log/stderr.log\n"
    config_file += "stdout_path #{shared}/log/stdout.log\n"
    return config_file
  end

  # get unicorn config from the main app
  def unicorn_config
    return EggApi.unicorn_config(name)['config']
  end

  # set the database config right, should be called only the first time (the front doesn't store the db password)
  def configure_database
    begin
      FileUtils.mkdir_p("/var/www/hosts/#{name}/shared/config") unless File.exist?("/var/www/hosts/#{name}/shared/config")
      if (database_yml != nil)
        db_yml = database_yml 
        File.open("/var/www/hosts/#{name}/shared/config/database.yml", "w") { |f| f.puts db_yml }
        return true if File.exist?("/var/www/hosts/#{name}/shared/config/database.yml")
      end
      return false
    rescue => e
      p e.message
      p e.backtrace
      @logger.error(e.message)
      status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
      @redis_global.set(name, status)
    end
  end

  def configure_unicorn
    begin
      FileUtils.mkdir_p("/var/www/hosts/#{name}/shared/config") unless File.exist?("/var/www/hosts/#{name}/shared/config")
      config_file = unicorn_config
      if config_file != nil
        File.open("/var/www/hosts/#{name}/shared/config/unicorn.rb", "w") { |f| f.puts config_file }
      else
        # oh boy, before rewritting over an existing configuration we check if there is already a unicorn.rb file
        if not File.exist?("/var/www/hosts/#{name}/shared/config  /unicorn.rb")
          # write a dummy config
          config_file = unicorn_dummy_config
          File.open("/var/www/hosts/#{name}/shared/config/unicorn.rb", "w") { |f| f.puts config_file }
        end
      end
    rescue => e
      p e.message
      p e.backtrace
      @logger.error(e.message)
      status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
      @redis_global.set(name, status)
    end
  end

  # create the new current link and copy the config
  def setup_pre
    begin
      # remove previous link
      FileUtils.rm("#{deploy_to}/current") if File.exist?("#{deploy_to}/current")
      # point the current dir to the right version
      FileUtils.rm("#{deploy_to}/current") if File.exist?("#{deploy_to}/current")
      FileUtils.ln_s("#{deploy_to}/#{version}", "#{deploy_to}/current")
    
      # copy the app config (database) if present
      if File.exist?("#{shared}/config")
        @logger.info("Copying configuration")
        FileUtils.cp_r("#{shared}/config", "#{deploy_to}/current")
      end
    rescue => e
      p e.message
      p e.backtrace
      @logger.error(e.message)
      status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
      @redis_global.set(name, status)
    end
  end

  # start the unicorn
  def start
    begin
      @logger.info("Starting #{name} #{version} with : bundle exec unicorn -c #{deploy_to}/current/config/unicorn.rb -D -E production #{deploy_to}/current/config.ru")
      start_log = `cd #{deploy_to}/current && bundle exec unicorn -c #{deploy_to}/current/config/unicorn.rb -D -E production #{deploy_to}/current/config.ru`
      sleep(5) # gives 5 seconds to the process to start
      if File.exist?("#{shared}/pids/unicorn-#{name}.pid")
        unicorn_pid = `cat #{shared}/pids/unicorn-#{name}.pid`
        is_running = system("kill -0 #{unicorn_pid}")
        @logger.info("started new unicorn #{name} #{version}") if is_running
        @logger.warn("something failed when starting unicorn for #{name} #{version}") unless is_running
      else
        @logger.warn("something failed when starting unicorn for #{name} #{version}")
      end
    rescue => e
      p e.message
      p e.backtrace
      @logger.error(e.message)
      status = {"status" => "failed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => e.message, "backtrace" => e.backtrace}, "identity" => @identity}.to_json
      @redis_global.set(name, status)
    end
    @logger.info("finished deployment for #{name} #{version}")
    status = {"status" => "deployed", "version" => version, "started_at" => start_time, "finished_at" => Time.now, "error" => {"message" => "", "backtrace" => ""}, "identity" => @identity}.to_json
    @redis_global.set(name, status)
  end
end

logger.info("Starting")
puts "Started" if environment == "development"

if (@first_run && (not @backoffice))
  code, body = EggApi.register({"hostname" => hostname, "token" => @cuddy_token}.to_json)
  if code.to_i == 200
    logger.info("Registered !")
  else
    logger.info("Could not register !, raising exception")
    raise LoadError, "could not register at first run !" unless (code.to_i == 200)
  end
end

while true
  queue = JSON.parse(@redis.get(@cuddy_token)) unless @redis.get(@cuddy_token) == nil
  queue ||= Array.new
  while queue.size > 0
    # key is token of the cuddy node, value is array, each item using following format : 
    #   {  "name" => string,           # the name of the app
    #      "version" => integer,       # the version number of the app
    #      "db_string" => string,      # basis for pwd
    # }
    app = queue.pop
    # don't do any
    app['db_string'] == "ALREADY_DONE" ? @db_config = false : @db_config = true
    app_d = Deploy.new(app['name'], app['version'], app['db_string'])
    fork {
      app_d.download        # get the new version of the app
      app_d.extract         # extract it
      app_d.setup_init      # prepare the end
      app_d.stop_previous   # stop the previous version
      # create the unicorn config only if this is not the backend server
      app_d.configure_unicorn unless @backoffice
      app_d.configure_database if @db_config
      app_d.setup_pre       # create the current link, copy the config
      app_d.start           # start the app
    }
    @redis.set(@cuddy_token, queue.to_json)
  end
end
