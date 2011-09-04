# encoding: utf-8
require "rubygems"
require "bundler/setup"
require "net/http"

# get all the gems in
Bundler.require(:default)

module SimpleApi
  extend self
  def post(request, payload)
    http_r = Net::HTTP.new("backup.arbousier.info", 8084)
    http_r.use_ssl = false
    response = nil
    http_r.start() do |http|
      req = Net::HTTP::Post.new(request)
      req.add_field("TOKEN", "0769e94ae71ddc205c05a194f45494cf84cb3e54648fd")
      req.body = payload
      req.set_form_data(payload)
      response = http.request(req)
    end
    return [response.code, response.body]
  end
end

class Harry < Thor
  include Thor::Actions
  desc "deploy", "setup the first user"
  def deploy
    # params[:name], params[:url], params[:bundler]
    name = "cuddy"
    url = "git://github.com/Udot/cuddy.git"
    bundler = "true"
    payload = {"name" => name, "repository" => url, "bundler" => "lah", "no_register" => 1}
    SimpleApi.post("/",payload)
  end
end