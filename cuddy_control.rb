#!/usr/bin/env ruby
require "rubygems"
require "bundler/setup"
require "fileutils"

# get all the gems in
Bundler.require(:default)

Daemons.run('cuddy.rb')