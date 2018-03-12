#!/usr/bin/env ruby
#
# bin/server.rb (ruby-cloudtrail-slack v1.0.0)
# Executes lib/server.rb
#
# Read README.md for details.
#
# Author: Cody Tubbs (codytubbs@gmail.com) July 2017
#         https://github.com/codytubbs/ruby-cloudtrail-slack
#
###############################################################################
# Attempts to follow strict Ruby Style Guidelines enforced by `Rubocop'
# rubocop:disable LineLength # Comment to rid line length warnings >80
require 'optparse'

state_dir      = Dir.pwd
options        = { :action => :run, creds_profile: 'default', region: 'us-west-2', state_dir: state_dir}
version        = '1.0.0'
daemonize_help = 'run daemonized in the background (default: false)'
pidfile_help   = 'the pid filename'
logfile_help   = 'the log filename'
include_help   = 'an additional $LOAD_PATH'
debug_help     = 'set $DEBUG to true'
warn_help      = 'enable warnings'
creds_help     = 'default: "default"'
state_help     = "default (current working directory): #{state_dir}"

op = OptionParser.new
op.banner =  "\nruby-cloudtrail-slack"
op.separator ''
op.separator 'Usage: bin/server.rb -Ilib [options]'
op.separator ''

op.separator 'Process options:'
op.on('-d', '--daemonize',   daemonize_help){         options[:daemonize] = true  }
op.on('-p', '--pid PIDFILE', pidfile_help)  { |value| options[:pidfile]   = value }
op.on('-l', '--log LOGFILE', logfile_help)  { |value| options[:logfile]   = value }
op.separator ''

op.separator 'Ruby options:'
op.on('-I', '--include PATH', include_help){ |value| $LOAD_PATH.unshift(*value.split(':').map{|v| File.expand_path(v)}) }
op.on(      '--debug',        debug_help)  { $DEBUG = true }
op.on(      '--warn',         warn_help)   { $-w = true }
op.separator ''

op.separator 'Common options:'
op.on('-c', '--creds-profile=NAME', creds_help){ |value| options[:creds_profile] = value }
op.on('-s', '--state-file-path=PATH', state_help){ |value| options[:state_dir] = value }
op.on('-h', '--help')    { puts op.to_s; exit }
op.on('-v', '--version') { puts version; exit }
op.separator ''

op.parse!(ARGV)

require 'server' unless options[:action] == :help || options[:action] == :version

case options[:action]
when :help then puts op.to_s
when :version then puts Server::VERSION
else
  Server.run!(options)
end
