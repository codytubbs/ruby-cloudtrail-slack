#
# A part of ruby-cloudtrail-slack v1.0.0
#
# Read README.md for details and change the below paths to fit the location of this project.
#
# Author: Cody Tubbs :: codytubbs@gmail.com :: July 2017
#         https://github.com/codytubbs/ruby-cloudtrail-slack
#

path_to_server = '/home/CHANGEME/ruby-cloudtrail-slack/bin/server.rb'
path_to_pid    = '/tmp/ruby-cloudtrail-slack.pid'
path_to_log    = '/tmp/ruby-cloudtrail-slack.log'
path_to_lib    = '/home/CHANGEME/ruby-cloudtrail-slack/'
path_to_states = '/home/CHANGEME/ruby-cloudtrail-slack'

God.watch do |w|
  w.name            = 'ruby-cloudtrail-slack'
  w.interval        = 60.seconds
  w.start           = "ruby #{path_to_server} -I#{path_to_lib}lib -d -p #{path_to_pid} -l #{path_to_log} -s #{path_to_states}"
  w.stop            = "kill -QUIT `cat #{path_to_pid}`"
  w.start_grace     = 20.seconds
  w.restart_grace   = 60.seconds
  w.stop_grace      = 60.seconds
  w.pid_file        = "#{path_to_pid}"

  #w.uid = ''
  #w.gid = ''

  w.behavior(:clean_pid_file)

  w.start_if do |start|
    start.condition(:process_running) do |c|
      c.interval = 5.seconds
      c.running = false
    end
  end
end