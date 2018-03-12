#!/usr/bin/env ruby
#
# lib/server.rb (ruby-cloudtrail-slack v1.0.0)
# Called from bin/server.rb
#
# Read README.md for details.
#
# Author: Cody Tubbs (codytubbs@gmail.com) July 2017
#         https://github.com/codytubbs/ruby-cloudtrail-slack
#
#
###############################################################################
# Attempts to follow strict Ruby Style Guidelines enforced by `Rubocop'
# rubocop:disable LineLength # Comment to rid line length warnings >80
# rubocop:disable Metrics/ParameterLists

require 'rubygems'
require 'aws-sdk'
require 'aws-sdk-core'
require 'aws-sdk-resources'
require 'slack-notifier'
require 'optparse'
require 'json'
require 'date'
require 'thwait'
require 'socket'
require 'net/smtp'
require 'fileutils'

require_relative '00_state_file'
require_relative '01_send_email'

class Server
  VERSION = '1.0.0'

  def self.run!(options)
    Server.new(options).run!
  end

  attr_reader :options, :quit

  def initialize(options)
    @options = options
    # daemonizing will change CWD, so expand any relative paths in advance
    options[:logfile] = File.expand_path(logfile) if logfile?
    options[:pidfile] = File.expand_path(pidfile) if pidfile?
  end

  def daemonize?
    options[:daemonize]
  end

  def logfile
    options[:logfile]
  end

  def pidfile
    options[:pidfile]
  end

  def logfile?
    !logfile.nil?
  end

  def pidfile?
    !pidfile.nil?
  end

  def info(msg)
    puts "[#{Process.pid}] [#{Time.now}] #{msg}"
  end


  def run!
    check_pid
    daemonize if daemonize?
    write_pid
    trap_signals

    if logfile?
      redirect_output
    elsif daemonize?
      suppress_output
    end

    until quit do # [1] infinite loop until kill -QUIT

      # MODIFY VARIABLES - [START HERE]
      email_from       = 'ruby-cloudtrail-slack@local.host'
      email_to         = 'your_team+ruby-cloudtrail-slack@your_domain.com'
      to_name          = 'AWS Monitoring Team'
      mail_server      = 'mail.host'
      webhook_url      = 'https://hooks.slack.com/services/XXX/XXX/XXX'
      channel          = 'ruby-cloudtrail-slack'
      # MODIFY VARIABLES - [STOP HERE], unless you know what you're doing

      # Updated as of July 2017
      regions = %w[us-east-1
                   us-east-2
                   us-west-1
                   us-west-2
                   ca-central-1
                   eu-central-1
                   eu-west-1
                   eu-west-2
                   ap-southeast-1
                   ap-southeast-2
                   ap-northeast-1
                   ap-northeast-2
                   ap-south-1
                   sa-east-1]

      regions = %w[us-west-2] if $DEBUG # Only if --debug is used when calling bin/server.rb

      slack_name       = 'AWS-CloudTrail Webhook'
      max_results      = 50 # Current limit set by AWS / SDK/API v2 is 50 (as of July 2017)
      localize_time    = true
      region_count     = regions.length
      credentials_file = "#{ENV['HOME']}/.aws/credentials"
      creds_profile    = options[:creds_profile]
      state_dir        = options[:state_dir]
      creds            = Aws::SharedCredentials.new(path: credentials_file, profile_name: creds_profile)

      Thread.abort_on_exception = false
      thread_group              = ThreadsWait.new


      def get_time # Return Time.now without time zone
        Time.now.strftime('%Y-%m-%d %H:%M:%S')
      end

      def task(region,
               localize_time,
               webhook_url,
               channel,
               creds,
               region_count,
               max_results,
               slack_name,
               creds_profile,
               state_dir)
        cloudtrail        = Aws::CloudTrail::Client.new(credentials: creds, region: region)
        notifier          = Slack::Notifier.new(webhook_url, channel: channel, username: slack_name)
        next_token        = String.new
        latest_event_time = String.new # TODO: Mess with Time.new later
        grouped_responses = Array.new
        filename          = ".#{creds_profile}.#{region}.cloudtrail.state"
        has_token         = false

        #raise("Thread: region=[#{region}] raised to test fatal handling/email.") if region == 'us-west-2' #and $DEBUG

        # Grab latest_event_time from state file, if exists.
        # check if state file exists, create if not.
        # TODO: check if state file has correct format, re-create/format if not.
        puts "region=[#{region}]\t[#{get_time}] Reading file=[#{filename}]"
        latest_event_time = read_state(filename, region, state_dir)

        until quit do # [2] infinite loop until kill -QUIT
          sleep region_count * 2 # Prevent being rate limited. TODO: Raise to region count * 2 after testing. [DONE]

          if !has_token # has_token == false (always matches for initial cycle of code as well)
            if latest_event_time.empty? # latest_event_time is nil
              puts "region=[#{region}]\t[#{get_time}] has_token=[false], latest_event_time=[nil], lookup with Time - 20 mins"
              # CloudTrail takes ~10 minutes to populate events from when they occurred to when viewable.
              response = cloudtrail.lookup_events(start_time: Time.now - 60 * 20, # 20 minutes #- 60 * 1440, # Minus 24 hours
                                                  max_results: max_results)
              puts "region=[#{region}]\t[#{get_time}] response.events.length = [#{response.events.length}]"
              # Check for next_token
              if response.next_token.to_s.empty?
                puts "region=[#{region}]\t[#{get_time}] next_token was empty."
                has_token = false
                # Go to print_event_data() if response.events.length >= 1
                if response.events.length >= 1
                  puts "region=[#{region}]\t[#{get_time}] adding response to grouped_responses from [has_token == false]"
                  grouped_responses.concat response.events.to_a
                  puts "region=[#{region}]\t[#{get_time}] grouped_responses.length = #{grouped_responses.length}"
                  puts "region=[#{region}]\t[#{get_time}] GOING TO print_event_data() from [has_token == false]"
                  latest_event_time = print_event_data(region,
                                                       grouped_responses,
                                                       localize_time,
                                                       webhook_url,
                                                       channel,
                                                       slack_name,
                                                       latest_event_time)
                  puts "region=[#{region}]\t[#{get_time}] Updating state file=[#{filename}] with [#{latest_event_time}]"
                  update_state(filename, latest_event_time, region, state_dir)
                  grouped_responses.clear # truncate after printing!
                  puts "region=[#{region}]\t[#{get_time}] *clean* next iteration"
                  next
                else
                  puts "region=[#{region}]\t[#{get_time}] print_event_data() location but events are nil && !has_token, next"
                  next
                end
              else
                next_token = response.next_token
                has_token = true
                # The very first event (no latest_event_time) with a token will reach this area
                puts "region=[#{region}]\t[#{get_time}] next_token was not empty."
                puts "region=[#{region}]\t[#{get_time}] next_token=[#{next_token}]"
                puts "region=[#{region}]\t[#{get_time}] adding response to grouped_responses from [next_token not nil]"
                # append responses and iterate until next_token is empty
                grouped_responses.concat response.events.to_a
                puts "region=[#{region}]\t[#{get_time}] grouped_responses.length = #{grouped_responses.length}"
                puts "region=[#{region}]\t[#{get_time}] next iteration"
                next
              end
            else # latest_event_time is NOT nil and has_token == false
              puts "region=[#{region}]\t[#{get_time}] latest_event_time [#{latest_event_time}] is NOT nil"
              d = DateTime.parse("#{latest_event_time}", '%I:%M %p') # Leave off %Z
              d = d + (1.0/(24*60*60)) # Add one second!
              start_time = d.strftime('%Y-%m-%d %H:%M:%S') # Leave off %z
              puts "region=[#{region}]\t[#{get_time}] start_time = [#{start_time}]"
              start_time = Time.parse(start_time) # Convert from Class String to Class Time
              # START X
              puts "region=[#{region}]\t[#{get_time}] executing lookup with start_time=[#{start_time}]"
              response = cloudtrail.lookup_events(start_time: start_time, # start_time is the latest_event_time + 1 sec.
                                                  max_results: max_results)
              puts "region=[#{region}]\t[#{get_time}] response.events.length = [#{response.events.length}]"
              # Check for next_token
              if response.next_token.to_s.empty?
                puts "region=[#{region}]\t[#{get_time}] next_token was empty."
                has_token = false
                # Go to print_event_data() if response.events.length >= 1
                if response.events.length >= 1
                  puts "region=[#{region}]\t[#{get_time}] adding response to grouped_responses from [latest_event_time NOT nil & has_token == false]"
                  grouped_responses.concat response.events.to_a
                  puts "region=[#{region}]\t[#{get_time}] grouped_responses.length = #{grouped_responses.length}"
                  puts "region=[#{region}]\t[#{get_time}] Going to print_event_data() from [latest_event_time NOT nil & has_token == false]"
                  latest_event_time = print_event_data(region,
                                                       grouped_responses,
                                                       localize_time,
                                                       webhook_url,
                                                       channel,
                                                       slack_name,
                                                       latest_event_time)
                  puts "region=[#{region}]\t[#{get_time}] Updating state file=[#{filename}] with [#{latest_event_time}]"
                  update_state(filename, latest_event_time, region, state_dir)
                  grouped_responses.clear # truncate after printing@
                  puts "region=[#{region}]\t[#{get_time}] *clean* next iteration"
                  next
                else
                  puts "region=[#{region}]\t[#{get_time}] print_event_data() point but events are nil [has_token == false], next"
                  next
                end
              else
                next_token = response.next_token
                has_token = true
                puts "region=[#{region}]\t[#{get_time}] latest_event_time is NOT nil [#{latest_event_time}] && next_token was not empty."
                puts "region=[#{region}]\t[#{get_time}] next_token=[#{next_token}]"
                # First event (no latest_event_time) with a token will reach this area
                puts "region=[#{region}]\t[#{get_time}] adding response to grouped_responses from [next_token not nil]"
                # append responses and iterate until next_token is empty
                grouped_responses.concat response.events.to_a
                puts "region=[#{region}]\t[#{get_time}] grouped_responses.length = #{grouped_responses.length}"
                puts "region=[#{region}]\t[#{get_time}] next iteration"
                next
              end
              # END of START X
            end
          else # has_token == true
            puts "region=[#{region}]\t[#{get_time}] *-- has_token = [TRUE]"
            puts "region=[#{region}]\t[#{get_time}] executing lookup with next_token=[#{next_token}]"
            response = cloudtrail.lookup_events(max_results: max_results,
                                                next_token: next_token)
            puts "region=[#{region}]\t[#{get_time}] response.events.length = [#{response.events.length}]"
            #puts response
            if response.next_token.to_s.empty?
              puts "region=[#{region}]\t[#{get_time}] next_token was empty."
              has_token = false
              # Go to print_event_data() if response.events.length >= 1
              if response.events.length >= 1
                puts "region=[#{region}]\t[#{get_time}] adding response to grouped_responses from [has_token == true]"
                grouped_responses.concat response.events.to_a
                puts "region=[#{region}]\t[#{get_time}] GOING TO print_event_data() from [has_token == true]"
                latest_event_time = print_event_data(region, grouped_responses,
                                                     localize_time,
                                                     webhook_url,
                                                     channel,
                                                     slack_name,
                                                     latest_event_time)
                puts "region=[#{region}]\t[#{get_time}] Updating state file=[#{filename}] with [#{latest_event_time}]"
                update_state(filename, latest_event_time, region, state_dir)
                grouped_responses.clear # truncate after printing!
                puts "region=[#{region}]\t[#{get_time}] *clean* next iteration"
                next
              else
                puts "region=[#{region}]\t[#{get_time}] print_event_data() point but events are nil [has_token == true]"
                next
              end
            else
              next_token = response.next_token
              puts "region=[#{region}]\t[#{get_time}] has_token = [#{next_token}]"
              # append responses until no more next_token, so we can reverse order and print in order of oldest to latest
              puts "region=[#{region}]\t[#{get_time}] adding response to grouped_responses from [has_token == true]"
              grouped_responses.concat response.events.to_a
              puts "region=[#{region}]\t[#{get_time}] grouped_responses.length = #{grouped_responses.length}"
              puts "region=[#{region}]\t[#{get_time}] Iterating to next_token before printing, until next_token is nil! next"
              next
            end
          end
        end
      end

      def print_event_data(region,
                           grouped_responses,
                           localize_time,
                           webhook_url,
                           channel,
                           slack_name,
                           latest_event_time)
        notifier  = Slack::Notifier.new(webhook_url, channel: channel, username: slack_name)
        responses = grouped_responses.length
        ct_count  = 0

        if responses >= 1
          puts "region=[#{region}] responses = [#{responses}]"
          grouped_responses.reverse.each do |event|
            slack_body_resources = { fields: [] } # Reset Hash content for next iteration
            event_id = event['event_id']
            event_name = event['event_name']
            next if event_name == 'ConsoleLogin' # TODO: Turn this into an Array once more exclusions exist...
            if localize_time # localize_time == true
              # Convert event_time to localhost timezone TODO: add option for specific timezone in config options?
              event_time = Time.parse(event['event_time'].to_s).localtime.strftime('%Y-%m-%d %H:%M:%S')
            else # localize_time == false
              event_time = event['event_time'].strftime('%Y-%m-%d %H:%M:%S')
            end

            if event_time.to_s > latest_event_time.to_s
              latest_event_time = event_time.to_s
              puts "region=[#{region}]\t[#{get_time}] Updated latest_event_time=[#{latest_event_time}] with current event event_time"
            else
              puts "region=[#{region}]\t[#{get_time}] Not updating latest_event_time with current event_time, not newer"
            end

            username = event['username']
            resources = event[:resources] # TODO: Check this
            cloud_trail_event = event['cloud_trail_event']

            puts "region=[#{region}]\t[#{get_time}] * Event = [#{ct_count}]"
            puts "region=[#{region}]\t[#{get_time}]\tevent_id = [#{event_id}]"
            puts "region=[#{region}]\t[#{get_time}]\tevent_name = [#{event_name}]"
            puts "region=[#{region}]\t[#{get_time}]\tevent_time = [#{event_time}]"
            puts "region=[#{region}]\t[#{get_time}]\tusername = [#{username}]"

            response_count = 1

            resources.each do |resource|
              resource_type = resource['resource_type']
              resource_name = resource['resource_name']
              puts "region=[#{region}]\t[#{get_time}]\tResource = [#{response_count}]"
              puts "region=[#{region}]\t[#{get_time}]\t\tresource_type = [#{resource_type}]"
              puts "region=[#{region}]\t[#{get_time}]\t\tresource_name = [#{resource_name}]"
              slack_body_resources[:fields].push({title: "Resource Type [#{response_count} of @@_RESOURCE_COUNT_@@]",
                                                  value: "#{resource_type}",
                                                  short: true})
              slack_body_resources[:fields].push({title: 'Resource Name',
                                                  value: "#{resource_name}",
                                                  short: true})

              response_count += 1
            end

            puts "region=[#{region}]\t[#{get_time}]\tEvent body (summarized):"
            parsed = JSON.parse(cloud_trail_event)
            puts parsed if $DEBUG
            trail_user_identity_type = parsed['userIdentity']['type'].downcase
            trail_user_identity_username = parsed['userIdentity']['userName']
            trail_account_id = parsed['userIdentity']['accountId']
            trail_event_source = parsed['eventSource']
            trail_aws_region = parsed['awsRegion']
            trail_source_ip_address = parsed['sourceIPAddress']
            trail_user_agent = parsed['userAgent']
            trail_event_type = parsed['eventType']

            puts "region=[#{region}]\t[#{get_time}]\t\tuserIdentity.type = [#{trail_user_identity_type}]"
            puts "region=[#{region}]\t[#{get_time}]\t\tuserIdentity.userName = [#{trail_user_identity_username}]"
            puts "region=[#{region}]\t[#{get_time}]\t\teventSource = [#{trail_event_source}]"
            puts "region=[#{region}]\t[#{get_time}]\t\tawsRegion = [#{trail_aws_region}]"
            puts "region=[#{region}]\t[#{get_time}]\t\tsourceIPAddress = [#{trail_source_ip_address}]"
            puts "region=[#{region}]\t[#{get_time}]\t\tuserAgent = [#{trail_user_agent}]"
            puts "region=[#{region}]\t[#{get_time}]\t\teventType = [#{trail_event_type}]"
            puts "region=[#{region}]\t[#{get_time}]\t\t[Click here to view full body] TODO: create link"

            ct_count += 1
            puts
            # Start slack notifier here...
            # Set color. Also supports HEX.
            if event_name.include?('Delete')
              color = 'danger'
            elsif event_name.include?('Terminate')
              color = 'warning'
            else
              color = 'good'
            end
            if trail_user_identity_username == nil
              # TODO: compare username and trail_user_identity_type when trail_user_identity_username is nil
              msg_head = "*#{event_name}* from *#{username}*" # from *#{trail_user_identity_type}*"
              trail_user_identity_username = username # for the slack_msg_body field below.
            else
              # Use trail_user_identity_type rather than username until trail_user_identity_type is found to be nil
              # TODO: compare username and trail_user_identity_type
              #msg_head = "*#{event_name}* from type[*#{username}*], username[*#{trail_user_identity_username}*]"
              msg_head = "*#{event_name}* from type=[*#{trail_user_identity_type}*], username=[*#{trail_user_identity_username}*]"
            end
            msg_console_link_attachment = "<https://#{region}.console.aws.amazon.com/cloudtrail/home?region=#{region}|Open CloudTrail Console>"
            slack_msg_body = { fallback: "#{msg_console_link_attachment}",
                               #pretext: "#{msg_head}",
                               text: "#{msg_console_link_attachment}",
                               color: "#{color}",
                               fields: [{ title: 'Event Name',
                                          value: "#{event_name}",
                                          short: true
                                        },
                                        { title: 'Event Source',
                                          value: "#{trail_event_source}",
                                          short: true
                                        },
                                        { title: 'AWS Region',
                                          value: "#{trail_aws_region}",
                                          short: true
                                        },
                                        { title: 'Event Time',
                                          value: "#{event_time}",
                                          short: true
                                        },
                                        { title: 'User Name',
                                          value: "#{trail_user_identity_username}",
                                          short: true
                                        },
                                        { title: 'Source IP Address',
                                          value: "#{trail_source_ip_address}",
                                          short: true
                                        },
                                        { title: 'Account ID',
                                          value: "#{trail_account_id}",
                                          short: true
                                        },
                                        { title: 'Event Type',
                                          value: "#{trail_event_type}",
                                          short: true
                                        }
                                     ]
            }
            # Push event resource(s) into the slack_msg_body if not nil
            if slack_body_resources[:fields].length >= 1
              slack_body_resources[:fields].each { |resource|
                # replacing @@_RESOURCE_COUNT_@@ template string with actual response_count
                resource[:title].gsub!('@@_RESOURCE_COUNT_@@', (response_count-1).to_s)
                slack_msg_body[:fields].push(resource)
              }
            end
            slack_msg_body[:fields].push({title: 'User Agent', value: "#{trail_user_agent}", short: false})
            slack_msg_body[:fields].push({title: 'Event ID', value: "#{event_id}", short: false})
            notifier.post text: "#{msg_head}", attachments: [slack_msg_body]
            # End slack notifier here.
          end
        end
        latest_event_time # Return latest
      end

      def go(region,
             localize_time,
             webhook_url,
             channel,
             creds,
             region_count,
             max_results,
             slack_name,
             creds_profile,
             email_from,
             email_to,
             mail_server,
             state_dir,
             to)
        fail_reason = String.new
        until quit do # [3] infinite loop until kill -QUIT
          sleep 1 # Starts each thread equally staggered... how they end up later is a different reality.
          begin
            task(region,
                 localize_time,
                 webhook_url,
                 channel,
                 creds,
                 region_count,
                 max_results,
                 slack_name,
                 creds_profile,
                 state_dir)
          rescue => fail_reason
            puts "[#{region}] Thread fail_reason=[#{fail_reason}]"
            sleep 1 # Breathe upon exception
            if fail_reason =~ /Rate exceeded/ # Go back in if we reached our limit somehow, after sleeping.
              notes = 'CloudTrail api calls are too fast, debug and/or add more time to sleeps'
              type  = 'exception'
              send_email(fail_reason, type, notes, email_from, email_to, mail_server, region, to)
              puts "[#{region}]\t[#{get_time}] Thread sleeping for 60 seconds"
              sleep 60 # Breathe
              next # Should be okay to iterate back in after sleeping, for now.
            end
            if fail_reason =~ /No such file or directory @ rb_sysopen - .(\S?).cloudtrail.state/
              notes = 'fs error? disk space? race condition? multiple processes?'
              type  = 'exception'
              send_email(fail_reason, type, notes, email_from, email_to, mail_server, region, to)
              puts "[#{region}]\t[#{get_time}] Thread sleeping for 10 minutes"
              sleep 1200 # 10 minutes. Breathe
              next # For now
            end
          ensure
            puts fail_reason unless fail_reason.empty? # Usually empty due to ctrl-c to exit
            # TODO: Send email to someone about the thread fail reason
            type  = 'unknown / fatal'
            notes = 'none, please investigate'
            send_email(fail_reason, type, notes, email_from, email_to, mail_server, region, to)
            puts "[#{region}]\t[#{get_time}] Thread sleeping for 10 minutes" unless fail_reason.empty?
            sleep 1200 unless fail_reason.empty? # 10 minutes. Breathe
            # TODO: add possible closure if nth time is reached in x amount of time?
            next unless fail_reason.empty?
          end
        end
      end

      regions.length.times { |i| # Start a thread for each region and call go()
        sleep 1
        # Create a tmpThread that will immediately get pushed in to the thread_group, then repeat
        tmp_thread = Thread.new(i){ |index|
          puts "Thread number=[#{index}] region=[#{regions[index]}] started"
          while regions.length > 0 do
            go(regions[index],
               localize_time,
               webhook_url,
               channel,
               creds,
               region_count,
               max_results,
               slack_name,
               creds_profile,
               email_from,
               email_to,
               mail_server,
               state_dir,
               to_name)
            regions.delete(regions[index]) # Delete region from task pool.
          end
        }
        thread_group.join_nowait(tmp_thread)
      }
      puts thread_group.all_waits
    end
    info 'Finished'
  end

  def daemonize
    exit if fork
    Process.setsid
    exit if fork
    Dir.chdir '/'
  end

  # Output redirection
  def redirect_output
    FileUtils.mkdir_p(File.dirname(logfile), :mode => 0755)
    FileUtils.touch logfile
    File.chmod(0644, logfile)
    $stderr.reopen(logfile, 'a')
    $stdout.reopen($stderr)
    $stdout.sync = $stderr.sync = true
  end

  def suppress_output
    $stderr.reopen('/dev/null', 'a')
    $stdout.reopen($stderr)
  end

  # PID management
  def write_pid
    if pidfile?
      begin
        File.open(pidfile, ::File::CREAT | ::File::EXCL | ::File::WRONLY){|f| f.write("#{Process.pid}") }
        at_exit { File.delete(pidfile) if File.exists?(pidfile) }
      rescue Errno::EEXIST
        check_pid
        retry
      end
    end
  end

  def check_pid
    if pidfile?
      case pid_status(pidfile)
      when :running, :not_owned
        puts "A server is already running. Check #{pidfile}"
        exit(1)
      when :dead
        File.delete(pidfile)
      else
        nil
      end
    end
  end

  def pid_status(pidfile)
    return :exited unless File.exists?(pidfile)
    pid = ::File.read(pidfile).to_i
    return :dead if pid == 0
    Process.kill(0, pid)
    :running
  rescue Errno::ESRCH
    :dead
  rescue Errno::EPERM
    :not_owned
  end

  # Signal handling
  def trap_signals
    trap(:QUIT) do # graceful shutdown
      puts "\n\n*** Received kill -QUIT, attempting to shutdown gracefully... ~30 seconds.\n\n"
      @quit = true # stops the infinite loops by setting quit=true and gracefully terminates.
    end
  end
end

