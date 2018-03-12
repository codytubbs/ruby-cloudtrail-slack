#
# 00_state_file.rb
#
# Called from lib/server.rb (ruby-cloudtrail-slack v1.0.0)
#
# Author: Cody Tubbs (codytubbs@gmail.com) July 2017
#         https://github.com/codytubbs/ruby-cloudtrail-slack
#
# rubocop:disable LineLength # Comment to rid length warnings from `rubocop'

def check_state(filename, region, state_dir)
  # First, check if File exists, create if not.
  # Use File.open with block to handle fd lifetime. (flush/close)
  puts "region=[#{region}]\t[#{get_time}] Checking for file [#{state_dir}/#{filename}]"
  if File.file?("#{state_dir}/#{filename}") # file? = files only, exist? = files/dirs
    puts "region=[#{region}]\t[#{get_time}] [#{state_dir}/#{filename}] exists... not creating"
  else
    puts "region=[#{region}]\t[#{get_time}] [#{state_dir}/#{filename}] does not exists... creating."
    File.open("#{state_dir}/#{filename}", 'w') do |file|
      file.write('latest_event_time=')
    end
  end
end

def update_state(filename, latest_event_time, region, state_dir)
  check_state(filename, region, state_dir)
  puts "region=[#{region}]\t[#{get_time}] Updating file=[#{state_dir}/#{filename}] with latest_event_time=[#{latest_event_time}]"
  position = 0 # Always modify first line.
  File.open("#{state_dir}/#{filename}", 'r+') do |file|
    file.each do |line|
      file.pos = position
      file.print line.gsub(/=.*$/, "=#{latest_event_time}")
    end
  end
end

def read_state(filename, region, state_dir)
  latest_event_time = String.new
  line_count        = 0
  check_state(filename, region, state_dir)
  IO.foreach("#{state_dir}/#{filename}") do |file|
    puts "region=[#{region}]\t[#{get_time}] [#{state_dir}/#{filename}] file output line ##{line_count+=1}: #{file}"
    puts "region=[#{region}]\t[#{get_time}] [#{state_dir}/#{filename}] checking for latest_event_time"
    if file =~ /^latest_event_time=(.*)$/
      puts "region=[#{region}]\t[#{get_time}] [#{state_dir}/#{filename}] last event time = [#{$1}]"
      latest_event_time = $1
    else
      puts "region=[#{region}]\t[#{get_time}] [#{state_dir}/#{filename}] file exists but latest_event_time not found."
      #latest_event_time = ''
    end
  end
  latest_event_time
end