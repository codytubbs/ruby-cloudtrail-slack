#
# 01_send_email.rb
#
# Called from lib/server.rb (ruby-cloudtrail-slack v1.0.0)
#
# Author: Cody Tubbs (codytubbs@gmail.com) July 2017
#         https://github.com/codytubbs/ruby-cloudtrail-slack
#
# rubocop:disable LineLength # Comment to rid length warnings from `rubocop'

def send_email(reason, type, notes, email_from, email_to, mail_server, region, to)
  return if reason.to_s.empty? # Don't spam when exiting/killing the code.
  puts "region=[#{region}]\t[#{get_time}] Sending exception email for reason=[#{reason}]"
  hostname = Socket.gethostname
  message  = "From: ruby-cloudtrail-slack <#{email_from}>\n"
  message += "To: #{to} <#{email_to}>\n"
  message += "Subject: Ruby-CloudTrail-Slack Exception error occurred\n\n"
  message += "Current process name and location:\n"
  message += "Program name [#{$PROGRAM_NAME}] is located at [#{Dir.pwd}/.] on [#{hostname}]\n\n"
  # Possibly print IPs on the host to make locating it a bit easier, but is somewhat of an info leak:
  # Socket.ip_address_list.each{|x| print x.ip_address + ", "}
  message += "Thread region:\n"
  message += "#{region}\n\n"
  message += "Error type:\n"
  message += "#{type}\n\n"
  message += "Exception reason:\n"
  message += "#{reason}\n\n"
  message += "Notes from developer regarding this exception (if any):\n"
  message += "#{notes}\n"
  Net::SMTP.start(mail_server) do |smtp|
    smtp.send_message message, email_from, email_to
  end
end