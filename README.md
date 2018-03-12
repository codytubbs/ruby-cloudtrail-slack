
# ruby-cloudtrail-slack v1.0.0 [2017-07]

   Looks up and pushes to [Slack][1] the API activity events captured by [AWS CloudTrail][2] that *create*, *update*, or *delete*
   resources in your account. Events for a [region][3] can be looked up for the times in which you had CloudTrail
   turned on in that region during the last seven days.  
   **It takes ~10 minutes for *CloudTrail* to populate events that occur, so expect a ~10 minute delay from the
   time of event to the time of *Slack* message.**

## Semi-technical information
   The default number of results returned per API call is set to 50, which is the [maximum possible count][4].
   The result response includes a token that can used to get the next page of results (1-50).
   The rate of lookup requests is limited to one per second per account. If this limit is exceeded,
   a throttling error is received by the server.rb. Proper sleeps are in place to avoid server-side
   throttling. Somewhat proper exception handling and notification is in place as well.

## Requirements and AWS Configuration
1. **Configure AWS CloudTrail Resource**  
(Requirement 1 of 3)
    - From your [AWS web console portal][5], click the **Services** drop down. Then under **Management Tools**, click **[CLoudTrail][6]**    
    - From your CloudTrail Dashboard, click **View Trails**
    - Next click **Create Trail**  
    - Choose a Trail name. it's irrelevant to this code, but choose something you'll recognize. e.g. *ruby-cloudtrail-slack* 
    - Under *Create Trail*, select **_Yes_** for **Apply trail to all regions**  
    - Under the trail **Management events**, choose **_Write-only_** for the **Read/Write events** option  
    - For specific (or all) S3 buckets and/or Lambda data events, I **do not** select to monitor these. I **do not** choose **select all S3 buckets in your account**. You can select
    buckets/lambdas if you wish, just ensure you aren't setting yourself up for an overload of messages for every S3 read/write, etc. These messages (data events) have not yet been tested.  
    - Under **Storage location** choose **_Yes_** for **Create a new S3 bucket**. Again, name it whatever you please, but something you'll recognize. e.g. *ruby-cloudtrail-slack*
    
    - The trail should be configured to monitor **write changes** only, this is how the codebase was tested 
      - In summary, what you're basically doing is having the CloudTrail console dashboard start populating itself with data events. These events are what the API calls from this code can see, parse, format, and send to Slack.

2. **Create AWS CloudTrail Access (IAM: User, Role, and Access Key)**  
(Requirement 2 of 3)
    - Via IAM, create a user with access to only the **ViewOnlyAccess** role (or possibly just **AWSCloudTrailReadOnlyAccess**)
    - Create an *Access Key* for this user and its singular role access.  Within the AWS credentials file that this script uses (as defined below), use the access key for the given profile name passed during execution

3. **(Properly) Define AWS Credentials**  
(Requirements 3 of 3)
    - Ensure to have a valid entry in ~/.aws/credentials with a proper access key  
    Execute `bin/server.rb` with `-h` for profile options. (Defaults to 'default' profile.)

## Installation

`$ echo "gem: --user-install" >> ~/.gemrc # if need be`  
`$ gem install aws-sdk slack-notifier OptionParser`  

 - Optional (for process monitoring/restarting via GOD - [http://godrb.com][7]):  
   `$ [sudo] gem install god`  
 - See below for details on how to daemonize with GOD. A script is included

## Script Configuration

  1. Prior to execution, modify the variables in the "**MODIFY VARIABLES - [START HERE]**" section in `lib/server.rb`  
  This is where all of your settings live, for example, your email to/from addresses and name, your mail server, the Slack webhook URL, and the Slack channel name.  

  2. Also, feel free to exclude the log file after successfully executing via one of the methods below.
  The script will send emails upon failure.  Turn on logging for debugging only, or remove some of the prints to limit
  the speed of file growth (currently verbose++)

## Execution (3 possible methods)

1. Method one [in the foreground, for testing proper configuration]:  
    - `$ bin/server.rb -Ilib --creds-profile=default`  
  
2. Method two [daemonized]:  
    - `$ bin/server.rb -Ilib -d`  
    - ... or with arguments (for example, non-default credentials):
    - `$ bin/server.rb -Ilib -d -p /tmp/ruby-cloudtrail-slack.pid -l /tmp/ruby-cloudtrail-slack.log -c not_default`  
    
3. Method three [daemonized via the GOD monitoring application] (preferred):
    - **Note**: If you want to ensure the script restarts when killed, or upon death in general, execute via GOD.

      1. `$ [sudo] gem install god` # as noted above in the installation section  
         - If `gem install` fails, first try: `$ sudo apt-get install build-essential ruby-dev`  
      2. Edit path variables at the top of `ruby-cloudtrail-slack.god`
      3. Now, first test via GOD in the foreground and ensure it's configured properly  
      `$ god -c ./ruby-cloudtrail-slack.god -D`  
      4. Once working in the foreground, stop the process
      5. Now execute *without* `-D`, to run the GOD script in the background:  
      `$ god -c ./ruby-cloudtrail-slack.god`
      6. while `tail -f`'ing the configured and defined log file:  
      ```$ kill -QUIT `cat <path_to_pid_file>` ``` and
      ensure GOD properly restarts the *ruby-cloudtrail-slack* `bin/server.rb`  
      It should catch the *QUIT signal* and shut down gracefully within about 30 to 60 seconds

## State file naming convention
 .[credential_profile_name].[aws_region].cloudtrail.state  
 - Don't bother these if possible. They keep record of the last event time from each region.  They attempt to prevent duplicate events from
  being sent when a few cases arise e.g. restarting the script, reaching token caps, (un)throttling, etc.


## TODO
1. Via the cloudtrail API, run a monitor to continuously check if the trail that allows this code to work:  
   1. Has access to all regions, and (upon change) alert if not  
   2. Has been removed, or become inaccessible, via permissions, etc. e.g. a possible sign of an accidental misconfiguration, a hack, or other nefarious activity
2. Test and send S3 bucket creation / deletion events (and possibly a whitelist of object keys)  
3. Test and send specific (pre-defined) lambda events  

##

Author :: Cody Tubbs :: (codytubbs+rcs@gmail.com)  
[https://github.com/codytubbs/ruby-cloudtrail-slack][98]  
[https://github.com/codytubbs][99]


[1]: https://slack.com
[2]: https://aws.amazon.com/cloudtrail/
[3]: https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/
[4]: https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/CloudTrail/Client.html#lookup_events-instance_method
[5]: https://us-west-2.console.aws.amazon.com/console/home?region=us-west-2
[6]: https://us-west-2.console.aws.amazon.com/cloudtrail/home?region=us-west-2#/dashboard
[7]: http://godrb.com
[98]: https://github.com/codytubbs/ruby-cloudtrail-slack
[99]: https://github.com/codytubbs