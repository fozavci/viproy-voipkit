##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::SIP
  include Msf::Auxiliary::AuthBrute

	def initialize
    super(
        'Name'        => 'Viproy SIP Enumerator Module',
        'Version'     => '1',
        'Description' => 'Enumeration Module for SIP Services',
        'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
        'License'     => MSF_LICENSE
    )
	
		deregister_options('RHOSTS','USER_AS_PASS','USERPASS_FILE','PASS_FILE','PASSWORD','BLANK_PASSWORDS')

		register_options(
		[
			OptInt.new('NUMERIC_MIN',   [true, 'Starting extension',0]),
			OptInt.new('NUMERIC_MAX',   [true, 'Ending extension', 9999]),
			OptBool.new('NUMERIC_USERS',   [true, 'Numeric Username Bruteforcing', false]),
      OptString.new('METHOD',   [ true, "Method for Brute Force (SUBSCRIBE,REGISTER,INVITE)", "SUBSCRIBE"]),
      OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
      Opt::RHOST,
			Opt::RPORT(5060),
		], self.class)
		register_advanced_options(
		[
      Opt::CHOST,
      Opt::CPORT(5065),
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptString.new('TO',   [ false, "The destination username to probe at each host", "1000"]),
      OptString.new('FROM',   [ false, "The source username to probe at each host", "1000"]),
      OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
			OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
      OptBool.new('USER_AS_FROM_and_TO', [true, 'Use the Username for From and To fields', true]),
      OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
      OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
      OptBool.new('VERBOSE',   [ false, "Verbose Level", false]),
		], self.class)
	end
	def run
		if datastore['METHOD'] =~ /[SUBSCRIBE|REGISTER|INVITE]/
			method = datastore['METHOD']
		else
			print_error("Brute Force METHOD must be defined")
    end

		listen_addr = datastore['CHOST']
		listen_port = datastore['CPORT']
		dest_addr =datastore['RHOST']  
		dest_port = datastore['RPORT']
    proto = datastore['PROTO'].downcase
    vendor = datastore['VENDOR'].downcase
    macaddress = datastore['MACADDRESS']

    sipsocket_start(listen_port,listen_addr,dest_port,dest_addr,proto,vendor,macaddress)
    sipsocket_connect
    print_debug("Socket is connected.") if datastore['DEBUG']

    reported_users=[]

		if datastore['NUMERIC_USERS'] == true
			exts=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
			exts.each { |ext|
				ext=ext.to_s
				from=to=ext if datastore['USER_AS_FROM_and_TO']
				reported_users = do_login(ext,from,to,dest_addr,method,reported_users)
			}      
    else
      if datastore['USER_FILE'].nil?
        print_error("User wordlist is not provided.")
        return
      end
			each_user_pass { |user, password|
				from=to=user if datastore['USER_AS_FROM_and_TO']
				reported_users = do_login(user,from,to,dest_addr,method,reported_users)
			}
		end

    sipsocket_stop
	end
	def do_login(user,from,to,dest_addr,method,reported_users)
    realm = datastore['REALM']
    cred={
		    'login'     => false,	
		    'user'      => user,
		    'password'  => nil,
		    'realm'     => realm,
		    'from'      => from,
		    'to'        => to
		}

    print_debug("Enumeration method is #{method}.") if datastore['DEBUG']
    case method
    when "REGISTER"
			result,rdata,rdebug,rawdata = send_register(cred)
			possible = /^200/
		when "SUBSCRIBE"
			result,rdata,rdebug,rawdata = send_subscribe(cred)
			possible = /^40[0-3]|^40[5-9]|^200/
		when "OPTIONS"
			result,rdata,rdebug,rawdata = send_options(cred)
			possible = /^40[0-3]|^40[5-9]/
		when "INVITE"
			result,rdata,rdebug,rawdata = send_invite(cred)
			possible = /^40[0-3]|^40[5-9]|^200/
		end

		if rdata != nil and rdata['resp'] =~ possible
			user=rdata['from'].split("@")[0]

			if ! reported_users.include?(user)
				print_good("User #{user} is Valid (Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")})")
        vprint_status("Warning: #{rdata['warning']}") if rdata['warning']

				#Saving the user to DB
				#report_auth_info(
				#	:host	=> dest_addr,
				#	:port	=> datastore['RPORT'],
				#	:sname	=> 'sip',
				#	:user	=> user,
				#	:proof  => nil,
				#	:source_type => "user_supplied",
				#	:active => true
				#)
				reported_users << user	
			end
    else
			vprint_status("User #{user} is Invalid (#{rdata['resp_msg'].split(" ")[1,5].join(" ")})") if rdata !=nil
      vprint_status("\tWarning \t\t: #{rdata['warning']}\n") if ! rdata.nil? and rdata['warning']
    end

    printresults(result,rdata,rdebug,rawdata) if datastore['DEBUG']

    return reported_users
  end
end

