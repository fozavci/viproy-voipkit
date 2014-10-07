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

	def initialize
		super(
			'Name'        => 'Viproy SIP Register Module',
			'Version'     => '1',
			'Description' => 'Register Discovery Module for SIP Services',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptString.new('USERNAME',   [ false, "The login username to probe at each host"]),
			OptString.new('PASSWORD',   [ false, "The login password to probe at each host"]),
			OptString.new('TO',   [ false, "The destination username to probe at each host", "1000"]),
			OptString.new('FROM',   [ false, "The source username to probe at each host", "1000"]),
			OptBool.new('LOGIN', [false, 'Login Using Credentials', false]),
      OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
			Opt::RPORT(5060),

		], self.class)

		register_advanced_options(
		[
      Opt::CHOST,
      Opt::CPORT(5065),
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
      OptBool.new('DEREGISTER', [false, 'De-Register After Successful Login', false]),
      OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
      OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
      OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
      OptBool.new('USEREQFROM',   [ false, "FROM will be cloned from USERNAME", true]),
    ], self.class)
	end
	
	def run_host(dest_addr)
		# Login parameters
		user = datastore['USERNAME']
		password = datastore['PASSWORD']
		realm = datastore['REALM']
    from = datastore['FROM']
    to = datastore['TO']

    # Socket parameters
		listen_addr = datastore['CHOST']
		listen_port = datastore['CPORT']
		dest_port = datastore['RPORT']
    proto = datastore['PROTO'].downcase
    vendor = datastore['VENDOR'].downcase
    macaddress = datastore['MACADDRESS']


    sipsocket_start(listen_port,listen_addr,dest_port,dest_addr,proto,vendor,macaddress)
    sipsocket_connect

    if vendor == 'mslync'
      result,rdata,rdebug,rawdata = send_negotiate(
          'realm'		  => realm,
          'from'      => from,
          'to'    	  => to
      )
      printresults(result,rdata,rdebug,rawdata)
    end

    result,rdata,rdebug,rawdata = send_register(
        'login'  	    => datastore['LOGIN'],
        'user'      	=> user,
        'password'	  => password,
        'realm'		    => realm,
        'from'    	  => from,
        'to'    	    => to
    )


    printresults(result,rdata,rdebug,rawdata,"register",user,password)

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

    sipsocket_stop

  end


end

