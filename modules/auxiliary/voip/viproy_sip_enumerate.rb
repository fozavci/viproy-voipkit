##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::SIP
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
        'Name'        => 'Viproy SIP Enumerator Module',
        'Version'     => '1',
        'Description' => 'Enumeration Module for SIP Services',
        'Author'      => ['fozavci', 'carchimandritis'],
        'License'     => 'GPL'
    )

    deregister_options('USER_AS_PASS','USERPASS_FILE','PASS_FILE','PASSWORD','BLANK_PASSWORDS', 'CPORT')

    register_options(
        [
            OptInt.new('NUMERIC_MIN',   [true, 'Starting extension',0]),
            OptInt.new('NUMERIC_MAX',   [true, 'Ending extension', 9999]),
            OptBool.new('NUMERIC_USERS',   [true, 'Numeric Username Bruteforcing', false]),
            OptString.new('METHOD',   [ true, "Method for Enumeration (SUBSCRIBE,REGISTER,INVITE,OPTIONS)", "SUBSCRIBE"]),
            OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
            OptString.new('RESPONSEREGEX',   [ false, "Regular expression for responses e.g. ^40[0-3]|^40[5-9]"]),
            Opt::RPORT(5060),
        ], self.class)

    register_advanced_options(
        [
            OptString.new('PRENUMERIC',   [ false, "Fixed string for the numeric enumeration e.g. ID"]),
            OptString.new('PASSWORD',   [ true, "The login password to probe at each host", "password"]),
            OptString.new('USERNAME',   [ true, "The login username to probe at each host", "NOUSER"]),
            OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
            OptBool.new('LOGIN', [false, 'Login Before Sending Message', false]),
            OptString.new('TO',   [ false, "The destination username to probe at each host", "1000"]),
            OptString.new('FROM',   [ false, "The source username to probe at each host", "1000"]),
           	OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
            OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
            OptBool.new('FROMEQTO', [true, 'FROM will be cloned from TO for enumeration', false]),
            OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
            OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
            OptBool.new('DEBUG',   [ false, "Debug Level", false]),
            OptBool.new('VERBOSE',   [ false, "Whether to print output for all attempts", false]),

        ], self.class)
  end

  def run_host(dest_addr)
    if datastore['METHOD'] =~ /[SUBSCRIBE|REGISTER|INVITE]/
      method = datastore['METHOD']
    else
      print_error("Enumeration METHOD must be defined")
    end

    sockinfo={}
    # Protocol parameters
    sockinfo["proto"] = datastore['PROTO'].downcase
    sockinfo["vendor"] = datastore['VENDOR'].downcase
    sockinfo["macaddress"] = datastore['MACADDRESS']

    # Socket parameters
    sockinfo["listen_addr"] = datastore['CHOST']
    sockinfo["listen_port"] = datastore['CPORT']
    sockinfo["dest_addr"] = dest_addr
    sockinfo["dest_port"] = datastore['RPORT']

    from = datastore['FROM']


    sipsocket_start(sockinfo)
    sipsocket_connect

    reported_users=[]

    # Registration
    
    if datastore["LOGIN"] == true 
    	u = datastore["USERNAME"]
	    results = send_register(
	        'login'       => true,
	        'loginmethod' => "REGISTER",
	        'user'        => u,
	        'password'    => datastore['PASSWORD'],
	        'realm'       => datastore['REALM'],
	        'from'        => u,
	        'to'          => u
	    )
    end

    if datastore['NUMERIC_USERS'] == true
      numbers=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
      if datastore["PRENUMERIC"]
      	exts = []
      	numbers.each {|n|
      		exts << datastore["PRENUMERIC"]+n.to_s
      	}
  	  else
  	  	exts = numbers  	
      end
      
      exts.each { |to|
        from=to if datastore['FROMEQTO']
        reported_users = enumerate(from,to,dest_addr,method,reported_users)
      }
    else
      if datastore['USER_FILE'].nil?
        print_error("User wordlist is not provided.")
        return
      end
      each_user_pass { |to, password|
        from=to if datastore['FROMEQTO']
        reported_users = enumerate(from,to,dest_addr,method,reported_users)
      }
    end

    sipsocket_stop
  end

  def enumerate(from,to,dest_addr,method,reported_users)
    realm = datastore['REALM']
    
    cred={
        'realm'     	=> realm,
        'from'      	=> from,
        'to'        	=> to
    }

    if datastore["RESPONSEREGEX"]
    	possible = Regexp.new "#{datastore["RESPONSEREGEX"]}"
    else
      possibles = {
        "REGISTER" => /^200/,
        "SUBSCRIBE" => /^40[0-3]|^40[5-9]|^200/,
        "OPTIONS" => /^40[0-3]|^40[5-9]/,
        "INVITE" => /^40[0-3]|^40[5-9]|^200/
      }
      possible = possibles[method.upcase]
    end
    
    case method
      when "REGISTER"
        results = send_register(cred)
      when "SUBSCRIBE"
        results = send_subscribe(cred)
      when "OPTIONS"
        results = send_options(cred)
      when "INVITE"
        results = send_invite(cred)
    end

    if results != nil
      rdata = results["rdata"]
      if rdata != nil 
	      if rdata['resp'] =~ possible
	        to=rdata['to'].split("@")[0]
	        if reported_users == nil or ! reported_users.include?(to)
	          rp = "User #{to} is Valid (Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")})"
	          rp << "\n    Warning \t\t: #{rdata['warning']}" if rdata['warning']
	          print_good(rp)
	          reported_users << to
	        end
	      else
        	rp = "User #{to} is Invalid (#{rdata['resp_msg'].split(" ")[1,5].join(" ")})"
        	rp << "\n    Warning \t\t: #{rdata['warning']}\n" if rdata['warning']
        	vprint_status(rp)
	      end
      end
      printresults(results) if datastore['DEBUG'] == true
    end

    return reported_users
  end
end
