##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'digest/md5'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::SIP
  include Msf::Auxiliary::AuthBrute


  def initialize
    super(
      'Name'        => 'Viproy SIP Invite SDP Tester',
      'Version'     => '1',
      'Description' => 'Invite SDP Testing Module for SIP Services',
      'Author'      => 'fozavci',
      'License'     => 'GPL'
    )

    deregister_options('RHOSTS','USER_AS_PASS','THREADS','DB_ALL_CREDS', 'DB_ALL_USERS', 'DB_ALL_PASS','USERPASS_FILE','PASS_FILE','PASSWORD','BLANK_PASSWORDS', 'BRUTEFORCE_SPEED','STOP_ON_SUCCESS' )

    register_options(
      [
        OptInt.new('NUMERIC_MIN',   [true, 'Starting extension',0]),
        OptInt.new('NUMERIC_MAX',   [true, 'Ending extension', 9999]),
        OptBool.new('NUMERIC_USERS',   [true, 'Numeric Username Bruteforcing', false]),
        OptString.new('USERNAME',   [ true, "The login username to probe at each host", "NOUSER"]),
        OptString.new('PASSWORD',   [ true, "The login password to probe at each host", "password"]),
        OptString.new('TO',   [ true, "The destination number to probe at each host", "1000"]),
        OptString.new('FROM',   [ true, "The source number to probe at each host", "1000"]),
        OptString.new('FROMNAME',   [ false, "Custom Name for Message Spoofing", nil]),
        OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
        OptBool.new('LOGIN', [false, 'Login Before Sending Message', false]),
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
      to =Rex::Text.pattern_create(datastore['TO'].split(" ")[1].to_i)
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

      send_register(
          'login' => login,
          'user' => user,
          'password' => password,
          'realm' => realm,
          'from' => from,
          'to' => to
      )

      36.times {|i|
        fdata=fuzzdata()
        fdata.each {|data|
            results = send_invite(
              'login' 	   	  => false,
              'loginmethod'   => datastore['LOGINMETHOD'].upcase,
              'user'  	      => user,
              'password'	    => password,
              'realm' 	      => realm,
              'from'  	      => from,
              'fromname'  	  => fromname,
              'to'  		      => to,
              'sdp'			      => sdpcontentprep(i,data),

          )
          # Rex.sleep(3) # Disable Sleep for 3 seconds
        }
      }

      if results != nil
        printresults(results) if datastore['DEBUG'] == true and results["rdata"] != nil

        if results["rdata"]['resp'] =~ /^18|^20|^48/ and results["callopts"] != nil and results["rawdata"].to_s =~ /#{results["callopts"]["tag"]}/
          print_good("Call: #{from} ==> #{to} is Ringing (Server Response: #{results["rdata"]['resp_msg'].split(" ")[1,5].join(" ")})")
        else
          vprint_status("Call: #{from} ==> #{to} is Failed (Server Response: #{results["rdata"]['resp_msg'].split(" ")[1,5].join(" ")})") if results["rdata"] != nil
        end
      end
    end

    sipsocket_stop

  end

  def fuzzdata
  	fdata=["A"*2050, "A"*1050, "A"*552, "AAAAAAA", "0x219387129387129378123", "0xFFFFFFFFFFFFFFFFF", "-123123123", '@(#&@(#*@!P"', '\'",%1%u%x', "' ,823 '", "\"')><h1>test"]
  end
  
  def sdpcontentprep(i,data)
	inj={}
	inj[0]='+1289371098273-viproy'
	inj[1]='127.0.0.1'
	inj[2]='127.0.0.1'
	inj[3]="-"
	inj[4]="IN"
	inj[5]="0"
	inj[6]="0"
	inj[7]="audio"
	inj[8]="16782"
	inj[9]="RTP"
	inj[10]="AVP"
	inj[11]="0"
	inj[12]="PCM"
	inj[13]="8000"
	inj[14]="urn:ietf:params:rtp-hdrext:csrc-audio-level"
	inj[15]="1"
	inj[16]="voip-metrics"
	inj[17]="video"
	inj[18]="16541"
	inj[19]="RTP"
	inj[20]="AVP"
	inj[21]="96"
	inj[22]="99"
	inj[23]="recvonly"
	inj[24]="96"
	inj[25]="H264"
	inj[26]="90000"
	inj[27]="96"
	inj[28]="fmtp"
	inj[29]="4DE01f"
	inj[30]="1"
	inj[31]="96"
	inj[32]="1366"
	inj[33]="768"
	inj[34]="H264"
	inj[35]="90000"

	#Fuzzing data is setting as the injection point
	inj[i] = data

	#Generic SDP Content 
	sdp_content = "v=0\r\n"
	sdp_content << "o=#{inj[0]} 0 0 IN IP4 #{inj[1]}\r\n"
	sdp_content << "s=#{inj[3]} \r\n"
	sdp_content << "c=#{inj[4]} IP4 #{inj[2]}\r\n"
	sdp_content << "t=#{inj[5]} #{inj[6]}\r\n"
	sdp_content << "m=#{inj[7]} #{inj[8]} #{inj[9]}/#{inj[10]} #{inj[11]}\r\n"
	sdp_content << "a=rtpmap:0 #{inj[12]}/#{inj[13]}\r\n"
	sdp_content << "a=extmap:#{inj[15]} #{inj[14]}\r\n"
	sdp_content << "a=extmap:2 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
	sdp_content << "a=rtcp-xr:#{inj[16]}\r\n"
	sdp_content << "m=#{inj[17]} #{inj[18]} #{inj[19]}/#{inj[20]} #{inj[21]} #{inj[22]}\r\n"
	sdp_content << "a=#{inj[23]}\r\n"
	sdp_content << "a=rtpmap:#{inj[24]} #{inj[25]}/#{inj[26]}\r\n"
	sdp_content << "a={inj[28]}:#{inj[27]} profile-level-id=#{inj[29]};packetization-mode=#{inj[30]}\r\n"
	sdp_content << "a=imageattr:#{inj[31]} send * recv [x=[0-#{inj[32]}],y=[0-#{inj[33]}]]\r\n"
	sdp_content << "a=rtpmap:99 #{inj[34]}/#{inj[35]}\r\n"
	sdp_content << "a=fmtp:99 profile-level-id=4DE01f\r\n"
	sdp_content << "a=imageattr:99 send * recv [x=[0-1366],y=[0-768]]\r\n"
	sdp_content << "\r\n"

      return sdp_content
  end
  
end

