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
      'Name'        => 'Viproy SIP Subscribe Module',
      'Version'     => '1',
      'Description' => 'Subscribe Discovery Module for SIP Services',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     => MSF_LICENSE
    )

    deregister_options('RHOSTS','USER_AS_PASS','THREADS','USERPASS_FILE','PASS_FILE','PASSWORD','BLANK_PASSWORDS', 'BRUTEFORCE_SPEED','STOP_ON_SUCCESS' )

    register_options(
        [
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
            Opt::CPORT(5065),
            OptString.new('SUBSCRIBETYPE',   [ false, "Subscribe message type (presence,message)", 'message']),
            OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
            OptString.new('LOGINMETHOD', [false, 'Login Method (REGISTER | SUBSCRIBE)', "SUBSCRIBE"]),
            OptBool.new('TO_as_FROM', [true, 'Try the to field as the from field for all users', false]),
            OptString.new('CUSTOMHEADER', [false, 'Custom Headers for Requests', nil]),
            OptString.new('P-Asserted-Identity', [false, 'Proxy Identity Field. Sample: <sip:100@RHOST:RPORT>', nil]),
            OptString.new('P-Charging-Vector', [false, 'Proxy Charging Field. Sample: icid-value=msanicid;msan-id=msan123;msan-pro=1 ', nil]),
            OptString.new('Record-Route', [false, 'Proxy Record-Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
            OptString.new('Route', [false, 'Proxy Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
            OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
            OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
            OptBool.new('DEBUG',   [ false, "Debug Level", false]),
        ], self.class)
  end

  def run
    # Login Parameters
    login = datastore['LOGIN']
    user = datastore['USERNAME']
    password = datastore['PASSWORD']
    realm = datastore['REALM']

    # Protocol parameters
    proto = datastore['PROTO'].downcase
    vendor = datastore['VENDOR'].downcase
    macaddress = datastore['MACADDRESS']

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
      from=Rex::Text.pattern_create(datastore['TO'].split(" ")[1].to_i)
    else
      to = datastore['TO']
    end

    # Socket parameters
    listen_addr = datastore['CHOST']
    listen_port = datastore['CPORT']
    dest_addr =datastore['RHOST']
    dest_port = datastore['RPORT']


    #Building Custom Headers
    customheader = ""
    customheader << datastore['CUSTOMHEADER']+"\r\n" if datastore['CUSTOMHEADER'] != nil
    customheader << "P-Asserted-Identity: "+datastore['P-Asserted-Identity']+"\r\n" if datastore['P-Asserted-Identity'] != nil
    customheader << "P-Charging-Vector: "+datastore['P-Charging-Vector']+"\r\n" if datastore['P-Charging-Vector'] != nil
    customheader << "Record-Route: "+datastore['Record-Route']+"\r\n" if datastore['Record-Route'] != nil
    customheader << "Route: "+datastore['Route']+"\r\n" if datastore['Route'] != nil

    sipsocket_start(listen_port,listen_addr,dest_port,dest_addr,proto,vendor,macaddress)
    sipsocket_connect

    to.to_s
    if datastore['TO_as_FROM']
      from=to
      fromname=nil
    end

    result,rdata,rdebug,rawdata,callopts = send_subscribe(
        'login' 	      => login,
        'loginmethod'  	=> datastore['LOGINMETHOD'],
        'subscribetype'	=> datastore['SUBSCRIBETYPE'],
        'user'  	      => user,
        'password'	    => password,
        'realm' 	      => realm,
        'from'  	      => from,
        'fromname'  	  => fromname,
        'to'  		      => to,
        'customheader'	=> customheader,
    )

    printresults(result,rdata,rdebug,rawdata) if datastore['DEBUG'] == true

    if rdata != nil and rdata['resp'] =~ /^18|^20|^48/ and rawdata.to_s =~ /#{callopts["tag"]}/
      print_good("Message: #{from} ==> #{to} Subscribe Sent (Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")})")
    else
      vprint_status("Message: #{from} ==> #{to} Subscription Failed (Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")})") if rdata != nil
    end

    if customheader != ""
      vprint_status("Custom Headers")
      vprint_status(customheader)
    end

    sipsocket_stop
  end
end