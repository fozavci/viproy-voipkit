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
      'Name'        => 'Viproy SIP Negotiate Module',
      'Version'     => '1',
      'Description' => 'Negotiate Discovery Module for SIP Services',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptString.new('TO',   [ true, "The destination username to probe at each host", "100"]),
      OptString.new('FROM',   [ true, "The source username to probe at each host", "100"]),
      OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
      Opt::RPORT(5060),
    ], self.class)

    register_advanced_options(
    [
      Opt::CHOST,
      Opt::CPORT(5065),
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
      OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
      OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
    ], self.class)
  end

  def run_host(dest_addr)
    listen_addr = datastore['CHOST']
    listen_port = datastore['CPORT']
    dest_port = datastore['RPORT']
    proto = datastore['PROTO'].downcase
    vendor = datastore['VENDOR'].downcase
    macaddress = datastore['MACADDRESS'] || "000000000000"

    sipsocket_start(listen_port,listen_addr,dest_port,dest_addr,proto,vendor,macaddress)
    sipsocket_connect

    result,rdata,rdebug,rawdata = send_negotiate(
      'realm'		  => datastore['REALM'],
      'from'    	=> datastore['FROM'],
      'to'    	  => datastore['TO']
    )

    printresults(result,rdata,rdebug,rawdata)
    sipsocket_stop
  end
end