##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'sipsocket'

class Metasploit3 < Msf::Auxiliary

    	include SIP
        include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SIP Proxy with Auto Replace Support',
			'Version'     => '$Revision$',
			'Description' => 'SIP Proxy with Auto Replace Support',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
			'License'     => MSF_LICENSE
		)

		deregister_options('RHOST','RHOSTS','RPORT')
		register_options(
		[
			OptAddress.new('PRXCLT_IP',   [true, 'Local IP of SIP Server for Client']),
			OptInt.new('PRXCLT_PORT',   [true, 'Local UDP Port of SIP Server for Client',5061]),
			OptAddress.new('PRXSRV_IP',   [true, 'Local IP of SIP Server for Server']),
			OptInt.new('PRXSRV_PORT',   [true, 'Local UDP Port of SIP Server for Server',5060]),
			OptAddress.new('CLIENT_IP',   [true, 'IP of SIP Client']),
			OptInt.new('CLIENT_PORT',   [true, 'Port of SIP Client',5060]),
			OptAddress.new('SERVER_IP',   [true, 'IP of Remote SIP Server']),
			OptInt.new('SERVER_PORT',   [true, 'Port of Remote SIP Server',5060]),
			OptPath.new('CONF_FILE',      [ false, "File containing Replacements and Custom Headers",
			#File.join(Msf::Config.install_root, "data", "wordlists", "sipproxy_replace.txt") ]),
			File.join("/tmp", "sipproxy_replace.txt") ]),
			OptPath.new('LOG_FILE',      [ false, "Log File for Requests and Responses",
			File.join("/tmp", "sipproxy_log.txt") ]),
		], self.class)

		register_advanced_options(
		[
			OptBool.new('DEBUG',   [ false, "Verbose Level", false]),
			OptBool.new('VERBOSE',   [ false, "Verbose Level", false])
		], self.class)
	end

	def run
	 	client_ip = datastore['CLIENT_IP']
	 	client_port = datastore['CLIENT_PORT']
	 	server_ip = datastore['SERVER_IP']
	 	server_port = datastore['SERVER_PORT']

	 	prxclient_ip = datastore['PRXCLT_IP']
	 	prxclient_port = datastore['PRXCLT_PORT']
	 	prxserver_ip = datastore['PRXSRV_IP']
	 	prxserver_port = datastore['PRXSRV_PORT']

		print_status("Proxy Service Started....")
		print_status("Settings For Client => #{prxclient_ip}:#{prxclient_port}")
		print_status("Settings For Server => #{prxserver_ip}:#{prxserver_port}")

		prxclt=SIP::Socket.new(prxclient_port,prxclient_ip,client_port,client_ip)
		prxclt.start_monitor
		#prxsrv=SIP::Socket.new(prxserver_port,prxserver_port,server_ip,server_port)    

                # Wait for finish..
                while true # @prxclt.thread.alive? or @prxsrv.thread.alive?
                        select(nil, nil, nil, 2)
                end
		prxclt.stop

	end

	def dispatch_request(from,buf)
		puts "Module :"
		puts "From:"+from.to_s
		puts "Buffer:"+buf.to_s
	end
end
