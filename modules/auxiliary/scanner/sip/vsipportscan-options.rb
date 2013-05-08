##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'digest/md5'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
        include Msf::Auxiliary::SIP

	def initialize
		super(
			'Name'        => 'UDP Port Scanner via SIP Options',
			'Version'     => '1',
			'Description' => 'UDP Port Scanner via Options Method for SIP Services',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
			'License'     => MSF_LICENSE
		)
		deregister_options('RPORT', 'RHOST' )	
		register_options(
		[
			OptString.new('RPORTS', [true, 'Port Range for UDP Port Scan', "5060-5065"]),
			OptAddressRange.new('RHOSTS', [true, 'IP Range for UDP Port Scan']),
			OptAddress.new('SIP_SERVER_IP',   [true, 'Vulnerable SIP Server IP']),
			OptInt.new('SIP_SERVER_PORT',   [true, 'Vulnerable SIP Server Port']),
			Opt::CHOST,	
			Opt::CPORT(5065)
		], self.class)

		register_advanced_options(
		[
			OptString.new('TO',   [ true, "The destination username to probe at each host", "100"]),
			OptString.new('FROM',   [ true, "The source username to probe at each host", "100"]),
			OptBool.new('DEBUG',   [ false, "Verbose Level", false]),
			OptBool.new('VERBOSE',   [ false, "Verbose Level", false])
		], self.class)
	end

    
	def run

		from = datastore['FROM']
		to = datastore['TO']
		listen_addr = datastore['CHOST']
		listen_port = datastore['CPORT'].to_i 
		dest_addr = datastore['SIP_SERVER_IP']
		dest_port = datastore['SIP_SERVER_PORT'].to_i 

		rhosts = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
		rports = Rex::Socket.portspec_crack(datastore['RPORTS'])

		start_sipsrv(listen_port,listen_addr,dest_port,dest_addr)
		#start_monitor

		rhosts.each do |rhost|
			rports.each do |rport|	
				vprint_status("Sending Packet for #{rhost}:#{rport}")
				result,rdata,rdebug,rawdata = send_options(
					'realm'		=> "#{rhost}:#{rport}",
					'from'    	=> from,
					'to'    	=> to
				)  


				if result == :received and ! (rdata['resp_msg'] =~ /timeout/)
					if rdata["contact"]
					report = "#{rdata["contact"].gsub("sip:","")} is Open\n"
					else
					report = "#{rhost}:#{rport} is Open\n"
					end
					report <<"    Server \t: #{rdata['server']}\n" if rdata['server']
					report <<"    User-Agent \t: #{rdata['agent']}\n"	if rdata['agent']
					print_good(report)

				else
					vprint_status("#{rhost}:#{rport} is Close/Filtered\n")
				end

			end
		end

	        stop

	end
end

