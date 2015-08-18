##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# Developed by Fatih Ozavci
# Copyright 2015, Fatih Ozavci
##



require 'rex/socket'
require 'timeout'

module Msf

module Auxiliary::MSRP

	#
	# MSRP Functions
	#

  	def get_msrp_sdp(sockinfo,msg={})
		listen_addr = Rex::Socket.source_address(sockinfo["dest_addr"])
		msrp_ref 	= Rex::Text.rand_text_alphanumeric(20)

		sdp_content = "v=0\r\n"
		sdp_content << "o=doubango 1983 678901 IN IP4 #{listen_addr}\r\n"
		sdp_content << "s=-\r\n"
		sdp_content << "c=IN IP4 #{listen_addr}\r\n"
		sdp_content << "t=0 0\r\n"
		sdp_content << "m=message #{datastore["SRVPORT"]} TCP/MSRP *\r\n"
		sdp_content << "c=IN IP4 #{listen_addr}\r\n"
		sdp_content << "a=path:msrp://#{listen_addr}:#{datastore["SRVPORT"]}/#{msrp_ref};tcp\r\n"
		sdp_content << "a=connection:new\r\n"
		sdp_content << "a=setup:actpass\r\n"


		if msg[:messagefilename].nil?
			sdp_content << "a=accept-types:text/plain message/CPIM \r\n"
			sdp_content << "a=accept-wrapped-types:text/plain image/jpeg image/gif image/bmp image/png\r\n"
			sdp_content << "a=sendrecv\r\n"
		else

			sdp_content << "a=accept-types:message/CPIM application/octet-stream\r\n"
			sdp_content << "a=accept-wrapped-types:application/octet-stream image/jpeg image/gif image/bmp image/png\r\n"
			sdp_content << "a=sendonly\r\n"
			sdp_content << "a=file-selector:name:\"#{msg[:messagefilename]}\" type:application/octet-stream size:#{msg[:size]}\r\n"
			sdp_content << "a=file-transfer-id:#{msg[:transfer_id]}\r\n"
			sdp_content << "a=file-disposition:attachment\r\n"
			sdp_content << "a=file-icon:cid:test@viproy.org\r\n"
		end

		return sdp_content
	end

	def prep_msrp_ok(clients,c,headers,content)
		msrp_req_id = headers["ref"]

		msrp_content = "MSRP #{msrp_req_id} 200 OK\r\n"
		msrp_content << "To-Path: #{clients[c][:msrp][:from_uri]}\r\n"
		msrp_content << "From-Path: #{clients[c][:msrp][:to_uri]}\r\n"
		msrp_content << "-------#{msrp_req_id}$\r\n"

		return msrp_content
	end
	def prep_msrp_content(clients,c,msg,br=nil)
		msrp_req_id = "#{Rex::Text.rand_text_numeric(9)}"
		if msg[:transfer_id].nil?
			msrp_message_id = "#{Rex::Text.rand_text_numeric(9)}"
		else
			msrp_message_id = msg[:transfer_id]
			msg.delete(:transfer_id)
		end

		if msg[:msrptype] == "application/octet-stream"
			content="#{msg[:message]}"
		else
			content="Subject: #{msg[:messagesubject]}\r\n\r\nContent-Type: #{msg[:messagetype]}\r\n\r\n#{msg[:message]}"
		end

		br = content.length if br == nil

		msrp_content = "MSRP #{msrp_req_id} SEND\r\n"
		msrp_content << "To-Path: #{clients[c][:msrp][:from_uri]}\r\n"
		msrp_content << "From-Path: #{clients[c][:msrp][:to_uri]}\r\n"
		msrp_content << "Message-ID: #{msrp_message_id}\r\n"
		msrp_content << "Byte-Range: 1-#{br}/#{br}\r\n"
		msrp_content << "Failure-Report: yes\r\n"
		msrp_content << "Success-Report: no\r\n"
		msrp_content << "Content-Type: #{msg[:msrptype]}\r\n\r\n"

		if msg[:msrptype] != "application/octet-stream"
			msrp_content << "Subject: #{msg[:messagesubject]}\r\n\r\n"
			msrp_content << "Content-Type: #{msg[:messagetype]}\r\n\r\n"
			msrp_content << "#{msg[:message]}\r\n"
		else
			msrp_content << "#{msg[:message]}\r\n"
		end

		msrp_content << "-------#{msrp_req_id}$\r\n"

		return msrp_content
	end

	def msrp_content_parser(data)
		msrp_headers={}
		headers = data.split("\r\n\r\n")[0]

		print_status("MSRP header parsing is starting...")
		
		if(headers =~ /^MSRP \s*(.*)$/i)
		  msrp_headers["ref"] = "#{$1.strip.split(" ")[0]}"
		  msrp_headers["type"] = "#{$1.strip.split(" ")[1,5].join(" ")}"
		  print_status("MSRP Reference: #{msrp_headers["ref"]}, MSRP Type is #{msrp_headers["ref"]}")
		end

		if(headers =~ /^To-Path:\s*(.*)$/i)
		  msrp_headers["to_uri"] = "#{$1.strip}"
		  print_status("MSRP TO URI: #{msrp_headers["to_uri"]}")
		end

		if(headers =~ /^From-Path:\s*(.*)$/i)
		  msrp_headers["from_uri"] = "#{$1.strip}"
		  print_status("MSRP FROM URI: #{msrp_headers["from_uri"]}")
		end

		if(headers =~ /^Message-ID:\s*(.*)$/i)
		  msrp_headers["message_id"] = "#{$1.strip}"
		  print_status("MSRP Message ID: #{msrp_headers["message_id"]}")
		end

		if(headers =~ /^Byte-Range:\s*(.*)$/i)
		  msrp_headers["byte_range"] = "#{$1.strip}"
		  print_status("MSRP Byte Range: #{msrp_headers["byte_range"]}")
		end
		if(headers =~ /^Failure-Report:\s*(.*)$/i)
		  msrp_headers["failure"] = "#{$1.strip}"
		  print_status("MSRP Failure Report: #{msrp_headers["failure"]}")
		end
		if(headers =~ /^Success-Report:\s*(.*)$/i)
		  msrp_headers["success"] = "#{$1.strip}"
		  print_status("MSRP Success Report: #{msrp_headers["success"]}")
		end
		if(headers =~ /^Content-Type:\s*(.*)$/i)
		  msrp_headers["content-type"] = "#{$1.strip}"
		  print_status("MSRP Content Type: #{msrp_headers["content_type"]}")
		end

		print_status("MSRP header parsing is completed.")
		

		print_status("MSRP content parsing is starting...")
		msrp_content={}

		case msrp_headers["content-type"] 
			when "message/cpim"
				if(data.split("\r\n\r\n")[1] =~ /^Subject:\s*(.*)$/i)
				  msrp_content["subject"] = "#{$1.strip}"
				  print_status("MSRP Subject: #{msrp_content["subject"]}")
				end

				if(data.split("\r\n\r\n")[2] =~ /^Content-Type:\s*(.*)$/i)
				  msrp_content["content_type"] = "#{$1.strip}"
				  print_status("MSRP Body Content Type: #{msrp_content["content_type"]}")
				end

				msrp_content["body"] = data.split("\r\n\r\n")[3].split("\r\n---")[0]
			  	print_status("MSRP Message Body : \n\t#{msrp_content["body"].gsub("\r\n","\r\n\t")}")
			when "application/octet-stream"
				msrp_content["body"] = data.split("\r\n---")[0]
			  	print_status("MSRP Message Body : \n\t#{msrp_content["body"].gsub("\r\n","\r\n\t")}")				
			when nil
				print_status("No MSRP message content found.")
		else
			print_status("Unknown Content-Type received.")
		end

		print_status("MSRP content parsing is completed.")

		return msrp_headers,msrp_content
	end

	# Process the MSRP data sent by the client
	def process_request(clients,c)	
		data = clients[c][:buff]
		headers,content = msrp_content_parser(data)

		clients[c][:msrp][:to_uri] ||= headers["to_uri"]
		clients[c][:msrp][:from_uri] ||= headers["from_uri"]

		case headers["type"] 
			when /^200/
				print_status("200 OK received")
			when "SEND"
				print_status("MSRP 200 OK is sending for #{headers["ref"]}")
				msrp_content=prep_msrp_ok(clients,c,headers,content)
				c.put(msrp_content)
				print_status("MSRP 200 OK sent for #{headers["ref"]}")
		else
			print_status("Unknown message received: #{headers["type"]}")
		end

		return clients[c]
	end

	#Fuzzing MSRP Content

	def fuzzing_msrp_content(clients,c,i,input,count)
		msrp_req_id = "#{Rex::Text.rand_text_numeric(9)}"
		msrp_message_id = "#{Rex::Text.rand_text_numeric(9)}"

   		inj={}
   		inj[0]="Request #{count}"
   		inj[1]="text/plain"
   		inj[2]="Request #{count}"
   		# inj[3] is in use for Byte Range
   		inj[4]="MSRP"
   		inj[5]="SEND"
   		inj[6]="To-Path"
   		inj[7]="From-Path"
   		inj[8]= msrp_message_id
   		inj[9]="yes"
   		inj[10]="no"
   		inj[11]="message/cpim"
   		inj[12]= msrp_req_id
   		
   		#Fuzzing data is setting as the injection point
   		inj[i] = input 

		msg="Subject: #{inj[0]}\r\n\r\nContent-Type: #{inj[1]}\r\n\r\n#{inj[2]}"
		br = inj[3] || msg.length 
		#br = msg.length

		msrp_content = "#{inj[4]} #{inj[12]} #{inj[5]}\r\n"
		msrp_content << "#{inj[6]}: #{clients[c][:msrp][:from_uri]}\r\n"
		msrp_content << "#{inj[7]}: #{clients[c][:msrp][:to_uri]}\r\n"
		msrp_content << "Message-ID: #{inj[8]}\r\n"
		msrp_content << "Byte-Range: 1-#{br}/#{br}\r\n"
		msrp_content << "Failure-Report: #{inj[9]}\r\n"
		msrp_content << "Success-Report: #{inj[10]}\r\n"
		msrp_content << "Content-Type: #{inj[11]}\r\n\r\n"
		msrp_content << "Subject: #{inj[0]}\r\n\r\n"
		msrp_content << "Content-Type: #{inj[1]}\r\n\r\n"
		msrp_content << "#{inj[2]}\r\n"
		msrp_content << "-------#{inj[12]}$\r\n"

		return msrp_content
	end


	def start_fuzzing(c,fuzzingstatus)
		return "completed" if fuzzingstatus == "completed"

  		fuzzinginput=["A"*1050, "A"*550, "AAAAAAA", "0x!@KKJS", "0x219387129387129378123", "0xFFFFFFFFFFFFFFFFF", "-123123123", '@(#&@(#*@!P"', '\'",%1%u%x', "' ,823 '", "\"')><h1>test"]
		count = 0

		print_status("Fuzzing is starting...")
		13.times {|i|
			fuzzinginput.each {|input|
				print_status("The MSRP message is preparing...")
				msrp_content = fuzzing_msrp_content(@clients,c,i,input,count)
				print_status("Sending the MSRP message: \n\t#{msrp_content.gsub("\r\n","\r\n\t")}")
				c.put(msrp_content)
				count += 1
			}
		}
		print_status("Fuzzing is completed.")
		fuzzingstatus = "completed"

		return fuzzingstatus
	end

end
end
