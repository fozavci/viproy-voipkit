# This service is prepared to provide IP phones services like CUCDM IP Phone services
# License: Metasploit Framework License (BSD)

require 'socket'
server = TCPServer.new(8080)
@serverip = "10.2.0.7"

@cf_devices={"SEP00000C07AC02" => {"91102" => "11010001410391102","91103" => "11010001410391103"},
             "SEPA44C11907E7A" => {"91104" => "11010001410391104"},
             "SEPA44C1174C472" => {"91105" => "11010001410391105","91106" => "11010001410391106"},
             "SEP0004F290AC34" => {"91107" => "Congratulations!"},
}

@sd_devices={"SEP00000C07AC02" => ["john:123","joe:2142"],
          "SEPA44C11907E7A" => ["jane:0004F290AC34","john:123", nil ,"joe:2142"],
          "SEPA44C1174C472" => ["julie:4134", nil,"joe:2142"],
          "SEP0004F290AC34" => ["jake:9992","julie:4134",nil ,"jane:9823","jacob:452"],
}

def parsevars(variables)
  vars={}
  variables.split(" ")[0].split("&").each {|v|
    vars[v.split("=")[0]]=v.split("=")[1]
  }
  return vars
end

def notfound(client)
  headers=prepheaders("Not found.","plain")
  client.puts "#{headers}#{"Not found."}"
end

def prepheaders(data,t="xml")
  headers = ["HTTP/1.1 200 OK",
             "Date: Tue, 14 Dec 2010 10:48:45 GMT",
             "Server: Ruby",
             "Content-Type: text/#{t}; charset=iso-8859-1",
             "Content-Length: #{data.length}\r\n\r\n"].join("\r\n")
  return headers
end

loop {
  client = server.accept

  req = client.gets
  req = req.split("\n")[0]
  puts "Request: "+req

  case req.to_s
    # speed dial services

    when /phonespeedialadd.cgi/
      if(req =~ /phonespeedialadd.cgi\?\s*(.*)$/i)
        vars=parsevars($1)
        if vars["device"] and @sd_devices[vars["device"]]
          device=vars["device"]
          puts "phonespeedialadd device: #{device} for item #{vars["entry"].to_i}"
          i=vars["entry"].to_i-1
          data = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
          data << "<CiscoIPPhoneText>"
          data << "<Title>Information</Title>"
          if @sd_devices[device][i].nil?
            @sd_devices[device][i]="#{vars["name"]}:#{vars["telno"]}"
            data << "<Text>Speed Dial [#{vars["name"]}] Added</Text>"
          else
            data << "<Text>Speed Dial [#{i+1}] already exists</Text>"
          end
          data << "<SoftKeyItem>"
          data << "<Name>Exit</Name>"
          data << "<Position>3</Position>"
          data << "<URL>SoftKey:Exit</URL>"
          data << "</SoftKeyItem>"
          data << "</CiscoIPPhoneText>"

          headers=prepheaders(data)
          client.puts "#{headers}#{data}"
        else
          notfound(client)
        end
      else
        notfound(client)
      end

    when /phonespeeddialdelete.cgi/
      if(req =~ /phonespeeddialdelete.cgi\?\s*(.*)$/i)
        vars=parsevars($1)
        if vars["device"] and @sd_devices[vars["device"]]
          device=vars["device"]
          puts "phonespeeddialdelete device: #{device} for item #{vars["entry"].to_i}"
          @sd_devices[device][vars["entry"].to_i-1]=nil

          data = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
          data << "<CiscoIPPhoneText>"
          data << "<Title>Information</Title>"
          data << "<Text>Speed Dial for Phone [#{device[3,12]}] Deleted</Text>"
          data << "<SoftKeyItem>"
          data << "<Name>Exit</Name>"
          data << "<Position>3</Position>"
          data << "<URL>SoftKey:Exit</URL>"
          data << "</SoftKeyItem>"
          data << "</CiscoIPPhoneText>"

          headers=prepheaders(data)
          client.puts "#{headers}#{data}"
        else
          notfound(client)
        end
      else
        notfound(client)
      end

    when /speeddials.cgi/
      if(req =~ /speeddials.cgi\?\s*(.*)$/i)
        vars=parsevars($1)
        if vars["device"] and @sd_devices[vars["device"]]
          device=vars["device"]
          puts "speeddials device: #{device}"

          data = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
          data << "<CiscoIPPhoneDirectory>"
          data << "<Title>Speed Dials</Title>"
          data << "<DirectoryEntry>"
          pos=0
          @sd_devices[device].each {|item|
            pos += 1
            if ! item.nil?
            data << "<Name>#{pos}:#{item.split(":")[0]}</Name>"
            data << "<Telephone>#{item.split(":")[1]}</Telephone>"
            end
          }
          data << "</DirectoryEntry>"
          data << "<SoftKeyItem>"
          data << "<Name>Dial</Name>"
          data << "<Position>1</Position>"
          data << "<URL>SoftKey:Dial</URL>"
          data << "</SoftKeyItem>"
          data << "<SoftKeyItem>"
          data << "<Name>Manage</Name>"
          data << "<Position>2</Position>"
          data << "<URL>http://#{@serverip}/bvsmweb/speeddialsmanage.cgi?device=SEP001795A407C5</URL>"
          data << "</SoftKeyItem>"
          data << "<SoftKeyItem>"
          data << "<Name>Back</Name>"
          data << "<Position>4</Position>"
          data << "<URL>SoftKey:Exit</URL>"
          data << "</SoftKeyItem>"
          data << "</CiscoIPPhoneDirectory>"

          headers=prepheaders(data)
          client.puts "#{headers}#{data}"
        else
          notfound(client)
        end
      else
        notfound(client)
      end



    # call forwarding services (fint must be uniq)

    when /showcallfwdperline.cgi/
      if(req =~ /showcallfwdperline.cgi\?\s*(.*)$/i)
        vars=parsevars($1)
        if vars["device"] and @cf_devices[vars["device"]]
          device=vars["device"]
          puts "showcallfwdperline device: #{device}"
          headers=prepheaders("CFA")
          client.puts "#{headers}#{"CFA"}"
        else
          notfound(client)
        end
      else
        notfound(client)
      end

    when /phonecallfwd.cgi/
      if(req =~ /phonecallfwd.cgi\?\s*(.*)$/i)
        vars=parsevars($1)
        if vars["device"] and @cf_devices[vars["device"]]
          device=vars["device"]
          puts "phonecallfwd device: #{device}"
          puts "call forwarding for #{vars["fintnumber"].to_s} to #{vars["telno1"].to_s}"
          @cf_devices[device] = {vars["telno1"] => vars["fintnumber"]}

          data = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
          data << "<CiscoIPPhoneText>"
          data << "<Title>Information</Title>"
          data << "<Text>Call Forward settings change requested</Text>"
          data << "<SoftKeyItem>"
          data << "<Name>Exit</Name>"
          data << "<Position>3</Position>"
          data << "<URL>SoftKey:Exit</URL>"
          data << "</SoftKeyItem>"
          data << "</CiscoIPPhoneText>"
          headers=prepheaders(data)
          client.puts "#{headers}#{data}"
        else
          notfound(client)
        end
      else
        notfound(client)
      end


    when /callfwdmenu.cgi|showcallfwd/
      if(req =~ /callfwdmenu.cgi|showcallfwd.cgi\?\s*(.*)$/i)
        vars=parsevars($1)

        if vars["device"] and @cf_devices[vars["device"]]
          device=vars["device"]
          puts "showcallfwd device #{device}"

          data =  "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
          data << "<CiscoIPPhoneMenu>"
          data << "<Title>Select line to set Call Fwds</Title>"
          data << "<Prompt></Prompt>"

          @cf_devices[device].each {|displaynumber,fintnumber|
            data << "<MenuItem>"
            data << "<Name>#{displaynumber}</Name>"
            data << "<URL>http://#{@serverip}/bvsmweb/callfwdperline.cgi?device=#{device}&amp;cfoption=CallForwardAll&amp;fintnumber=#{fintnumber}</URL>"
            data << "</MenuItem>"
          }
          data << "<SoftKeyItem>"
          data << "<Name>Select</Name>"
          data << "<Position>1</Position>"
          data << "<URL>SoftKey:Select</URL>"
          data << "</SoftKeyItem>"
          data << "<SoftKeyItem>"
          data << "<Name>&lt;&lt;</Name>"
          data << "<Position>2</Position>"
          data << "<URL>SoftKey:&lt;&lt;</URL>"
          data << "</SoftKeyItem>"
          data << "<SoftKeyItem>"
          data << "<Name>Exit</Name>"
          data << "<Position>3</Position>"
          data << "<URL>SoftKey:Exit</URL>"
          data << "</SoftKeyItem>"
          data << "</CiscoIPPhoneMenu>"

          headers=prepheaders(data)
          client.puts "#{headers}#{data}"
        else
          notfound(client)
        end
      else
        notfound(client)
      end
    else
      notfound(client)
  end

  client.close
}
