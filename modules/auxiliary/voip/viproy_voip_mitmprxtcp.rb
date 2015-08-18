##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::TcpServer

  def initialize(info = {})
    super(
      'Name'           => 'Viproy MITM Proxy for TCP/TLS',
      'Version'        => '1',
      'Description'    => 'MITM Proxy for TCP/TLS',
      'License'        => 'GPL',
      'Author'         => 'fozavci',
      'References'     =>	[],
    )

    register_options(
      [
          OptString.new('RHOST',   [ true, "Destination IP Address", nil]),
          OptString.new('RPORT',   [ true, "Destination Port", nil]),
          OptBool.new('SSL', [ false, 'Negotiate SSL for proxy connections', false]),
          OptString.new('LOGFILE',   [ true, "Log file for content"]),

      ], self.class)

    register_advanced_options(
      [
          OptPath.new('REPLACEFILE',      [ false, "File containing Replacements, one per line"]),
          OptBool.new('DEBUG',   [ false, "Debug Level", false]),
      ], self.class)
  end

  def setup
    super
    @logfname = datastore['LOGFILE']
    @destinationip = datastore['RHOST']
    @dstq={}
    @state = {}
    set_replacefile(datastore['REPLACEFILE']) if datastore['REPLACEFILE']
  end

  def run
    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
    exploit()
  end

  def on_client_connect(c)
    begin
      #Banner
      #greetings(c)

      @state[c] = {
          :name    => "#{c.peerhost}:#{c.peerport}",
          :ip      => c.peerhost,
          :port    => c.peerport,
      }

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
    rescue ::Timeout::Error, ::Errno::EPIPE => e
      print_error(e.message)
    end
  end

  def greetings(c)
    c.put "Banner"
  end

  def dqm(c)
    if ! @dstq[c.peerhost]
      @dstq[c.peerhost] = Rex::Socket::Tcp.create(
          'PeerHost'  => @destinationip,
          'PeerPort'  => datastore['RPORT'],
          'SSL'       => datastore['SSL'],
          'SSLVerifyMode' => 'NONE',
      )
    end
    return @dstq[c.peerhost]
  end

  def on_client_data(c)
    begin
      dst = dqm(c)
      print_status("Client #{c.peerhost} is connected")

      data = c.get_once
      #Search and Replace Point for Server
      replace_it(data,"REQ") if datastore['REPLACEFILE'] != nil
      print_status("Request Received:\n\t#{data.gsub("\n","\n\t")}")
      return if not data
      dst.put data
      print_status("Data sent to: #{@destinationip}")


      resp = dst.get_once(-1,2)
      #Search and Replace Point for Client
      replace_it(resp,"RES") if datastore['REPLACEFILE'] != nil
      print_status("Response Received:\n\t#{resp.gsub("\n","\n\t")}")
      c.put resp

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE => e
      print_error(e.message)
      print_status("No Response Received!")
      resp = "No Response"
    ensure
      if not @logfname.nil?
        logwrite(data,c.peerhost)
        logwrite(resp,@destinationip)
      end
    end
  end


  def on_client_close(c)
    print_status("Server connections are closing...")
    dqm(c).close
    @state.delete(c)
    print_status("Server connections are closed")
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
