#Viproy - VoIP Penetration Testing Kit
Viproy Voip Pen-Test Kit provides penetration testing modules for VoIP networks. It supports signalling analysis for SIP and Skinny protocols, IP phone services and network infrastructure. Viproy 2.0 is released at Blackhat Arsenal USA 2014 with TCP/TLS support for SIP, vendor extentions support, Cisco CDP spoofer/sniffer, Cisco Skinny protocol analysers, VOSS exploits and network analysis modules. Furthermore, Viproy provides SIP and Skinny development libraries for custom fuzzing and analyse modules.

##Homepage of Project
http://viproy.com<br>

##Black Hat USA 2014 - Network: VoIP Wars Attack of the Cisco Phones
https://www.youtube.com/watch?v=hqL25srtoEY

##DEF CON 21 - VoIP Wars Return of the SIP
https://www.youtube.com/watch?v=d6cGlTB6qKw

##Attacking SIP/VoIP Servers Using Viproy
https://www.youtube.com/watch?v=AbXh_L0-Y5A

##Current Testing Modules
* SIP Register
* SIP Invite
* SIP Message
* SIP Negotiate
* SIP Options
* SIP Subscribe
* SIP Enumerate
* SIP Brute Force
* SIP Trust Hacking
* SIP UDP Amplification DoS
* SIP Proxy Bounce
* Skinny Register
* Skinny Call
* Skinny Call Forward
* CUCDM Call Forwarder
* CUCDM Speed Dial Manipulator
* MITM Proxy TCP
* MITM Proxy UDP
* Cisco CDP Spoofer

#Documentation

##Installation
Copy "lib" and "modules" folders' content to Metasploit root directory.<br>
Mixins.rb File (lib/msf/core/auxiliary/mixins.rb) should contains the following lines<br>
require 'msf/core/auxiliary/sip'<br>
require 'msf/core/auxiliary/skinny'<br>

##Usage of SIP Modules
https://github.com/fozavci/viproy-voipkit/blob/master/SIPUSAGE.md

##Usage of Auxiliary Viproy Modules
https://github.com/fozavci/viproy-voipkit/blob/master/OTHERSUSAGE.md
