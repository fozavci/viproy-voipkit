#Viproy - VoIP Penetration Testing Kit
VoIP penetration testing modules for Metasploit Framework

##Homepage of Project
http://viproy.com<br>

##Black Hat USA 2014 - Network: VoIP Wars Attack of the Cisco Phones
https://www.youtube.com/watch?v=hqL25srtoEY

##DEF CON 21 - VoIP Wars Return of the SIP
https://www.youtube.com/watch?v=d6cGlTB6qKw

##Attacking SIP/VoIP Servers Using Viproy
https://www.youtube.com/watch?v=AbXh_L0-Y5A

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
