#Viproy - VoIP Penetration Testing Kit
Viproy Voip Pen-Test Kit provides penetration testing modules for VoIP networks. It supports signalling analysis for SIP and Skinny protocols, IP phone services and network infrastructure. Viproy 2.0 is released at Blackhat Arsenal USA 2014 with TCP/TLS support for SIP, vendor extentions support, Cisco CDP spoofer/sniffer, Cisco Skinny protocol analysers, VOSS exploits and network analysis modules. Furthermore, Viproy provides SIP and Skinny development libraries for custom fuzzing and analyse modules.

##Current Version and Updates
Current version: 4.1 (Requires ruby 2.1.X and Metasploit Framework Github Repo) <br>
Pre-installed repo: https://github.com/fozavci/metasploit-framework-with-viproy

##Homepage of Project
http://viproy.com<br>

##Black Hat USA 2016 - VoIP Wars: The Phreakers Awaken
https://www.slideshare.net/fozavci/voip-wars-the-phreakers-awaken
https://www.youtube.com/watch?v=rl_kp5UZKlw

##Black Hat Europe 2015 - VoIP Wars: Destroying Jar Jar Lync
http://www.slideshare.net/fozavci/voip-wars-destroying-jar-jar-lync-unfiltered-version
https://youtu.be/TMdiXYzY8qY

##The Art of VoIP Hacking Workshop Slide Deck
http://www.slideshare.net/fozavci/the-art-of-voip-hacking-defcon-23-workshop

##Black Hat USA 2014 - VoIP Wars: Attack of the Cisco Phones
https://www.youtube.com/watch?v=hqL25srtoEY

##DEF CON 21 - VoIP Wars: Return of the SIP
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
* Boghe VoIP Client INVITE PoC Exploit (New)
* Boghe VoIP Client MSRP PoC Exploit (New)
* SIP Message with INVITE Support (New)
* Sample SIP SDP Fuzzer (New)
* MSRP Message Tester with SIP INVITE Support (New)
* Sample MSRP Message Fuzzer with SIP INVITE Support (New)
* Sample MSRP Message Header Fuzzer with SIP INVITE Support (New)

#Documentation

##Installation
Copy "lib" and "modules" folders' content to Metasploit root directory.<br>
Mixins.rb File (lib/msf/core/auxiliary/mixins.rb) should contains the following lines<br>
require 'msf/core/auxiliary/sip'<br>
require 'msf/core/auxiliary/skinny'<br>
require 'msf/core/auxiliary/msrp'<br>

##Usage of SIP Modules
https://github.com/fozavci/viproy-voipkit/blob/master/SIPUSAGE.md

##Usage of Skinny Modules
https://github.com/fozavci/viproy-voipkit/blob/master/SKINNYUSAGE.md

##Usage of Auxiliary Viproy Modules
https://github.com/fozavci/viproy-voipkit/blob/master/OTHERSUSAGE.md
