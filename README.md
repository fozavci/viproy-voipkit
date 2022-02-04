# Discontinued
Viproy was a PoC VoIP security assessment tool which had several modules and exploits to maintain. However, it was developed as a modules set to Metasploit Framework. As Metasploit Framework had significant updates, Viproy's current modules won't be able to work unless you use legacy Kali Linux and Metasploit Framework versions. I discontinued the project a long time ago as I stopped working on the VoIP and UC project for last 5 years. <br>

If you still need these modules, "infosecconsultant" has prepared a note on the Issues section (https://github.com/fozavci/viproy-voipkit/issues/22). I suggest you to take a look at it, if it works for you, please also express your appreciation to them. I'm not planning to improve any code base or documentation, but please feel free to fork this repository and make your own.    

# Viproy - VoIP Penetration Testing Kit
Viproy Voip Pen-Test Kit provides penetration testing modules for VoIP networks. It supports signalling analysis for SIP and Skinny protocols, IP phone services and network infrastructure. Viproy 2.0 is released at Blackhat Arsenal USA 2014 with TCP/TLS support for SIP, vendor extentions support, Cisco CDP spoofer/sniffer, Cisco Skinny protocol analysers, VOSS exploits and network analysis modules. Furthermore, Viproy provides SIP and Skinny development libraries for custom fuzzing and analyse modules. Viproy VoIP Kit was used for VoIP exploit demonstrations in VoIP Wars presentation series, Departed Communications presentationm series and live VoIP Wars trainings in Black Hat, DEF CON, HITB, AusCERT and Troopers. 

Viproxy MITM Proxy and Testing Tools is developed using Metasploit Framework environment located in the Viproy modules. It is a standalone Metasploit module which enables users to intercept the TCP/TLS traffic and to execute some attacks against thick client applications, mobile applications and VoIP clients. Viproxy can be used to attack the Microsoft Lync and Skype for Business environments as demonstrated during the VoIP Wars: The Phreakers Awaken in Black Hat USA 2016 and VoIP Wars: Destroying Jar Jar Lync presentation at Black Hat Europe 2015, GSEC Hack In The Box Singapore 2015 and Ruxcon 2015 events. Viproxy has magic words to perform inline attacks. It also has an online rule console to manage the attacks including INVITE subject update, MESSAGE content update and sending invalid content for fuzzing.

## Author
Fatih Ozavci<br>
LinkedIn: https://au.linkedin.com/in/fozavci<br>
Slide Share: https://www.slideshare.net/fozavci<br>
Github: https://www.github.com/fozavci<br>

## Current Version and Updates
Current version: 4.1 (Requires ruby 2.1.X and Metasploit Framework Github Repo) <br>
Pre-installed repo: https://github.com/fozavci/metasploit-framework-with-viproy

## Documentation

### Installation
Copy "lib" and "modules" folders' content to Metasploit root directory.<br>
Mixins.rb File (lib/msf/core/auxiliary/mixins.rb) should contains the following lines<br>
require 'msf/core/auxiliary/sip'<br>
require 'msf/core/auxiliary/skinny'<br>
require 'msf/core/auxiliary/msrp'<br>

### Usage of SIP Modules
https://github.com/fozavci/viproy-voipkit/blob/master/SIPUSAGE.md

### Usage of Skinny Modules
https://github.com/fozavci/viproy-voipkit/blob/master/SKINNYUSAGE.md

### Usage of Auxiliary Viproy Modules
https://github.com/fozavci/viproy-voipkit/blob/master/OTHERSUSAGE.md

## Talks & Videos

### BSides Canberra, Australia 2017 - Departed Communications: Learn the ways to smash them 
https://www.slideshare.net/fozavci/departed-communications-learn-the-ways-to-smash-them

### Black Hat USA 2016 - VoIP Wars: The Phreakers Awaken
https://www.slideshare.net/fozavci/voip-wars-the-phreakers-awaken<br>
https://www.youtube.com/watch?v=rl_kp5UZKlw

### DEF CON 24 - VoIP Wars: The Live Workshop
No video.

### Black Hat Europe 2015 - VoIP Wars: Destroying Jar Jar Lync
http://www.slideshare.net/fozavci/voip-wars-destroying-jar-jar-lync-unfiltered-version<br>
https://youtu.be/TMdiXYzY8qY

### DEF CON 23 - The Art of VoIP Hacking Workshop Slide Deck
http://www.slideshare.net/fozavci/the-art-of-voip-hacking-defcon-23-workshop<br>
https://youtu.be/hwDD7K9oXeI

### Black Hat USA 2014 / DEF CON 22 - VoIP Wars: Attack of the Cisco Phones
https://www.youtube.com/watch?v=hqL25srtoEY

### DEF CON 21 - VoIP Wars: Return of the SIP
https://www.youtube.com/watch?v=d6cGlTB6qKw

### Attacking SIP/VoIP Servers Using Viproy
https://www.youtube.com/watch?v=AbXh_L0-Y5A
