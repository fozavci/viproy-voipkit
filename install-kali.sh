#!/bin/sh
# viproy install script for msf on kali linux

cp lib/msf/core/auxiliary/* /usr/share/metasploit-framework/lib/msf/core/auxiliary/
echo "require 'msf/core/auxiliary/sip'" >> /usr/share/metasploit-framework/lib/msf/core/auxiliary/mixins.rb
echo "require 'msf/core/auxiliary/skinny'" >> /usr/share/metasploit-framework/lib/msf/core/auxiliary/mixins.rb
echo "require 'msf/core/auxiliary/msrp'" >> /usr/share/metasploit-framework/lib/msf/core/auxiliary/mixins.rb
cp modules/auxiliary/voip/viproy* /usr/share/metasploit-framework/modules/auxiliary/voip/
cp modules/auxiliary/spoof/cisco/viproy_cdp.rb /usr/share/metasploit-framework/modules/auxiliary/spoof/cisco/
printf "You can execute msfconsole now.\nViproy modules placed under auxiliary/voip/viproy*\n"
apt install libpcap-dev
gem install pcaprub

