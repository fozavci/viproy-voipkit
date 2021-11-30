cp lib/msf/core/auxiliary/* /usr/share/metasploit-framework/lib/msf/core/auxiliary/
cat << EOF >> /usr/share/metasploit-framework/lib/msf/core/auxiliary/mixins.rb
require 'msf/core/auxiliary/sip'
require 'msf/core/auxiliary/skinny'
require 'msf/core/auxiliary/msrp'

Msf::Auxiliary::Mixins = ""
EOF

cp modules/auxiliary/voip/viproy* /usr/share/metasploit-framework/modules/auxiliary/voip/
cp modules/auxiliary/spoof/cisco/viproy_cdp.rb /usr/share/metasploit-framework/modules/auxiliary/spoof/cisco/
printf "You can execute msfconsole now.\nViproy modules placed under auxiliary/voip/viproy*\n"
apt-get install libpcap-dev
gem install pcaprub

