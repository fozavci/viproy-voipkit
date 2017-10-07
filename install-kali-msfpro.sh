#!/bin/bash -eu
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables as an error when substituting.
# viproy install script for msfpro on kali linux

updatedb
msfpro=$(locate /opt/metasploit/apps/pro/vendor/bundle/ruby/*/gems/metasploit-framework-* | head -n1)

cp lib/msf/core/auxiliary/* $msfpro/lib/msf/core/auxiliary
echo "require 'msf/core/auxiliary/sip'" >> $msfpro/lib/msf/core/auxiliary/mixins.rb
echo "require 'msf/core/auxiliary/skinny'" >> $msfpro/lib/msf/core/auxiliary/mixins.rb
echo "require 'msf/core/auxiliary/msrp'" >> $msfpro/lib/msf/core/auxiliary/mixins.rb

cp modules/auxiliary/voip/viproy* $msfpro/modules/auxiliary/voip/
cp modules/auxiliary/spoof/cisco/viproy_cdp.rb $msfpro/modules/auxiliary/spoof/cisco/

printf "You can execute msfconsole now.\nViproy modules placed under auxiliary/voip/viproy*\n"

apt install libpcap-dev
gem install pcaprub
