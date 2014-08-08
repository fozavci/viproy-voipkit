cp lib/msf/core/auxiliary/* /usr/share/metasploit-framework/lib/msf/core/auxiliary/
echo "require 'msf/core/auxiliary/sip'" >> /usr/share/metasploit-framework/lib/msf/core/auxiliary/mixins.rb
echo "require 'msf/core/auxiliary/skinny” >> /usr/share/metasploit-framework/lib/msf/core/auxiliary/mixins.rb
cp modules/auxiliary/voip/viproy* /usr/share/metasploit-framework/modules/auxiliary/voip/
cp modules/auxiliary/spoof/cisco/viproy-cdp.rb /usr/share/metasploit-framework/modules/auxiliary/spoof/cisco/
echo "You can execute msfconsole now.\nViproy modules placed under auxiliary/voip/viproy*”
