mkdir -p /usr/share/metasploit-framework/lib/rex/proto/sip
cp data/wordlists/sipproxy_replace.txt /usr/share/metasploit-framework/data/wordlists/sipproxy_replace.txt
cp lib/msf/core/auxiliary/sip.rb /usr/share/metasploit-framework/lib/msf/core/auxiliary/sip.rb
echo "require 'msf/core/auxiliary/sip'" >> /usr/share/metasploit-framework/lib/msf/core/auxiliary/mixins.rb
cp lib/rex/proto/sip/socket.rb /usr/share/metasploit-framework/lib/rex/proto/sip/socket.rb
cp lib/rex/proto/sip.rb /usr/share/metasploit-framework/lib/rex/proto/sip.rb
cp modules/auxiliary/scanner/sip/vsip* /usr/share/metasploit-framework/modules/auxiliary/scanner/sip 
echo "You can execute msfconsole now.\nViproy modules placed under auxiliary/scanner/sip/vsip*"
