#Usage of Auxilary Viproy Modules

##CDP Tester

set INTERFACE en5<br>
set ACTION Sniffer<br>
run<br>
jobs<br>

use auxiliary/spoof/cisco/viproy_cdp<br>
show options <br>
set INTERFACE en5<br>
set ACTION Spoof <br>
run<br>

http://www.viproy.com/captures/viproy_cdp.pcapng<br>
