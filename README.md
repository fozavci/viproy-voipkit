#SIP Services Testing Modules for Metasploit Framework


VulnVOIP is vulnerable SIP server, you can use it for tests<br>
VulnVOIP : http://www.rebootuser.com/?cat=371<br>

I will publish a SIP Pen-test guide soon at www.gamasec.net/fozavci<br>
Basic Usage of Modules are presented below, it can be used before guide.
All modules have DEBUG and VERBOSE supports

#INSTALLATION
Copy all "lib" and "modules" folders' content to Metasploit Root Directory.

#Sample Usage Video
http://youtu.be/1vDTujNVKGM

#GLOBAL SETTINGS
setg CHOST 172.16.100.1 #Local Host<br>
setg RHOSTS 172.16.100.6 #Target Host<br>
setg RHOST 172.16.100.6 #Target Host<br>

#Basic Usage of REGISTER Module <br>
use auxiliary/scanner/sip/gsipregister<br>
show options <br>
run<br>

set LOGIN true<br>
set USERNAME 101<br>
set PASSWORD s3cur3<br>
run<br>

#Basic Usage of OPTIONS Module<br>
use auxiliary/scanner/sip/gsipoptions <br>
show options <br>
run<br>
set DEBUG true<br>
run<br>
set VERBOSE true<br>
run<br>

#Basic Usage of INVITE Module<br>
use auxiliary/scanner/sip/gsipinvite <br>
show options <br>
set FROM 101<br>
run<br>
<br>
set LOGIN true<br>
set USERNAME 101<br>
set PASSWORD s3cur3<br>
run<br>


#Basic Usage of ENUMERATOR Module<br>
use auxiliary/scanner/sip/gsipenumerator <br>
show options <br>
set NUMERIC_USERS true<br>
set NUMERIC_MAX 500<br>
run<br>

set METHOD REGISTER<br>
run<br>

set METHOD INVITE<br>
run<br>

#Basic Usage of BRUTE FORCE Module<br>
use auxiliary/scanner/sip/gsipbruteforce <br>
show options <br>
set PASS_FILE /tmp/passwords <br>
set NUMERIC_USERS true<br>
set NUMERIC_MAX 500<br>
run<br>

set USER_FILE /tmp/users<br>
set NUMERIC_USERS false<br>
run<br>

