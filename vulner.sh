#!/bin/bash
#This script is intend for Scanning and mapping the network, identifying open ports,finding users with weak passwords,and potential vulnerabilities based on service detection.
#information gathering

#FUNCTION 1 - Introduction message of the script
function intro_message()
{	
# Set the message to display
message=" PROJECT VULNER - PENTESTING "

# Set the width and height of the banner
width=100
height=5

# Define the character used for the banner border
borderChar="*"

# Calculate the length of the message and the left and right padding needed
messageLength=${#message}
paddingLength=$(( (width - messageLength) / 2 ))
leftPadding=$(printf "%0.s${borderChar}" $(seq 1 $paddingLength))
rightPadding=$(printf "%0.s${borderChar}" $(seq 1 $paddingLength))

# Print the top border of the banner
printf "%0.s${borderChar}" $(seq 1 $width)
echo ""

# Print the message with padding
echo "${leftPadding}${message}${rightPadding}"

# Print the bottom border of the banner
printf "%0.s${borderChar}" $(seq 1 $width)
echo ""

echo "[*] This script is for Scanning and mapping the network, identifying open ports,"
echo "[*] finding users with weak passwords, and potential vulnerabilities based on service detection"
echo -e "[*] The script is created by Mary Ann Lim Tian \n"
}

#FUNCTION 2 - group of functions to execute this script
function call_function()
{
	#start timestamp
	Nmap_Device_StartTimestamp=$(echo "$(date '+%D %r') - ")
    #Call FUNCTION 3 - log creation
	log_creation
	#call FUNCTION 4- to scan current IP range and timestamp device stats in /var/log/pt.log
	ip_range_info
	#call FUNCTION 5 - to check IP address entry if correct or not
	TargetIP_check
	#call FUNCTION 8 - check if user has own username list or to create
	user_list_option
	#call FUNCTION 9 - check if user has own password list or to create
	pass_list_option
	#call FUNCTION 10 - TCP Scan for open ports ,services and OS detection info
	nmap_tcp_scan	
	#call FUNCTION 11 - UDP Scan for open ports
	udp_scan
	#call FUNCTION 12 - Bruteforce Target device
	bruteforcing
	#call FUNCTION 13 - scan for vulnerabilities of each target devices open port services
	vulnerability_check
}

#FUNCTION 3 - log creation
function log_creation()
{
 if [ -f /var/log/pt.log ]                  #if pt.log (scanned audit log) exist
 then
	currentuser=$(whoami)                    #to get current user
	sudo chown $currentuser /var/log/pt.log  #to provide current user who is not a root user to write in /var/log/pt.log
	echo "[#]/var/log/pt.log exist"
 else
	currentuser=$(whoami)                    #to get current user
			#create PT Log to audit enumeration done on Target Address
	sudo touch /var/log/pt.log               #to create custom log file in /var/log
	sudo chown $currentuser /var/log/pt.log  #to permit currentuser to write in the custom audit log file <pt.log>
	echo "[#]/var/log/pt.log created"
 fi
}	


#FUNCTION 4 - Host Disccovery 
function ip_range_info()
{
	#~ 1.1 Automatically identify the LAN network range
		ip_range_cidr=$(ip route | grep -oE '([0-9]{1,3}[\.]){3}[0-9]{1,3}/[0-9]{1,2}') #to get the Network Address/CIDR notation
		ip_range=$(netmask -r $ip_range_cidr) #to get IP range
		echo "[#] The network range is: $ip_range_cidr" #display network address/cidr
		echo "[#] The first & last IP address is: $ip_range" #display network range
		echo "[#] nmap running to check for host discovery..." 
	#~ 1.2 Automatically scan the current LAN and
	#~ 1.3 Enumerate each live host using nmap
		#do nmap to scan or do a host dicovery of available IP Addresses within the network range specified
		Avail_IP_Addr=$(nmap -sn $ip_range_cidr)
		echo -e "[#]The available IP Addresses in $ip_range_cidr are: \n $Avail_IP_Addr \n"
}

#FUNCTION 5 - $target_ip variable will only match IP addresses with valid values
function TargetIP_check()
{
#ask user to enter ip address from nmap results
echo "[?]Enter Target IP Address from above choices: "
read target_ip 

	if [[ $target_ip =~ ^(([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$ ]]
	#format [01]?[0-9]?[0-9] matches numbers from 0 to 199
	#2[0-4][0-9] matches numbers from 200 to 249
	#25[0-5] matches numbers from 250 to 255
	then #to check if entered IP is in correct 
		LocalPath=$(pwd) #to get the current working directory
		dir=$(echo "$LocalPath/vulner_report") #passing vulner_reort directory where target device report will be saved
			if [ ! -d "$dir" ] #check if directory does not exist
			then
			echo "[#]Creating directory: $dir"
			mkdir -p $LocalPath/vulner_report
			else
			echo "[#]vulner_report directory exist"
			fi
	Target_Rpt_filepath=$(sudo echo "$dir/report_$target_ip.txt") #create target device report with this filename format in the current working directoy
	echo "$target_ip REPORT on $('date')" > $Target_Rpt_filepath #timestamp of report created
	else
		echo "[!] Invalid IP address format"
		TargetIP_check
	fi
}

#FUNCTION 6 -  Allow the user to create username list 
function username_creation()
{
# Prompt user for username list name
	echo "[?]Enter a name for your username list: " 
	read user_list_name
# Create new username list file
	userlistfile="${user_list_name}_list.txt"
	touch "$userlistfile"

# Prompt user to enter username until they enter "quit"
while true; do
    read -p "[?]Enter a username to add to your list or type 'quit' to exit: " username
    
    # Check if user entered "quit", if so, break out of loop
    if [[ "$username" == "quit" ]]
    then
        break
    fi
    
    # Add username to username list file
    echo "$username" >> "$userlistfile"
done

echo -e "[#]Your username list has been created and saved t $LocalPath/$userlistfile. \n"
}

#FUNCTION 7 - Allow the user to create password list 
function password_creation()
{
	# Prompt user for password list name
	echo "[?]Enter a name for your password list: " 
	read pass_list_name
# Create new password list file
	passlistfile="${pass_list_name}_list.txt"
	touch "$passlistfile"

# Prompt user to enter passwords until they enter "quit"
while true; do
    read -p "Enter a password to add to your list or type 'quit' to exit: " password
    
    # Check if user entered "quit", if so, break out of loop
    if [[ "$password" == "quit" ]]
    then
        break
    fi
    
    # Add password to password list file
    echo "$password" >> "$passlistfile"
done

echo "[#]Your password list has been created and saved to $LocalPath/$passlistfile."
}

#FUNCTION 8 - check if user has own username list
function user_list_option()
{    
	echo "[?] Do you have a username list file?[y/n]: "
	read answer
	if [[ $answer == Y || $answer == y ]] 
	then
		#Allow the user to specify a user list
		echo "[?] Enter username list filename [include file path if it's in another folder ex. /home/kali/user.lst]: "
		read userlistfile
	elif [[ $answer == N || $answer == n ]]  
	then 
		#call FUNCTION 4 username_creation
		username_creation
	else
		user_list_option
	fi
}

#FUNCTION 9 - check if user has it's own password list
function pass_list_option()
{
	echo "[?] Do you have a password list file?[y/n]: "
	read answer
	#if condition statement to identify next action
	if [[ $answer == Y || $answer == y ]] 
	then
		#Allow the user to specify a password list
		echo "[?] Enter password list filename [include file path if it's in another folder ex. /home/kali/pass.lst]: "
		read passlistfile
	elif [[ $answer == N || $answer == n ]] 
	then
		#call FUNCTION 5 password_creation
		password_creation
	else 
		pass_list_option
	fi
} 

#FUNCTION 10 - TCP Scan for open ports ,services and OS detection info
function nmap_tcp_scan()
{
	echo -e "Host discovery network range  $ip_range_cidr up and running devices are \n$Avail_IP_Addr" >> $Target_Rpt_filepath
	#~ 1.4 Find potential vulnerabilities for each device
		#provide option to check top 1000 ports or All ports
		echo -e "\n[?]Do you want to check all TCP open ports or top 1000 TCP ports only? [A: All | B: Top 1000]: "
		read scan_choice
			case $scan_choice in
			A|a)
			echo -e "[#]START CHECKING FOR OPEN PORTS, OS DETECTION, WEAK CREDENTIALS and POTENTIAL VULNERABILITIES INFO \n" 
			echo "[!]nmap running to check for all open ports ... this may take awhile..."
			nmap_tcp_output=$(sudo nmap -p- -sV -O $target_ip )  #scan all ports, display the open ports ,services and OS detection info
			open_tcp_ports=$(echo "$nmap_tcp_output" | grep open | awk -F / '{ print $1 }')
			open_tcp_protocol=$(echo "$nmap_tcp_output" | grep open | awk '{ print $3 }')
			echo -e "\n$nmap_tcp_output"
			echo "[#]TCP Open Ports found: $(echo "$open_tcp_ports" | wc -w)"
			echo -e "\n[#]These are TCP open port services for $target_ip \n$nmap_tcp_output \n" >> $Target_Rpt_filepath
			;;
			B|b)
			echo -e "[#]START CHECKING FOR OPEN PORTS, OS DETECTION, WEAK CREDENTIALS and POTENTIAL VULNERABILITIES INFO \n" 
			echo "[!]nmap running to check for top TCP 1000 ports ... this may take awhile..."
		    nmap_tcp_output=$(sudo nmap -sV -O $target_ip)  #scan all ports, display the open ports and OS detection info
		    open_tcp_ports=$(echo "$nmap_tcp_output" | grep open | awk -F / '{ print $1 }')
			open_tcp_protocol=$(echo "$nmap_tcp_output" | grep open |awk '{ print $3 }')
			echo -e "\n$nmap_tcp_output"
			echo "[#]TCP Open Ports found: $(echo "$open_tcp_ports" | wc -w)"
			echo -e "\n[#]These are the TCP open port services for $target_ip \n$nmap_tcp_output \n" >> $Target_Rpt_filepath
			;;
		    *) #if input not within the list provided
			echo "[!]Invalid Choice...try again"
			nmap_results              #function to display and choose different type of attacks
			;;	
			esac
}

#FUNCTION 11 - UDP Scan for open ports
function udp_scan() 
{
	#to scan UDP ports from 1 to 1000
	echo -e "\n[!]Masscan running to check for top 1000 UDP ports...this may take awhile....\n"
	mascan_udp_output=$(sudo masscan $target_ip -pU:1-1000 --banners --open) 
	open_udp_ports=$(echo "$mascan_udp_output" |grep open |awk -F / '{print $1}'|awk '{print $4}')
	if [[ -n "$open_udp_ports" ]]
	then
	echo "[#]UDP Open Ports found: $(echo "$open_udp_ports" | wc -w)"
	echo -e "\n[#]These are the top 1000 UDP open port services for $target_ip \n$mascan_udp_output \n" >> $Target_Rpt_filepath
	else
	echo "[#]There are no open UDP ports found"
	echo -e "[#]There are no open UDP ports found \n$mascan_udp_output \n" >> $Target_Rpt_filepath
	fi
}

#FUNCTION 12 - Bruteforce Target device
function bruteforcing()
{
if [[ $(echo "$open_tcp_protocol" |wc -l) -gt 1 ]] then
    # If more than one login service is available, choose the first service –
	first_port=$(echo "$open_tcp_ports" |head -n 1)
	first_protocol=$(echo "$open_tcp_protocol" |head -n 1)
	echo -e "\n[!]Starting bruteforce using first port and service found $first_port ($first_protocol)"
    bruteforce_result=$(hydra -L $userlistfile -P $passlistfile $target_ip -s $first_port $first_protocol -t4 -I)
    valid=$(echo "$bruteforce_result" |grep valid |awk '{print $(NF-3)}')
    if [[ $valid == 0 ]] 
    then
    echo -e "[#]There is no valid credenials found \n $bruteforce_result" >> $Target_Rpt_filepath #to save in target device report
    echo -e "\n $bruteforce_result \n" # to display on user screen
    else
    echo -e "****** Bruteforce using Hydra Result ****** \n $bruteforce_result" >> $Target_Rpt_filepath #to save in target device report
    echo -e "\n $bruteforce_result \n" # to display on user screen
    fi 
else
    echo -e "\n[!]Starting bruteforce using only port and service found $open_tcp_ports ($open_tcp_protocol)"
    bruteforce_result=$(hydra -L $userlistfile -P $passlistfile $target_ip -s $open_tcp_ports $open_tcp_protocol -t4 -I)
    valid=$(echo "$bruteforce_result" |grep valid |awk '{print $(NF-3)}')
    if [[ $valid == 0 ]] 
    then
    echo -e "[#]There is no valid credenials found \n $bruteforce_result" >> $Target_Rpt_filepath #to save in target device report
    echo -e "\n $bruteforce_result \n" # to display on user screen
    else
    echo -e "****** Bruteforce using Hydra Result ****** \n $bruteforce_result" >> $Target_Rpt_filepath #to save in target device report
    echo -e "\n $bruteforce_result \n" # to display on user screen
    fi
 fi
 num_device=$(echo "$Avail_IP_Addr" |grep -oE '([0-9]{1,3}[\.]){3}[0-9]{1,3}'|wc -l)
	num_openport=$(($(echo "$open_tcp_ports" |wc -w) + $(echo "$open_udp_ports" |wc -w)))
	Nmap_Device_Timestamp=$(echo "$Nmap_Device_StartTimestamp $(date '+%r') - [*] Nmap Scanning on $target_ip from Network Address/CIDR: $ip_range_cidr with Network Range: $ip_range, devices found: $num_device, Open Ports found: $num_openport ")
	echo "[#]$Nmap_Device_Timestamp" >> /var/log/pt.log
}		

#FUNCTION 13 - scan for vulnerabilities of each target devices open port services
function vulnerability_check()
{
	echo -e "[#]Checking for vulenrabilities on all open services... This may take awhile \n"

#loop to scan each port of target device and file reading line by line
	#Check vulnerability for TCP open ports
	while read line; do
	  if echo "$line" | grep -q open; then
		port=$(echo $line | cut -d '/' -f 1)
		service=$(echo $line | cut -d ' ' -f 3)

		echo "[*]Running Vulnerability check on port $port ($service)..."
		port_vuln_result=$(nmap --script vuln -p $port $target_ip -sV)
		echo -e "[*]Vulnerability result on $port ($service)*** \n" >> $Target_Rpt_filepath
		echo "$port_vuln_result" >> $Target_Rpt_filepath
	  fi
	done <<< "$(echo "$nmap_tcp_output" | grep open)" # to redirect the input of a loop to come from a string
	echo -e "[!] Vulnerability Check for TCP ports on $target_ip completed. Output saved in $Target_Rpt_filepath\n"
	
	#Check vulnerability for UDP open ports
	if [[ -n "$open_udp_ports" ]]
	then
		while read line; do #loop to read each line from $open_udp_ports variable
			if [[ -n "$open_udp_ports" ]] #check length of string not zero
			then
			    echo "[*]Running Vulnerability check on port $open_udp_ports..."
				port_vuln_result=$(nmap --script vuln -sU -p $open_udp_ports $target_ip -sV)
				echo -e "[*]Vulnerability result on $open_udp_ports*** \n" >> $Target_Rpt_filepath
				echo "$port_vuln_result" >> $Target_Rpt_filepath
			fi
		done <<< $open_udp_ports # to redirect the input of a loop to come from a string
	echo -e "[!] Vulnerability Check for UDP Ports on $target_ip completed. Output saved in $Target_Rpt_filepath\n"
	else
	echo -e "[!] No UDP open ports on $target_ip. \n"
	fi
	
	#call FUNCTION 12 - Exit script
	exit_script	
}	

#FUNCTION 14 - user option to exit script
function exit_script()
{
	#Define an exit message to be displayed
	ExitMessage1=$(echo "[*] You have exited the script.")
	ExitMessage2=$(echo "[*] Have an AWESOME day!")
	#to check if user want to scan another target device
	echo -n "[?] Do you want to check another target device? [Y/N]: " 
	read answer
			if [[ $answer == Y || $answer == y ]] 
			then
			#user to enter another 
				#call Function 13 - main program
			    call_function
			elif [[ $answer == N || $answer == n ]]
			then
				echo -n "[?] Do you like to open the log file? [Y/N]: "
				read answer
				if [[ $answer == Y || $answer == y ]] 
				then
					cat /var/log/pt.log
					echo -e "\n"
					echo "[#]Log file is located at /var/log/pt.log"
					echo "Target device report is located $dir"
					echo "$ExitMessage1"
					echo "$ExitMessage2"
					#call credits function
					credits
				else
					echo "Log file is located at /var/log/pt.log"
					echo "Target device report is located $dir"
					echo "$ExitMessage1"
					echo "$ExitMessage2"
					#call credits function
					credits
					exit
				fi
			else
				exit_script
			fi
}
	

#FUNCTION 15 - Script References
function credits()
{
echo -e "\nCREDITS and REFERENCES: \n"
echo "Credits to Center for Cyebersecurity Training "
echo "https://www.oreilly.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html"
echo "https://geekflare.com/nmap-vulnerability-scan/credits"
echo "https://justhackerthings.com/post/learning-remote-enumeration-part-1/"
echo "https://www.tutorialkart.com/bash-shell-scripting/bash-while-true/"
echo "https://linuxhint.com/while_read_line_bash/"
echo "https://www.freecodecamp.org/news/bash-scripting-tutorial-linux-shell-script-and-command-line-for-beginners/"
echo "https://stackoverflow.com/questions/69780937/border-an-array-of-words-in-bash"
echo "https://www.notion.so/cfcapac/Penetration-Testing-2a92d0591af04ee393fd74a3438fd42c#5d55fdad716642be83f7f02c626a4867"
}

#START OF SCRIPT TO RUN
#call FUNCTION 1 - Introduction message of the script
intro_message
#call FUNCTION 2 - group of functions to execute this script
call_function


