#!/bin/bash
# 1. Display the Linux version
#  a. create a variable to store Linux version terminal command
#  b. use this action $(uname -v) to get Linux version and store in linuxver variable
#  c. echo to display the Title of this script
#  c. echo to display the Linux version stored in $linuxver
#  NOTE: echo -e is use to enable interpretation of backslash escapes. \n for new line
    echo -e "These are the Linux Operating System Information \n"
	linuxver=$(uname -v)
	echo "    Linux version:  $linuxver"

# 2. Display the Private IP Address, Public IP address and the default gateway
#  a. create 3 variables for Private IP, Public IP and Default Gateway to store terminal commands
#  b. for Private IP address use action and text manipulation $(ifconfig | grep broadcast |awk '{print $2}') to get the IP only and store in PrivateIP variable
#  c. for Private IP address use action $(curl -s ifconfig.io) to get the IP only in silent mode and store in PublicIP variable
#  d. for Default Gateway use action and text manipulation $(route |grep UG |awk '{print $2}') to get the IP only and store in GatewayIP variable
#  e. echo to display the results of the 3 variables $PrivateIP, $PublicIP, $GatewyIP

	PrivateIP=$(ifconfig | grep broadcast |awk '{print $2}')
	PublicIP=$(curl -s ifconfig.io)
	GatewayIP=$(route |grep UG |awk '{print $2}')

	echo "    Private IP:      $PrivateIP"
	echo "    Public IP:       $PublicIP"
	echo -e "    Default Gateway: $PublicIP \n"
	
#3. Display the hard disk size; free and used space
#  a. use this action df -h / to get all hard disk size; free and used space. 
#      -h to display human readable format
#       / to display all available hard disk
#   NOTE: this command /dev/sda1 -to get the physical hard drive 1. Hard drive may be listed as /sda1, /sda0, or you may even have more than one.        
#  b. echo to display the title of hard disk information
    
    echo "Hard Disk Infomation: "
    df -h /

# 4. Display the top 5 directories and the size
#  a. create variable to store terminal command showing the current working directory
#  b. echo to display the title Top 5 directories on the current working directory
#  b. use action du to get the file space usage
#   	du -h flag to display a human-readable suffixes like M for megabytes and G for gigabytes
#   	sort -n flag Compare according to string numerical value.
#   	sort -r flag Reverse the result of comparisons.
#   	use action head -5 to print the first 5 lines
    
    CurrDir=$(pwd)
    echo -e "\nTop 5 Directories in $CurrDir"  
    du -h |sort -nr |head -5

# 5. Display the CPU usage; refresh every 10 seconds
#  a. echo to display the title CPU Utilization refreshes every 10 seconds and CTRL-C to cancel
#  b. use action mpstat -u 10 tto display the usage for each processor. -u to track CPU performance and 10 to set interval in seconds

   echo -e "\nCPU Utilization Performance - refreshes at 10 seconds interval. To cancel press Ctrl-C" 
   mpstat -u 10
   

# display all references: 
   echo -e "\nThese are the references for terminal commands used for this script \n"
   echo "https://phoenixnap.com/kb/linux-check-disk-space - command to check hard disk information"
   echo "https://www.tecmint.com/find-top-large-directories-and-files-sizes-in-linux/ - command to show top 5 directories"
   echo "https://phoenixnap.com/kb/check-cpu-usage-load-linux - command to display CPU utilization with interval"
