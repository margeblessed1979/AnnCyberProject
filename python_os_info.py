#!/usr/bin/python3
#1. Display the OS version – if Windows, display the Windows details; if executed on Linux, display the Linux details.

import os           # import the os module to run Linux commands

import platform

def os_info(): #platform module is to obtain information about the current operating system and machine
	print("[!] Displaying the Operating System details")
	# Print the name of the current operating system
	print('The current OS is:', platform.system())
	# Print the version of the operating system
	print('The OS version is:', platform.version())
	# Print the release of the operating system
	print('The OS release is:', platform.release())
	# Print the architecture of the machine
	print('The OS architecture machine is:', platform.machine())
	print("\n")


#2. Display the private IP address, public IP address, and the default gateway.
def getprivateip():
	print("Displaying the private IP address, public IP address, and the default gateway.")
	import subprocess
	# Run the ifconfig command and capture its output
	output = subprocess.check_output(['ifconfig']).decode('utf-8')
	# Find the first non-loopback interface and extract its IP address
	for line in output.split('\n'):
		if 'inet ' in line and '127.0.0.1' not in line:
			ip_address = line.split()[1]
			break
		# Print the IP address
	print('The Private IP address is: ', ip_address)


def getpublicip():
	# import the requests module and give it an alias 'req'
	import requests as req
	# declare a string variable 'url' and assign a URL to check public 
	url: str=('https://checkip.amazonaws.com')
	# send a GET request to the URL and store the response in 'request'
	request=req.get(url)
	# extract the public IP address from the response and store it in the variable 'publicip'
	publicip: str=request.text
	print('The Public IP address is: ',publicip)


def getdefaultgateway():
	# Import the netifaces library
	import netifaces
	# Create an empty dictionary to store the result
	result = {}
	# Get the default gateway and the network interface for the AF_INET address family
	gateway, neti = netifaces.gateways()['default'][netifaces.AF_INET]
	# Add the network interface and gateway to the result dictionary
	result[neti] = gateway
	print ('The default gateway is: ' ,result[neti])
	print("\n")


#3. Display the hard disk size; free and used space.
def getharddisksize():
	import shutil
	# Get the total, free, and used disk space
	total, used, free = shutil.disk_usage("/")
	print("[!] Displaying the hard disk size; free and used space")
	# Convert bytes to GB for readability
	print('Hard disk total size is: %d GB' % (total // (1024*1024*1024)))
	print('Hard disk used size is: %d GB' % (used // (1024*1024*1024)))
	print('Hard disk free size is: %d GB' % (free // (1024*1024*1024)))
	print("\n")


#4. Display the top five (5) directories and their size.
def top_five_dir():
	print("[!] Displaying the top five (5) directories and their size..may take awhile...")
	 # Define the directory you want to check
	directory = "/"
       # Define a dictionary to store the directory sizes
	directory_sizes = {}

    # Loop through all directories and subdirectories in the specified directory
	for root, dirs, files in os.walk(directory):
        # Get the size of the directory
		directory_size = 0
		for name in files:
			file_path = os.path.join(root, name)
			if os.path.exists(file_path):
				directory_size += os.path.getsize(file_path)
        # Add the directory size to the dictionary
		directory_sizes[root] = directory_size
    # Get the top five directories by size
	top_five_directories = sorted(directory_sizes.items(), key=lambda x: x[1], reverse=True)[:5]
    # Display the top five directories and their sizes
	for directory, size in top_five_directories:
		print(f"{directory}: {size} bytes")
	print("\n")


#5. Display the CPU usage; refresh every 10 seconds.


def cpu_usage():   
	import time  # import the time module to format time
	print("[!] Displaying the CPU usage which refresh every 10 seconds...CTRL Z to interrupt or cancel")
	while True:     # run an infinite loop
        # run the 'grep' and 'awk' command to get CPU usage and read the first line of output
		cpu_times = os.popen("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'").readline()
         # convert the CPU usage to float data type
		cpu_percent = float(cpu_times)    
        # get the current time and format it
		time_str = time.strftime("%I:%M:%S %p")   
        # print the time and CPU usage percentage with 6 characters for decimal places
		print("CPU USAGE: " f"{time_str} CPU {cpu_percent:6.2f}%")
         # wait for 10 seconds before repeating the loop
		time.sleep(10)  

def credits_ref(): 
	print("\nhttps://note.nkmk.me/en/python-platform-system-release-version/")
	print("https://stackoverflow.com/questions/72331707/socket-io-returns-127-0-0-1-as-host-address-and-not-192-168-0-on-my-device")
	print("https://www.youtube.com/watch?v=62RCDlWIQUY")
	print("https://www.programcreek.com/python/?code=kylechenoO%2FAIOPS_PLATFORM%2FAIOPS_PLATFORM-master%2FCMDB%2FAsset%2Flib%2FNETI.py")
	print("https://stackoverflow.com/questions/48929553/get-hard-disk-size-in-python")
	print("https://www.geeksforgeeks.org/python-get-list-of-files-in-directory-with-size/")
	print("https://docs.python.org/3/library/os.html\n")


print("[*] You are about to run a Python Script for")
print("[*] Project PHYTON FUNDAMENTALS - OS INFO")
print("[*] The script is created by Mary Ann Lim Tian\n")
credits_ref()
os_info()
getprivateip()
getpublicip()
getdefaultgateway()
getharddisksize()
top_five_dir()
cpu_usage()

