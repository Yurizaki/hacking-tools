# Notes for the Pratical Ethical Hacking - The complete course
_Start date: 05/08/2019_
_Last updated: 05/08/2019_

* 📌 Target - to become PEH certified before the end of 31st of December

## Contents
* The 5 Stages of Ethical Hacking
*   1 Reconnaissance 🔍
* Appendix
  * Websites
  * Tools

## The 5 Stages of Ethical Hacking
### 1 Reconnaissance
Reconnaissance is the first stage of ethical hacking. It can be either active or passive.
* The __active approach__, closely ties into the second phase of ethical hacking, Scanning & Enumeration, using tools such as nmap, nessus, etc... scanning actively against ports, ips, running software & their version etc....
* The __passive approach__ is more to do with searching online, using lookup tools, searching for company names, pictures, socials, details, users, etc... Just not performing anything active against an individual or company. 

#### Passive Reconnaissance
Can be related to either gathering information on the targets physical location information or the targets social job information.
* __Location information__ can be anything related to, satellite imagery, drone recon, building & ground layout.
  * More detailed info on badge reader locations, secured doors, smoke & lunch break areas, security office & patrols, cctv, fencing, etc...
* __Job information__ can be anything related to the employees details which can be found online, such as their name, job title, appearance, phone number, email, addresses, hobbies, etc...
  * Focus on the photos which could aid in location information, such as desks, areas, laptops and other machines around, what is on their desktop, what tools do they use, any other people in the photo, etc... 

As well as the above, reconnaissance can be made on the targets web and hosts details. There are 4 specific areas to look for:
* Target Validation - ❗ Before performing any further steps, validate the target before attacking (even before reconnaissance)
* Finding Subdomains
* Finger printing - Whats running on a website/host, what services are running, what versions of the applications are running, what ports are open, what version of protocols are they using on the port etc...
  * Can be used in active reconnaissance, for passive reconnaissance, utilise whats already published on the web. 
* Data Breaches - Credentials dumped, breached incidents of the past that has leaked data

#### Web information gathering
One of the first tasks is to identify what subdomains are available. This is important as there could be many third layer subdomains i.e. X.tesla.com, or further layer subdomains, X.X.tesla.com, these subdomains could have unsecured access as they could have been set public by mistake by developers or testers. These could be forms, provide more information, provide further access to exploit.

#### Identifying Technologies
The following tools can be used to identify what technologies are being user for the running of a website/server. [Builtwith], Wapplyzer, WhatWeb
The purpose of this exercise is that identifying what technologies are in use, and identify what versions of those technologise are in user, can help us narrow down the possible attack vectors to take. i.e. Seeing a website running Drupel  in PHP, means that we can look up exploits for Drupel and PHP. 

#### Reconnaissance in Review
* Identify the target
  * Perform the appropriate searching to validate the targets domains, hosts, dns, etc....
    * Dnsrecon, Httpprobe, __Hunter.io__, Nslookup
* Find any subdomains
  * Identify and validate any possible subdomains of the target that could be used as additional points of attack.  
    *  Bluto, __crt.sh__, Dig, Googlefu, __Httpprobe__, Nmap, __Sublist3r__, Owasp Amass, WHOIS
* Hostsite/server Fingerprinting
  * Identify what technologies the platform is running & what versions of those technologies are  
    * Builtwith, __Burpsuite__, Foxyproxy, Nmap, Netcat, __Wappalyzer__, WhatWeb
* Look for any data breaches related to the site and or sites users
  * __Breach-parse__, HaveIBeenPwned, Owasp Amass, Weleakinfo

### 2 Scanning & Enumeration
#### NMAP

##### Scan Example
Example nmap scan. Some information has been exluded. Gives us a list of ports open and running software, what that software is, and general information on the target device.
* Notice a port open running SMB
* Good ports to begin scanning/enumerating/attacking
  * Port 80 - TCP
  * Port 139 - SMB
  * Port 443 - HTTPS

nmap -T4 -p- -A
	-T4 nmap has a choice of spead -T 1 -> 5
	-p- scan for all ports, if not passed - will scan the most popular ports only, approx 65000 ports, need to know all which are open
	-p- means scan all ports
	-p X,X scan specific ports
	-A everything, tell me everything that you can find
	
nmap - network map
	scans for open ports
	stealth scanning -sS
		even tho its stealth it can still be detected.
		SYN - open port responds SYNACK
		nmap sends RST (lmao jk not really) - resets the connection so con isn't made
```
└─$ sudo nmap -T4 -p- -A 192.168.81.129  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-06 13:29 EDT
Nmap scan report for 192.168.81.129
Not shown: 65529 closed ports
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
111/tcp   open  rpcbind     2 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
32768/tcp open  status      1 (RPC #100024)

MAC Address: 00:0C:29:1F:83:C2 (VMware)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Network Distance: 1 hop

Host script results:
|_clock-skew: 2h37m42s
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE
HOP RTT     ADDRESS
1   1.35 ms 192.168.81.129

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.76 seconds
```
##### Checking out the target
On our machine we go to the targets IP address: 192.168.81.129
Upon doing so we are greeted with the following default web server page. This is an automatic flag, a finding, its not exploitable but tells us about the architecture and clients hygeine.
If we can access a web host like this, we can possibly find the website in another directory. Or they could not be be hosting a website but have the ports open, if so, that is poor hygiene, that could mean there are further potential vulnerabilities
![image](https://user-images.githubusercontent.com/8808090/132257446-004445c7-1a88-445a-9d7a-cf4d845793e4.png)
![image](https://user-images.githubusercontent.com/8808090/132257463-35dc46ee-4ecc-4b5e-b6e1-ea6c6f74432c.png)

##### Vulnerability Scanning
An example Nikto scan. Good for basic scanning, but can be easily blocked. Does Directory busting for us.
Detecting the server technology and version, OS, port info. Can notify technology thats outdated and what the technology could be vulnerable to.... especially remote vulnerabilities... which can be findings
* Notice
  * mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.
  * OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST (cross site scripting)
```
└─$ sudo nikto -h http://192.168.81.129/ 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.81.129
+ Target Hostname:    192.168.81.129
+ Target Port:        80
+ Start Time:         2021-09-06 16:01:50 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Wed Sep  5 23:12:46 2001
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ OSVDB-27487: Apache is vulnerable to XSS via the Expect header
+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-838: Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.
+ OSVDB-4552: Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.
+ OSVDB-2733: Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi. CAN-2003-0542.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.
+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ OSVDB-682: /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS).
+ OSVDB-3268: /manual/: Directory indexing found.
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /test.php: This might be interesting...
+ /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.
+ /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.
+ /shell?cat+/etc/hosts: A backdoor was identified.
+ 8724 requests: 0 error(s) and 30 item(s) reported on remote host
+ End Time:           2021-09-06 16:02:15 (GMT-4) (25 seconds)
```
##### Directory busting
Web servers can have hundreds or thousands of well known web pages and directories of common file extensions. We can use a directory busting tool which will scan a servers url against a common set of names to find what paths, files, folders, extensions exist on the server.
![image](https://user-images.githubusercontent.com/8808090/132260264-d466c34d-4830-44eb-96f3-87cfd3e90f75.png)

##### Information disclosure problems
As can be seen by this image as well as several others from the scans, servers headers disclose version information.
![image](https://user-images.githubusercontent.com/8808090/132260785-45702853-2db4-446f-b6b1-75594c30716c.png)

### Burpe suit
Send to repeater
ALlows you to modify the request in real time and see the response of that modified request

##### Enumerating SMB
SMB is a file sharing tool. Scnerios where this would be used are:
* Common server that many users can access, a file share.
* Printer/scanning, when scanning a document the document may appear in a file share folder on your network.
The type of version of SMB can be used to exploit.

A snippet from running auxiliary(scanner/smb/smb_version from msfconsole. 
* Notice Samba 2.2.1a
```
msf6 auxiliary(scanner/smb/smb_version) > run
[*] 192.168.81.129:139    - SMB Detected (versions:) (preferred dialect:) (signatures:optional)
[*] 192.168.81.129:139    -   Host could not be identified: Unix (Samba 2.2.1a)
[*] 192.168.81.129:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/smb_version) > 
```

Running a tool called smbclient
Notice
* Cannot get access just to the domain without authentication
* There are 2 fileshares however, IPC$ and ADMIN$
```
└─$ smbclient -L \\\\192.168.81.129\\
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful

        Server               Comment
        ---------            -------
        KIOPTRIX             Samba Server

        Workgroup            Master
        ---------            -------
        MYGROUP              KIOPTRIX
```
Trying to connect to ADMIN$ with anonymous access fails:
```
└─$ smbclient \\\\192.168.81.129\\ADMIN$
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Enter WORKGROUP\kali's password: 
tree connect failed: NT_STATUS_WRONG_PASSWORD
```
Connecting to the IPC$ file share is a success, however when attempting to invoke any commands we hit a dead end
```
─$ smbclient \\\\192.168.81.129\\IPC$ 
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls - la
NT_STATUS_NETWORK_ACCESS_DENIED listing \-
```

##### Enumeration on SSH
Simply attempting to connect to ssh is enopugh, when even attemoting a password you are beginning to exploit

Making a connection
Notice
* There isn't much more to do here, what is important about this approach is to check if there are any company banners with any details present when making the connection.
```
┌──(kali㉿kali)-[~]
└─$ ssh 192.168.81.129                
Unable to negotiate with 192.168.81.129 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1
┌──(kali㉿kali)-[~]
└─$ ssh 192.168.81.129 -oKexAlgorithms=+diffie-hellman-group1-sha1 
Unable to negotiate with 192.168.81.129 port 22: no matching cipher found. Their offer: aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc,rijndael128-cbc,rijndael192-cbc,rijndael256-cbc,rijndael-cbc@lysator.liu.se
┌──(kali㉿kali)-[~]
└─$ ssh 192.168.81.129 -oKexAlgorithms=+diffie-hellman-group1-sha1 -c aes128-cbc  
The authenticity of host '192.168.81.129 (192.168.81.129)' can't be established.
RSA key fingerprint is SHA256:VDo/h/SG4A6H+WPH3LsQqw1jwjyseGYq9nLeRWPCY/A.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.81.129' (RSA) to the list of known hosts.
kali@192.168.81.129's password: 
```

##### Searchsploit
```
──(kali㉿kali)-[~]
└─$ searchsploit Samba 2.2.1a  
--------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                  |  Path
--------------------------------------------------------------------------------------
Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit)                                                                                                                    | osx/remote/9924.rb
Samba < 2.2.8 (Linux/BSD) - Remote Code Execution                                                                                                                               | multiple/remote/10.c
Samba < 3.0.20 - Remote Heap Overflow                                                                                                                                           | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                                                                                   | linux_x86/dos/36741.py
--------------------------------------------------------------------------------------
Shellcodes: No Results
```

##### Researching potential vulnerabilities
###### Scanning notes
TCP
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
Information disclosure - 404 page found
OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST (cross site scripting)
mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.

SMB
Samba (2.2.1a)
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)



Webalizer Version 2.01 - http://192.168.81.129/usage/usage_202006.html

SSH
80/443 - 192.168.81.129 - 20:54 06/08/21 - Dedfault web page running Apache on Redhad linux.nI
OpenSSH 2.9p2

###### Order of attack
Port 80 (TCP)
* 80/443 potentially vulnerable to https://www.exploit-db.com/exploits/764 [OpenLuck]
* 
Port 139 (SMB)
* vulnerable to https://www.rapid7.com/db/modules/exploit/linux/samba/trans2open/
* https://www.exploit-db.com/exploits/7
* https://www.exploit-db.com/exploits/10

Port 443 (SSH)

## Appendix
### Tools
| Tool | Methodology | Cmd/Online | Stage | Info |
| ------ | ------ | ------ | ------ | ------ |
| arp-scan | | CMD | S | Sends ARP packets to hosts on the local network and displays any responses that are received. 
| Bluto | Finding subdomains | | R |
| [Breach-parse] | Data breaches | | R |
| [Builtwith] | Fingerprinting | Online | R |
| [Burpsuite] | Fingerprinting | CMD | R | Webproxy that allows us to intercept & modify requests & responses. Connect your browser to burpsuite and any requests made through the browser will be intercepted and stepped through in burpsuite
| crt.sh | Finding subdomains | Online | R | Uses Certificate fingerprinting to identify what subdomains of a domain have certificate 
| Dig | Finding subdomains | | R
| Dirb |  | CMD | S |
| Dirbuster |  | CMD | S |
| Dnsrecon | Target validation | | R
| Foxyproxy | Fingerprinting | | R | 
| Googlefu | Finding subdomains, Fingerprinting | Online | R | Google search syntax
| Gobuster |  | CMD | S |
| [Hunter.io] | Target validation | Online | R | Allows the ability to identify email addresses, email address patterns, users, departments, etc... |
| HaveIBeenPwned | Data breaches | | R | 
| Metasploit (msfconsole) |  | CMD | S | An exploitation framework that also does auxiliary modules, post modules, sample payloads, encoders, etc...
| MSF Venum | | CMD | S |
| Netcat | Fingerprinting | | R
| Nikto |  | CMD | S | Web vulnerability Scanner - good for a basic scan, but can be easily blocked by good basic security
| Nmap | Finding subdomains, Fingerprinting |  | R |
| Netdiscover | | CMD | S | is  an  active/passive  ARP reconnaissance tool, initially developed to gain information about wireless networks without DHCP servers in wardriving scenarios
| Nslookup | Target validation | | R
| searchsploit |  | CMD | S |
| smbclient |  | | s | Attenp to connect to a file share
| [Sublist3r] | Finding subdomains | CMD | R | Provides the ability to find subdomains of any layer of a domain. 
| [Httpprobe] | Target Validation, Finding subdomains | CMD | R | Take a list of domains and probe for working http and https servers 
| [Owasp Amass] | Finding subdomains, Data breaches | CMD | R | An all in one tool
| Wappalyzer | Fingerprinting | Online | R |
| Weleakinfo | Data breaches | | R
| WhatWeb | Fingerprinting | CMD | R | 
| WHOIS | Finding subdomains | | R |

### Famous Attacks

* Wannacry - Eternal Blue (M.S. 17 0 1 0)
  * Utilised a flaw within SMB

### Other
 * Rob Fuller Darknet Diares Podcast - Talks about incorrectly attacking the wrong target.


[Blueteam]: <https://blueteamlabs.online/>
[Breach-parse]: <https://github.com/hmaverickadams/breach-parse>
[Builtwith]: <https://builtwith.com/>
[Bugcrowd]: <https://bugcrowd.com/>
[Course]: <https://www.udemy.com/course/draft/2642432/learn/lecture/16966290#overview>
[Crt.sh]: <https://crt.sh/>
[Cve details]: <https://www.cvedetails.com>
[ExploitDb]: <https://www.exploit-db.com>
[Googlefu]: <https://ahrefs.com/blog/google-advanced-search-operators/>
[hmaverickadams]: https://github.com/hmaverickadams>
[Httpprobe]: <https://github.com/tomnomnom/httprobe>
[Hunter.io]: <https://hunter.io>
[Kioptrix lvl1]: <https://drive.google.com/drive/folders/1jfWv128tX2bJkrhf2-jvhlG9F_bhSgk8>
[OpenLuck]: <https://github.com/heltonWernik/OpenLuck>
[Owasp Amass]: <https://github.com/OWASP/Amass>
[Tryhackme]: <https://tryhackme.com/>
[Rapid7]: <https://www.rapid7.com>
