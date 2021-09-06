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

### Identifying Technologies
The following tools can be used to identify what technologies are being user for the running of a website/server. [Builtwith], Wapplyzer, WhatWeb
The purpose of this exercise is that identifying what technologies are in use, and identify what versions of those technologise are in user, can help us narrow down the possible attack vectors to take. i.e. Seeing a website running Drupel  in PHP, means that we can look up exploits for Drupel and PHP. 

### Burpsuite 

## Appendix
### Tools
| Tool | Methodology | Cmd/Online | Info |
| ------ | ------ | ------ | ------ |
| Bluto | Finding subdomains |
| [Breach-parse] | Data breaches |
| [Builtwith] | Fingerprinting | Online |
| [Burpsuite] | Fingerprinting | CMD | Webproxy that allows us to intercept & modify requests & responses. Connect your browser to burpsuite and any requests made through the browser will be intercepted and stepped through in burpsuite
| crt.sh | Finding subdomains | Online | Uses Certificate fingerprinting to identify what subdomains of a domain have certificate 
| Dig | Finding subdomains |
| Dnsrecon | Target validation |
| Foxyproxy | Fingerprinting ||
| [Googlefu] | Finding subdomains, Fingerprinting | Online | Google search syntax
| [Hunter.io] | Target validation | Online | Allows the ability to identify email addresses, email address patterns, users, departments, etc... |
| HaveIBeenPwned | Data breaches |
| Nmap | Finding subdomains, Fingerprinting |
| Nslookup | Target validation |
| Netcat | Fingerprinting |
| [Sublist3r] | Finding subdomains | CMD | Provides the ability to find subdomains of any layer of a domain. 
| [Httpprobe] | Target Validation, Finding subdomains | CMD | Take a list of domains and probe for working http and https servers 
| [Owasp Amass] | Finding subdomains, Data breaches | CMD | An all in one tool
| Wappalyzer | Fingerprinting | Online |
| Weleakinfo | Data breaches |
| WhatWeb | Fingerprinting | CMD |
| WHOIS | Finding subdomains |

### Other
 * Rob Fuller Darknet Diares Podcast - Talks about incorrectly attacking the wrong target.

[Blueteam]: <https://blueteamlabs.online/>
[Breach-parse]: <https://github.com/hmaverickadams/breach-parse>
[Builtwith]: <https://builtwith.com/>
[Bugcrowd]: <https://bugcrowd.com/>
[Course]: <https://www.udemy.com/course/draft/2642432/learn/lecture/16966290#overview>
[Crt.sh]: <https://crt.sh/>
[Googlefu]: <https://ahrefs.com/blog/google-advanced-search-operators/>
[hmaverickadams]: https://github.com/hmaverickadams>
[Httpprobe]: <https://github.com/tomnomnom/httprobe>
[Hunter.io]: <https://hunter.io>
[Owasp Amass]: <https://github.com/OWASP/Amass>
[Tryhackme]: <https://tryhackme.com/>
