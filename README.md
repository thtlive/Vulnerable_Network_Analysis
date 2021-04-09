# Vulnerable_Network_Analysis
Attack, defense and analysis of a vulnerable network

# RED TEAM

# Exposed Services
Initial network scan for host ip  : nmap -sP 192.168.1.*/24

Nmap scan results for each machine reveal these open services and OS details:

nmap -sV 192.168.1.110  (Target 1)
nmap -sV 192.168.1.115  (Target 2)

This scan identifies the services below as potential points of entry:
- Target 1 & 2 (exposed services)
ports 22,80,111,139 and 445 are open.

The following vulnerabilities were identified on target 1;

- Easy to guess password and username 
- Mysql database password is easy to find and use. It should be encrypted (using RSA or AES) to provide an extra layer of security
- Several ports are open or showing as open. There are known vulnerabilities for these ports that attackers can take advantage of.   111, 139 and 445 are critical. 

# Exploitation

The Red Team was able to penetrate Target 1 and retrieve the following confidential data:

- Enumerate users using ‘wpscan --url 192.168.1.110/wordpress --enumerate u’ 

- ssh michael@192.168.1.110 with password: “michael” (weak and and easy to guess)

- use grep to find the first flag in the html directory after successfully logging in as Michael.

Found flag2.txt by sniffing through directories still logged in as Michael. Finally found flag2 sitting in the var/www/ folder.

- In the html directory, nano wp-config.php to find the username and password for MySQL database

- Run mysql -u root -p to log into MySQL using the password discovered above.

- Show databases; use wordpress; show tables;

Navigate through the tables for any flags/hashes.  

- Select * from wp_posts;

Found both flags 3 and 4 in the wp_posts table. 

- select * from wp_users;

Found both hashes for Michael and Steven, used john the ripper to unhash the passwords.

Secure a user shell as the user whose password you cracked

- Spawn a python shell with the command ‘python -c import pty;pty.spawn(“/bin/bash”)’

- Escalate to root. One flag can be discovered after this step.

Alternatively,  we can use the find command to find flag 2and 4 by running "find / -type f -name “flag*”"


# BLUE TEAM

Network Topology
The following machines were identified on the network:
- Target 1
Operating System: Linux (Apache httpd 2.4.10 (Debian))
Purpose: Apache web server/ Wordpress website host
IP Address: 192.168.1.110

- Target 2
Operating System: Linux (Apache httpd 2.4.10 (Debian))
Purpose: 2nd Apache web server/ Wordpress website host
IP Address: 192.168.1.115

- HyperV
Operating System: Windows
Purpose: Azure Cloud Jump Box
IP Address: 192.168.1.1

- Attacker
Operating System: Kali Linux
Purpose: Attacking Machine
IP Address: 192.168.1.90

- ELK
Operating System: Linux (Ubuntu)
Purpose: SIEMs for analyzing logs from beats
IP Address: 192.168.1.100 

# Description of Targets

There are two vulnerable targets on this network; Target 1 &  2: 

Both targets are Apache web servers and have ssh enabled. So, ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:

# Monitoring the Targets
Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

- Name of Alert 1: Excessive http errors
**Metric**: metricbeat
**Threshold**: 400/5mins
**Vulnerability Mitigated**: brute-force attack
**Reliability**: Does this alert generate lots of false positives/false negatives? No 
**Rate**: High if threshold is set right.

- Name of Alert 2: http request size monitor 
**Metric**: metricbeat
**Threshold**: 400/5mins
**Vulnerability Mitigated**: DDoS
**Reliability**: Does this alert generate lots of false positives/false negatives? 
**Rate**: High

- Name of Alert 3: cpu usage monitor
**Metric**: metricbeat
**Threshold**:max system.process.cpu.total.pct above 0.5 in last 5mins
**Vulnerability Mitigated**: unauthorized ssh access and root escalation
**Reliability**: Does this alert generate lots of false positives/false negatives? No, the threshold has to be set properly.
**Rate**: high reliability.


## Suggestions for Going Further
The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats, identified by the alerts above. In addition to watching for occurrences of such threats, the network should be hardened against them. The Blue Team suggests that IT implement the fixes below to protect the network:
● Vulnerability 1: Port 111 (Portmapper) rpcbind
Patch: install special-security-package with apt-get
Why It Works: special-security-package scans the system for viruses every day
Other suggestions: add IPTables to deny TCP connection of unwanted IP ranges
● Vulnerability 2: Port 139 (NetBIOS) NBSTAT
Patch: chmod 600 /var/www/html/wordpress/wp-config.php
Why It Works: By changing the permissions on the config file, only the owner would have full access while all other privileges would be denied to all outside users.
Other suggestions: Disable file and printer sharing, block ports 135-139 completely, use complex passwords
● Vulnerability 3: Port 445 (SMB)
Patch: restrict access to TCP port 445 (SMB)
Why it Works: Prevents file and printer sharing from unauthorized users
Other suggestions: delete HKLM\System\CurrentControlSet\Services\NetBT\Parameters\TransportBindName in the Windows Registry



## NETWORK ANALYSIS

Time Thieves
You must inspect your traffic capture to answer the following questions:
- What is the domain name of the users' custom site? mysocalledchaos.com
- What is the IP address of the Domain Controller (DC) of the AD network? 10.6.12.12
- What is the name of the malware downloaded to the 10.6.12.203 machine? june11.dll
- Upload the file to VirusTotal.com.
- What kind of malware is this classified as? Trojan Horse


Vulnerable Windows Machine
Find the following information about the infected Windows machine:
- Host name: ROTTERDAM-PC
- IP address: 172.16.4.205
- MAC address: 00:59:07:b0:63:a4
- What is the username of the Windows user whose computer is infected? matthijs.devries
- What are the IP addresses used in the actual infection traffic? 172.16.4.205, 166.62.111.64, 185.243.115.84


Illegal Downloads
IT was informed that some users are torrenting on the network. The Security team does not forbid the use of torrents for legitimate purposes, such as downloading operating systems. However, they have a strict policy against copyright infringement. IT shared the following about the torrent activity:
The machines using torrents live in the range 10.0.0.0/24 and are clients of an AD domain.
The DC of this domain lives at 10.0.0.2 and is named DogOfTheYear-DC.
The DC is associated with the domain dogoftheyear.net.
Find the following information about the machine with IP address 10.0.0.201:
- MAC address :  00:16:17:18:66:C8
- Windows username :  Blanco-Desktop
- OS version : Win64
- Which torrent file did the user download? Betty_Boop_Rythm_on_the_Reservation.avi.torrent

