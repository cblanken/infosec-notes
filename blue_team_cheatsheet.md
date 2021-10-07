# Blue Team Cheatsheet

## Blogs / Other Resources
- [DFIR Diva](https://dfirdiva.com/)
- [threathunting.se](https://www.threathunting.se/)


## Query Languages / DSLs
- [EQL(Event Query Language)](https://eql.readthedocs.io/en/latest/)

## Scanning
- [Nessus](https://docs.tenable.com/nessus/Content/GetStarted.htm): a vulnerability scanner used in assessments and pen tests
- [OpenVAS](https://openvas.org/): Open vulnerability Assessment Scanner of the Greenbone Vulnerability Management (GVM) Solution
- [Greenbone Docs](https://docs.greenbone.net/)

## System Monitoring
- [SysMon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk](https://docs.splunk.com/Documentation?_ga=2.100904193.1601637958.1597684046-190830518.1518030052)

## Threat Management, Intelligence, and Hunting
- [Active Countermeasures Network Threat Hunter Training](https://www.activecountermeasures.com/wp-content/uploads/2021/08/Network-Threat-Hunting-202108.pdf): [local pdf](docs/Network-Threat-Hunting-202108.pdf)
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [Greynoise](https://www.greynoise.io/)
- [AbuseIPDB](https://www.abuseipdb.com/): db of IPs displaying malicious behavior
- [Talos Reputation Center](https://talosintelligence.com/reputation_center/lookup)
- [MITRE](https://www.mitre.org/)
    - [MITRE CVE](https://cve.mitre.org/): cyber common vulnerabilites and exploitations
    - [MITRE ATT&CK](https://attack.mitre.org/): 
    - [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/): tool to visualize defensive coverage and map attacker tactics and techniques
    - [MITRE CAR (Cyber Analytics Repository)](https://car.mitre.org/): knowledge base of analytics based on the MITRE ATT&CK adversary model
    - [MITRE Shield](https://shield.mitre.org/) / [MITRE Engage](https://engage.mitre.org/): defensive knowledge base 
- [BZAR](https://github.com/mitre-attack/bzar): Bro/Zeek ATT&CK-based analytics and reporting
- [yara (Yet Another Ridiculous Acronym_)](https://github.com/virustotal/yara): the pattern-matching swiss knife
- ISACs (Information Sharing and Anaylysis Centers)
    - [US-CERT](https://us-cert.cisa.gov/)
    - [AlienVAult OTX](https://otx.alienvault.com/)
    - [ThreatConnect]()
    - [MISP](https://www.misp-project.org/)

## Incident Response

## Packet / Network Analysis
- [tcpdump](https://www.tcpdump.org/)
- [Wireshark](https://www.wireshark.org/)
- [tshark](https://tshark.dev/)
- [zeek](https://docs.zeek.org/en/master/)
- [RITA (Real Intelligence Threat Analytics)](https://github.com/activecm/rita): [Webcast](https://www.activecountermeasures.com/webcasts/09-09-2020-acm-webcast-getting-started-with-rita/)
- [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng): dynamic network analysis tool

## Malware Analysis
- [Binary Exploitation](binary_exploitation.md)
- [YARA (Yet Another Ridiculous Acronym)](https://virustotal.github.io/yara/): a tool to help identify and classify malware
    - [LOKI](https://github.com/Neo23x0/Loki): simple IOC and YARA Scanner
    - [THOR Lite](https://www.nextron-systems.com/thor-lite/): free IOC and YARA Scanner
    - [Fenrir](https://github.com/Neo23x0/Fenrir): free IOC and YARA Scanner (bash script)
    - [VALHALLA](https://valhalla.nextron-systems.com/): YARA feed hosted by Nextron Systems (Florian Roth)
- [Cuckoo Sandbox](https://cuckoosandbox.org/): automated malware analysis system and sandbox
- [Python PE Module](https://pypi.org/project/pefile/): all PE file basic structures in Python
- [pestudio](https://www.winitor.com/): malware assessment tool
- [MalwareBazaar](https://bazaar.abuse.ch/): malware sample database
- [REMnux](https://docs.remnux.org/): linux malware analysis toolkit distro

## Windows 
### [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/)
- [Live Sysinternals](https://live.sysinternals.com/): run sysinternals applications from the internet
- Networking Utilities
    - [TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview)
- Process Utilities
    - [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
    - [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)
    - [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)
    - [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
    - [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
- Security Utilities
    - [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- System Information
    - [PsInfo](https://docs.microsoft.com/en-us/sysinternals/downloads/psinfo)
    - [WinObj](https://docs.microsoft.com/en-us/sysinternals/downloads/winobj)
- Misc
    - [BgInfo](https://docs.microsoft.com/en-us/sysinternals/downloads/bginfo): display system info on the desktop background
    - [RegJump](https://docs.microsoft.com/en-us/sysinternals/downloads/regjump): cmdlet that opens the `regedit` to the given path
    - [Strings](https://docs.microsoft.com/en-us/sysinternals/downloads/strings): similar to Linux `strings`
### Windows Event Logs
- Windows event logs are usually stored in `.evt` or `.evtx` files in `C:\Windows\System32\winevt\Logs`
- The logs can be accessed with:
    1. Event Viewer (can be launched with `eventvwr.msc`)
    1. `Wevtutil.exe` (cmd tool)
    1. `Get-WinEvent` (PowerShell cmdlet)
- There are 5 [types of events](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-types):
    1. Error: a significant problem e.g. a service that fails to load on startup
    1. Warning: not necessarily significant but could cause issues later
    1. Information: describes successful operation of an app, driver, or service
    1. Success Audit: record of an successful audited security access
    1. Failure Audit: record of an failed audited security access
- Important Events to watch out for
     - Windows Powershell
        - 104: indicator of logs being clearted with 
        - 400: indicator of Powershell downgrade attack
- [Events to Monitor](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [Windows 10 and Windows Server 2016 security auditing reference](https://www.microsoft.com/en-us/download/confirmation.aspx?id=52630)
- [Command line process auditing](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing#try-this-explore-command-line-process-auditing)
- [PowerShell ♥ the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/) 
- [Tampering with Windows Event Tracing](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63?gi=24175d4957a9)
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)

### Sysmon
- Start Sysmon with config file: `Sysmon.exe -accepteula -i sysmonconfig-export.xml`
- List of the most important Events by ID that are analyzed by Sysmon
    - 1: Process Creation
        ```xml
        <!-- exclude svchost.exe process from event logs -->
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="exclude">
                <CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
            </ProcessCreate>
        </RuleGroup>
        ```
    - 3: Network Connection: looks for events that occur remotely including suspicious binaries and opened ports
        ```xml
        <!-- identify suspicous network connection over port 4444 (commonly used by Metasploit) -->
        <RuleGroup name="" groupRelation="or">
            <NetworkConnect onmatch="include">
                <Image condition="image">nmap.exe</Image>
                <DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>
            </NetworkConnect>
        </RuleGroup>
        ```
    - 7: Image Loaded:
        ```xml
        <!-- look for DLLs that have been loaded in the \Temp\ directory -->
        <RuleGroup name="" groupRelation="or">
            <ImageLoad onmatch="include">
                <ImageLoaded condition="contains">\Temp\</ImageLoaded>
            </ImageLoad>
        </RuleGroup>
        ```
    - 8: CreateRemoteThread: monitor for processes injecting code into other processes
        ```xml
        <!-- look at the memory address for an ending condition which could indicate a Cobalt Strike beacon-->
        <RuleGroup name="" groupRelation="or">
            <CreateRemoteThread onmatch="include">
                <StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>
                <SourceImage condition="contains">\</SourceImage>
            </CreateRemoteThread>
        </RuleGroup>
        ```
    - 11: File Created: log events when files are created or overwritten
    - 12/13/14: Registry Event: looks for changes or modifiation to the registry
    - 15: FileCreateStreamHash: look for any files created in a alternate data stream
    - 22: DNS Event: log all DNS queries and events
    
