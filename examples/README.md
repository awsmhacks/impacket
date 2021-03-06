# Example Scripts
Scripts utilizing the impacket library to perform various tasks.

[Remote Execution // Interactive Shells](#remote-execution--interactive-shells)  
[Kerberos // Tickets](#remote-execution--interactive-shells)  
[Windows Secrets // Credential Dumping](#remote-execution--interactive-shells)  
[WMI](#wmi)  
[SMB/MSRPC // Registry // Services](#smbmsrpc--registry--services)  
[MSSQL / TDS](#mssql--tds)  
[Files and Formats](#files--formats)  
[Exploits and Vulnerabilities](#exploits--vulnerabilities)  
[Misc](#misc)  

---------------------------------------------------------------------------------------------------
## Remote Execution // Interactive Shells

### [atexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)   
This example executes a command on the target machine through the Task Scheduler service.   
ATSVC example for some functions implemented, creates, enums, runs, delete jobs.  
Returns the output of such command  


### [dcomexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py)  
A similar approach to psexec but executing commands through DCOM.    
You can select different objects to be used to execute the commands.  
Currently supported objects are:
   1. MMC20.Application (49B2791A-B1AE-4C90-9B8E-E860BA07F889) - Tested Windows 7, Windows 10, Server 2012R2
   2. ShellWindows (9BA05972-F6A8-11CF-A442-00A0C90A8F39) - Tested Windows 7, Windows 10, Server 2012R2
   3. ShellBrowserWindow (C08AFD90-F2A1-11D1-8455-00A0C91F3880) - Tested Windows 10, Server 2012R2  
 


### [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)
A similar approach to psexec w/o using RemComSvc. 
Instantiates a local smbserver to receive the output of the commands.   
This is useful in the situation where the target machine does NOT have a writeable share available.    



### [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)  
A similar approach to smbexec but executing commands through WMI.  
Main advantage here is it runs under the user (has to be Admin)   
account, not SYSTEM, plus, it doesn't generate noisy messages  
in the event log that smbexec.py does when creating a service.  
Drawback is it needs DCOM, hence, I have to be able to access   
DCOM ports at the target machine.  



### [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)
PSEXEC like functionality example using [RemComSvc](https://github.com/kavika13/RemCom)      





---------------------------------------------------------------------------------------------------
## Kerberos // Tickets

### [findDelegation.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/findDelegation.py)
This module will try to find all delegation relationships in a given domain.  
Delegation relationships can provide info on specific users and systems to target, as access to these systems will grant access elsewhere also.    
Unconstrained, constrained, and resource-based constrained delegation types are queried for and displayed. 


### [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py)
This script will attempt to list and get TGTs for those users that have the property
'Do not require Kerberos preauthentication' set (UF_DONT_REQUIRE_PREAUTH).  
For those users with such configuration, a John The Ripper output will be generated so  
you can send it for cracking.  


### [getPac.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getPac.py)
This script will get the PAC of the specified target user just having a normal authenticated user credentials.  
It does so by using a mix of [MS-SFU]'s S4USelf + User to User Kerberos Authentication.  
Original idea (or accidental discovery :) ) of adding U2U capabilities inside a S4USelf by Benjamin Delpy (@gentilkiwi)  


### [getST.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py)
Given a password, hash, aesKey or TGT in ccache, it will request a Service Ticket and save it as ccache  
If the account has constrained delegation (with protocol transition) privileges you will be able to use  
the -impersonate switch to request the ticket on behalf other user (it will use S4U2Self/S4U2Proxy to
request the ticket.)  
Similar feature has been implemented already by Benjamin Delphi (@gentilkiwi) in Kekeo (s4u)  


### [getTGT.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py)
Given a password, hash or aesKey, it will request a TGT and save it as ccache  


### [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)
This module will try to find Service Principal Names that are associated with normal user account.  
Since normal account's password tend to be shorter than machine accounts, and knowing that a TGS request  
will encrypt the ticket with the account the SPN is running under, this could be used for an offline  
bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.  


### [goldenPac.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/goldenPac.py)
MS14-068 Exploit. Kudos to @BiDOrD for pulling it up first!   
Well done :).  
This one also established a SMBConnection and PSEXEcs the   
target.  
A few important things:
1) you must use the domain FQDN or use -dc-ip switch
2) target must be a FQDN as well and matching the target's Ne
3) Just RC4 at the moment - DONE (aes256 added)
4) It won't work on Kerberos-only Domains (but can be fixed)
5) Use WMIEXEC approach instead


### [kintercept.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/kintercept.py)
A tool for intercepting TCP streams and for testing KDC handling  
of PA-FOR-USER with unkeyed checksums in MS Kerberos S4U2Self  
protocol extention (CVE-2018-16860 and CVE-2019-0734).  
The tool listens on a local port (default 88), to which the hijacked  
connections should be redirected (via port forwarding, etc), and sends  
all the packets to the upstream DC server.  
If s4u2else handler is set, the name in PA-FOR-USER padata in every proxied  
packet will be changed to the name specified in the handler's argument.  


### [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)
This script implements a child-domain to forest privilege escalation  
as detailed by Sean Metcalf (@PyroTek3) at https://adsecurity.org/?p=1640. We will  
be (ab)using the concept of Golden Tickets and ExtraSids researched and implemented  
by Benjamin Delpy (@gentilkiwi) in mimikatz (https://github.com/gentilkiwi/mimikatz).  
The idea of automating all these tasks came from @mubix.  


### [ticketConverter.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py)
This script will convert kirbi files (commonly used by mimikatz) into ccache files used by impacket,  
and vice versa.  


### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
This script will create TGT/TGS tickets from scratch or based on a template (legally requested from the KDC)  
allowing you to customize some of the parameters set inside the PAC_LOGON_INFO structure, in particular the  
groups, extrasids, etc.  
Tickets duration is fixed to 10 years from now (although you can manually change it)  




---------------------------------------------------------------------------------------------------
## Windows Secrets // Credential Dumping

### [mimikatz.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mimikatz.py)
Mini shell to control a remote mimikatz RPC server developed by @gentilkiwi  


### [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)
Performs various techniques to dump hashes from the  
remote machine without executing any agent there.  
For SAM and LSA Secrets (including cached creds)  
we try to read as much as we can from the registry  
and then we save the hives in the target system  
(%SYSTEMROOT%\\Temp dir) and read the rest of the  
data from there.  
For NTDS.dit we either:
  a. Get the domain users list and get its hashes
     and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
     call, replicating just the attributes we need.
  b. Extract NTDS.dit via vssadmin executed  with the
     smbexec approach.
     It's copied on the temp dir and parsed remotely.
The script initiates the services required for its working  
if they are not available (e.g. Remote Registry, even if it is   
disabled). After the work is done, things are restored to the   
original state.


### [dpapi.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dpapi.py)
You can unlock masterkeys, credentials and vaults.   
For the three, you will specify the file name (using -file for
masterkeys and credentials, and -vpol and -vcrd for vaults).  
If no other parameter is sent, the contents of these resource will be shown, with their encrypted data as well.  
If you specify a -key blob (in the form of '0xabcdef...') that key will be used to decrypt the contents.  
In the case of vaults, you might need to also provide the user's sid (and the user password will be asked).  
For system secrets, instead of a password you will need to specify the system and security hives.  



---------------------------------------------------------------------------------------------------
## WMI 

### [wmipersist.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmipersist.py)
This script creates/removes a WMI Event Consumer/Filter and link   
between both to execute Visual Basic based on the WQL filter   
or timer specified.


### [wmiquery.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiquery.py)
[MS-WMI] example. It allows to issue WQL queries and  
get description of the objects.  



---------------------------------------------------------------------------------------------------
## SMB/MSRPC // Registry // Services

### [addcomputer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py)
This script will add a computer account to the domain and set its password.  
Allows to use SAMR over SMB (this way is used by modern Windows computer whenadding machines through the GUI) and LDAPS.  
Plain LDAP is not supported, as it doesn't allow setting the password.  


### [getArch.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getArch.py)
This script will connect against a target (or list of targets) machine/s and gather the OS architecture type
installed.  
The trick has been discovered many years ago and is actually documented by Microsoft here:
  https://msdn.microsoft.com/en-us/library/cc243948.aspx#Appendix_A_53
and doesn't require any authentication at all. 


### [lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py)
DCE/RPC lookup sid brute forcer example  


### [netview.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/netview.py)
The idea of this script is to get a list of the sessions  
opened at the remote hosts and keep track of them.  
Coincidentally @mubix did something similar a few years  
ago so credit goes to him (and the script's name ;)).  
Check it out at https://github.com/mubix/netview  
The main difference with our approach is we keep   
looping over the hosts found and keep track of who logged  
in/out from remote servers. Plus, we keep the connections  
with the target systems and just send a few DCE-RPC packets.  
One VERY IMPORTANT thing is:  
YOU HAVE TO BE ABLE TO RESOLV THE DOMAIN MACHINES NETBIOS   
NAMES. That's usually solved by setting your DNS to the   
domain DNS (and the right search domain). 


### [reg.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/reg.py)
Remote registry manipulation tool.  
The idea is to provide similar functionality as the REG.EXE Windows utility.  


### [registry-read.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/registry-read.py)
A Windows Registry Reader Example  


### [rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py)
DCE/RPC endpoint mapper dumper.  
This script will dump the list of RPC endpoints and string bindings registered at the target.   
It will also try to match them with a list of well known endpoints.  


### [rpcmap.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcmap.py)
Scan for listening MSRPC interfaces  


### [samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py)
DCE/RPC SAMR dumper. 
An application that communicates with the Security Account Manager Remote interface from the MSRPC suite.   
It lists system user accounts, available resource shares and other sensitive information exported through this service.  


### [services.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/services.py)
[MS-SCMR] services common functions for manipulating services   
It supports start, stop, delete, status, config, list, create and change.  


### [smbclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py)
Mini shell using some of the SMB funcionality of the library  


### [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py)
Simple SMB Server example.  



---------------------------------------------------------------------------------------------------
## MSSQL / TDS

### [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)
[MS-TDS] & [MC-SQLR] example.  


### [mssqlinstance.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlinstance.py)
[MC-SQLR] example. Retrieves the instances names from the target host  



---------------------------------------------------------------------------------------------------
## Files + Formats

### [esentutl.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/esentutl.py)
ESE utility. Allows dumping catalog, pages and tables.  

### [ntfs-read.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntfs-read.py)
Mini shell for browsing an NTFS volume 



---------------------------------------------------------------------------------------------------
## Exploits // Vulnerabilities

### [exchanger.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/exchanger.py)
A tool for connecting to MS Exchange via RPC over HTTP v2  


### [goldenPac.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/goldenPac.py)
MS14-068 Exploit. Kudos to @BiDOrD for pulling it up first!   
Well done :).  
This one also established a SMBConnection and PSEXEcs the   
target.  
A few important things:
1) you must use the domain FQDN or use -dc-ip switch
2) target must be a FQDN as well and matching the target's Ne
3) Just RC4 at the moment - DONE (aes256 added)
4) It won't work on Kerberos-only Domains (but can be fixed)
5) Use WMIEXEC approach instead



---------------------------------------------------------------------------------------------------
## Misc

### [GetADUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetADUsers.py)
This script will gather data about the domain's users and their corresponding email addresses.  
It will also include some extra information about last logon and last password set attributes.  
You can enable or disable the the attributes shown in the final table by changing the values in line 184 and
headers in line 190.  
If no entries are returned that means users don't have email addresses specified.  
If so, you can use the -all-users parameter.  



### [karmaSMB.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/karmaSMB.py)
The idea of this script is to answer any file read request with a set of predefined contents based on the extension asked.    
When executing this script w/o a config file the pathname file contents will be sent for every request.     
If a config file is specified, format should be this way:
   <extension> = <pathname>
for example:
   bat = /tmp/batchfile
   com = /tmp/comfile
   exe = /tmp/exefile



### [mqtt_check.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mqtt_check.py)
Simple MQTT example aimed at playing with different login options.  
Can be converted into a account/password brute forcer quite easily.  



### [nmapAnswerMachine.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/nmapAnswerMachine.py)
Responds to nmap scans as specified host  



### [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py)
This module performs the SMB Relay attacks originally discovered  
by cDc extended to many target protocols (SMB, MSSQL, LDAP, etc).  
It receives a list of targets and for every connection received it  
will choose the next target and try to relay the credentials. Also, if  
specified, it will first to try authenticate against the client connecting  
to us.  



### [ping.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ping.py)
Simple ICMP ping.  



### [ping6.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ping6.py)
Simple ICMP6 ping.  



### [rdp_check.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rdp_check.py)
[MS-RDPBCGR] and [MS-CREDSSP] partial implementation   
just to reach CredSSP auth. This example test whether  
an account is valid on the target host.  


 
### [sambaPipe.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/sambaPipe.py)
This script will exploit CVE-2017-7494, uploading and executing the shared library specified by the user through
the -so parameter.  
The script will use SMB1 or SMB2/3 depending on the target's availability. Also, the target share pathname is
retrieved by using NetrShareEnum() API with info level 2.  



### [smbrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbrelayx.py)
This module performs the SMB Relay attacks originally discovered  
by cDc. It receives a list of targets and for every connection received it   
will choose the next target and try to relay the credentials. Also, if  
specified, it will first to try authenticate against the client connecting   
to us.  



### [sniff.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/sniff.py)
Simple packet sniffer.   
This packet sniffer uses the pcap library to listen for packets in  
transit over the specified interface. The returned packages can be  
filtered according to a BPF filter (see tcpdump(3) for further  
information on BPF filters).  


### [sniffer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/sniffer.py)
Simple packet sniffer.  
This packet sniffer uses a raw socket to listen for packets  
in transit corresponding to the specified protocols.  


### [split.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/split.py)
Pcap dump splitter.  
This tools splits pcap capture files into smaller ones, one for each  
different TCP/IP connection found in the original.  





 



