# Example Scripts
Scripts utilizing the impacket library to perform various tasks.


### addcomputer.py
This script will add a computer account to the domain and set its password.  
Allows to use SAMR over SMB (this way is used by modern Windows computer whenadding machines through the GUI) and LDAPS.  
Plain LDAP is not supported, as it doesn't allow setting the password.  


### atexec.py
ATSVC example for some functions implemented, creates, enums, runs, delete jobs.  
This example executes a command on the target machine through the Task Scheduler service.   
Returns the output of such command  


### dcomexec.py
A similar approach to psexec but executing commands through DCOM.  
You can select different objects to be used to execute the commands.  
Currently supported objects are:
   1. MMC20.Application (49B2791A-B1AE-4C90-9B8E-E860BA07F889) - Tested Windows 7, Windows 10, Server 2012R2
   2. ShellWindows (9BA05972-F6A8-11CF-A442-00A0C90A8F39) - Tested Windows 7, Windows 10, Server 2012R2
   3. ShellBrowserWindow (C08AFD90-F2A1-11D1-8455-00A0C91F3880) - Tested Windows 10, Server 2012R2


### dpapi.py
You can unlock masterkeys, credentials and vaults.   
For the three, you will specify the file name (using -file for
masterkeys and credentials, and -vpol and -vcrd for vaults).  
If no other parameter is sent, the contents of these resource will be shown, with their encrypted data as well.  
If you specify a -key blob (in the form of '0xabcdef...') that key will be used to decrypt the contents.  
In the case of vaults, you might need to also provide the user's sid (and the user password will be asked).  
For system secrets, instead of a password you will need to specify the system and security hives.  


## esentutl.py
ESE utility. Allows dumping catalog, pages and tables.  


## exchanger.py
A tool for connecting to MS Exchange via RPC over HTTP v2  


## findDelegation.py
This module will try to find all delegation relationships in a given domain.  
Delegation relationships can provide info on specific users and systems to target, as access to these systems will grant access elsewhere also.    
Unconstrained, constrained, and resource-based constrained delegation types are queried for and displayed.  


## GetADUsers.py
This script will gather data about the domain's users and their corresponding email addresses.  
It will also include some extra information about last logon and last password set attributes.  
You can enable or disable the the attributes shown in the final table by changing the values in line 184 and
headers in line 190.  
If no entries are returned that means users don't have email addresses specified.  
If so, you can use the -all-users parameter.  


### getArch.py
This script will connect against a target (or list of targets) machine/s and gather the OS architecture type
installed.  
The trick has been discovered many years ago and is actually documented by Microsoft here:
  https://msdn.microsoft.com/en-us/library/cc243948.aspx#Appendix_A_53
and doesn't require any authentication at all.  


### GetNPUsers.py
This script will attempt to list and get TGTs for those users that have the property
'Do not require Kerberos preauthentication' set (UF_DONT_REQUIRE_PREAUTH).  
For those users with such configuration, a John The Ripper output will be generated so  
you can send it for cracking.  


## getPac.py
This script will get the PAC of the specified target user just having a normal authenticated user credentials.  
It does so by using a mix of [MS-SFU]'s S4USelf + User to User Kerberos Authentication.  
Original idea (or accidental discovery :) ) of adding U2U capabilities inside a S4USelf by Benjamin Delpy (@gentilkiwi)  


### getST.py
Given a password, hash, aesKey or TGT in ccache, it will request a Service Ticket and save it as ccache  
If the account has constrained delegation (with protocol transition) privileges you will be able to use  
the -impersonate switch to request the ticket on behalf other user (it will use S4U2Self/S4U2Proxy to
request the ticket.)  
Similar feature has been implemented already by Benjamin Delphi (@gentilkiwi) in Kekeo (s4u)  


### getTGT.py
Given a password, hash or aesKey, it will request a TGT and save it as ccache  


### GetUserSPNs.py
This module will try to find Service Principal Names that are associated with normal user account.  
Since normal account's password tend to be shorter than machine accounts, and knowing that a TGS request  
will encrypt the ticket with the account the SPN is running under, this could be used for an offline  
bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.  


## goldenPac.py
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


### karmaSMB.py
The idea of this script is to answer any file read request  
with a set of predefined contents based on the extension   
asked, regardless of the sharename and/or path.  
When executing this script w/o a config file the pathname   
file contents will be sent for every request.   
If a config file is specified, format should be this way:
   <extension> = <pathname>
for example:
   bat = /tmp/batchfile
   com = /tmp/comfile
   exe = /tmp/exefile
The SMB2 support works with a caveat. If two different  
filenames at the same share are requested, the first  
one will work and the second one will not work if the request  
is performed right away. This seems related to the   
QUERY_DIRECTORY request, where we return the files available.  
In the first try, we return the file that was asked to open.  
In the second try, the client will NOT ask for another   
QUERY_DIRECTORY but will use the cached one. This time the new file  
is not there, so the client assumes it doesn't exist.  
After a few seconds, looks like the client cache is cleared and  
the operation works again. Further research is needed trying  
to avoid this from happening.  


### kintercept.py
A tool for intercepting TCP streams and for testing KDC handling  
of PA-FOR-USER with unkeyed checksums in MS Kerberos S4U2Self  
protocol extention (CVE-2018-16860 and CVE-2019-0734).  
The tool listens on a local port (default 88), to which the hijacked  
connections should be redirected (via port forwarding, etc), and sends  
all the packets to the upstream DC server.  
If s4u2else handler is set, the name in PA-FOR-USER padata in every proxied  
packet will be changed to the name specified in the handler's argument.  


### lookupsid.py
DCE/RPC lookup sid brute forcer example  


### mimikatz.py
Mini shell to control a remote mimikatz RPC server developed by @gentilkiwi  


### mqtt_check.py
Simple MQTT example aimed at playing with different login options.  
Can be converted into a account/password brute forcer quite easily.  


### mssqlclient.py
[MS-TDS] & [MC-SQLR] example.  


### mssqlinstance.py
[MC-SQLR] example. Retrieves the instances names from the target host  


### netview.py
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


### nmapAnswerMachine.py
Responds to nmap scans as specified host  


## ntfs-read.py
Mini shell for browsing an NTFS volume  


### ntlmrelayx.py
This module performs the SMB Relay attacks originally discovered  
by cDc extended to many target protocols (SMB, MSSQL, LDAP, etc).  
It receives a list of targets and for every connection received it  
will choose the next target and try to relay the credentials. Also, if  
specified, it will first to try authenticate against the client connecting  
to us.  


### ping.py
Simple ICMP ping.  


### ping6.py
Simple ICMP6 ping.  


### psexec.py
PSEXEC like functionality example using RemComSvc (https://github.com/kavika13/RemCom)  


### raiseChild.py
This script implements a child-domain to forest privilege escalation  
as detailed by Sean Metcalf (@PyroTek3) at https://adsecurity.org/?p=1640. We will  
be (ab)using the concept of Golden Tickets and ExtraSids researched and implemented  
by Benjamin Delpy (@gentilkiwi) in mimikatz (https://github.com/gentilkiwi/mimikatz).  
The idea of automating all these tasks came from @mubix.  


### rdp_check.py
[MS-RDPBCGR] and [MS-CREDSSP] partial implementation   
just to reach CredSSP auth. This example test whether  
an account is valid on the target host.  


### reg.py
Remote registry manipulation tool.  
The idea is to provide similar functionality as the REG.EXE Windows utility.  


## registry-read.py
A Windows Registry Reader Example  


### rpcdump.py
DCE/RPC endpoint mapper dumper.  


### rpcmap.py
Scan for listening MSRPC interfaces  


### sambaPipe.py
This script will exploit CVE-2017-7494, uploading and executing the shared library specified by the user through
the -so parameter.  
The script will use SMB1 or SMB2/3 depending on the target's availability. Also, the target share pathname is
retrieved by using NetrShareEnum() API with info level 2.  


### samrdump.py
DCE/RPC SAMR dumper.


### secretsdump.py
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


### services.py
[MS-SCMR] services common functions for manipulating services  


### smbclient.py
Mini shell using some of the SMB funcionality of the library  


### smbexec.py
A similar approach to psexec w/o using RemComSvc. The technique is described here  
https://www.optiv.com/blog/owning-computers-without-shell-access
Our implementation goes one step further, instantiating a local smbserver to receive the  
output of the commands. This is useful in the situation where the target machine does NOT  
have a writeable share available.  
Keep in mind that, although this technique might help avoiding AVs, there are a lot of  
event logs generated and you can't expect executing tasks that will last long since Windows  
will kill the process since it's not responding as a Windows service.  
Certainly not a stealthy way.  


### smbrelayx.py
This module performs the SMB Relay attacks originally discovered  
by cDc. It receives a list of targets and for every connection received it   
will choose the next target and try to relay the credentials. Also, if  
specified, it will first to try authenticate against the client connecting   
to us.  


### smbserver.py
Simple SMB Server example.  


### sniff.py
Simple packet sniffer.   
This packet sniffer uses the pcap library to listen for packets in  
transit over the specified interface. The returned packages can be  
filtered according to a BPF filter (see tcpdump(3) for further  
information on BPF filters).  


### sniffer.py
Simple packet sniffer.  
This packet sniffer uses a raw socket to listen for packets  
in transit corresponding to the specified protocols.  


### split.py
Pcap dump splitter.  
This tools splits pcap capture files into smaller ones, one for each  
different TCP/IP connection found in the original.  


### ticketConverter.py
This script will convert kirbi files (commonly used by mimikatz) into ccache files used by impacket,  
and vice versa.  


### ticketer.py
This script will create TGT/TGS tickets from scratch or based on a template (legally requested from the KDC)  
allowing you to customize some of the parameters set inside the PAC_LOGON_INFO structure, in particular the  
groups, extrasids, etc.  
Tickets duration is fixed to 10 years from now (although you can manually change it)  


### wmiexec.py
A similar approach to smbexec but executing commands through WMI.  
Main advantage here is it runs under the user (has to be Admin)   
account, not SYSTEM, plus, it doesn't generate noisy messages  
in the event log that smbexec.py does when creating a service.  
Drawback is it needs DCOM, hence, I have to be able to access   
DCOM ports at the target machine.  


### wmipersist.py
This script creates/removes a WMI Event Consumer/Filter and link   
between both to execute Visual Basic based on the WQL filter   
or timer specified.


### wmiquery.py
[MS-WMI] example. It allows to issue WQL queries and  
get description of the objects.  

