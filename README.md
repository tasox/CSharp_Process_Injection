# Process Injection techniques using C#

This project contains various process injection techniques using low and higher level Windows API calls. It supports both x86/x64 architectures as well as outputs the memory address of the remote process where the shellcode injected, the payload address, the remote processID and the ThreadId. These information can help the less experienced to practice and understand every technique using tools like x64dbg, x32dbg, processhacker, process explorer etc.

#### Process Access
- [Process Access rights](https://gist.github.com/Rhomboid/0cf96d7c82991af44fda)


#### Steps
- Open powershell (x86/x64) or any other process. See line 27.
- Add your shellcode to the project. 
- The solution platform must be the same as architecture of the process that you want to inject. 
    - For example, If the Powershell is x64 then the project must compiled under x64 platform.

To avoid errors during the compilation, you have to check the 'Allow Unsafe Code' box on the Visual Studio.
![image](https://user-images.githubusercontent.com/9944198/128598233-55193980-93ca-476a-8651-ad6f7b5545ab.png)


#### Categories
- [01. Process Injection (High Level Windows API)](https://github.com/tasox/CSharp_Process_Injection/blob/main/README.md#01-process-injection-high-level-windows-api)
- [02. Process Injection (High Level Windows API)  - Suspends spawned process](https://github.com/tasox/CSharp_Process_Injection/blob/main/README.md#02-process-injection-high-level-windows-api-suspends-the-spawned-process)
- [03. Process Injection (Low Level Windows API), Map a view of a section](https://github.com/tasox/CSharp_Process_Injection#03-process-injection-low-level-windows-api-map-a-view-of-a-section)
- [04. Process Injection (Low Level Windows API), Modify permissions of a section](https://github.com/tasox/CSharp_Process_Injection/blob/main/README.md#04-process-injection-low-level-windows-api-modify-permissions-of-a-section)


### 01. Process Injection (High Level Windows API)

This category contains a remote process injection technique using basic Windows API calls. It supports x86 and x64 architecture and this can defined during the compilation on the Visual Studio. Moreover, this project outputs various information about the remote process injection as well as sets 2 breakpoints, which facilitates the debugging process.

#### API Calls
- OpenProcess
- VirtualAllocEx 
- WriteProcessMemory
- CreateRemoteThread

![image](https://user-images.githubusercontent.com/9944198/128016947-184fe2a9-f8c2-4886-b985-d4e28b4c79bf.png)

![image](https://user-images.githubusercontent.com/9944198/128017226-8dabc072-3b40-4e89-a5e2-ce79e834296a.png)

![image](https://user-images.githubusercontent.com/9944198/128017354-0cf154e0-3109-4db0-9169-521a7c70a7f6.png)

![image](https://user-images.githubusercontent.com/9944198/128017428-ebaa4208-a2df-42b6-b682-fb5d0e9f9867.png)


### 02. Process Injection (High Level Windows API), suspends the spawned process.

This category demonstrates a shellcode injection (x86/x64) into the Windows Update agent (wuauclt.exe), however can be any process that its execution timeframe is too quick and you want to keep it open in order to analyze what is happening in the background. A small trick to achieve this is to suspend process threads. There are only a few changes from the "01" example.

Don't underestimate the simplicity of this method. I encourage you to read this report:
- https://thedfirreport.com/2021/06/20/from-word-to-lateral-movement-in-1-hour/

#### API Calls
- OpenProcess
- VirtualAllocEx 
- WriteProcessMemory
- CreateRemoteThread

![image](https://user-images.githubusercontent.com/9944198/128206032-859920fb-1e74-4d80-8646-14cc25f30b6e.png)

![image](https://user-images.githubusercontent.com/9944198/128205795-058008fe-cc9c-4398-a1ed-d148b3d5cb8b.png)

![image](https://user-images.githubusercontent.com/9944198/128205893-44853aee-d0eb-440e-8190-0aa3709b965c.png)

### 03. Process Injection (Low Level Windows API), Map a view of a section.

This category demonstrates a shellcode injection (x86/x64) into a process of your choice (i.e. explorer.exe). In this scenario lower level of Windows API has been used in order to create a new section and map it to a remote process.

#### API Calls
- OpenProcess
- NtCreateSection
- NtMapViewOfSection
- NtCreateThreadEx (you can also uncomment 'CreateRemoteThread' and use it, instead of 'NtCreateThreadEx')

![image](https://user-images.githubusercontent.com/9944198/128521939-1576b6cf-9714-4126-a290-2b7030dbb33e.png)

![image](https://user-images.githubusercontent.com/9944198/128522102-183a5dbe-8b19-4751-a62e-66609bc26a4c.png)

![image](https://user-images.githubusercontent.com/9944198/128522283-71e9b74f-737d-418e-9540-81d8cadfa552.png)

![image](https://user-images.githubusercontent.com/9944198/128522463-45b2b073-b58d-4a0c-a527-6992c706e28c.png)

![image](https://user-images.githubusercontent.com/9944198/128522549-bd2b8054-6017-4446-8297-84af5b2325da.png)


### 04. Process Injection (Low Level Windows API), Modify permissions of a section.
 
This category demonstrates a shellcode injection (x86/x64) into a process of your choice (i.e. explorer.exe). In this scenario lower level of Windows API has been used in order to create a new section and map it to a remote process afterwards the Windows API call 'NtProtectVirtualMemory' has been called to modify section's permissions.

#### API Calls
- OpenProcess
- NtCreateSection
- NtMapViewOfSection
- NtCreateThreadEx (you can also uncomment 'CreateRemoteThread' and use it, instead of 'NtCreateThreadEx')
- NtProtectVirtualMemory

Before calling the 'NtProtectVirtualMemory'.
![image](https://user-images.githubusercontent.com/9944198/128596418-2503be6d-e342-4811-859a-8b85e3f4bc94.png)

After the call of 'NtProtectVirtualMemory'.
![image](https://user-images.githubusercontent.com/9944198/128596445-7f90ec1f-0eed-40c3-bd8d-90d74a5ada2d.png)



## Resources
- https://github.com/trustedsec/SysmonCommunityGuide/blob/master/create-remote-thread.md
- https://www.ired.team/offensive-security/code-injection-process-injection
- https://www.forrest-orr.net/blog
