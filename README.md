# Process Injection techniques using C#

This project contains various process injection tehniques using low and higher level Windows API calls. It supports both x86/x64 architectures as well as outputs the memory address of the remote process where the shellcode injected, the payload address, the remote processID and the ThreadId. These information can help the less experienced to practice and understand every technique using tools like x64dbg, x32dbg, processhacker, process explorer etc.

### Standard Process Injection (High Level Windows API)

This project contains a remote process injection tehnique using basic Windows API calls. It supports x86 and x64 architecture and this can defined during the compilation on the Visual Studio. Moreover, this project outputs various information about the remote process injection as well as sets 2 breakpoints, which facilitates the debugging process.

#### Steps
- Open powershell (x86/x64) or any other process. See line 27.
- Add your shellcode to the project. 
- The solution platform must be the same as architecture of the process that you want to inject. 
    - For example, If the Powershell is x64 then the project must compiled under x64 platform.

![image](https://user-images.githubusercontent.com/9944198/128016947-184fe2a9-f8c2-4886-b985-d4e28b4c79bf.png)

![image](https://user-images.githubusercontent.com/9944198/128017226-8dabc072-3b40-4e89-a5e2-ce79e834296a.png)

![image](https://user-images.githubusercontent.com/9944198/128017354-0cf154e0-3109-4db0-9169-521a7c70a7f6.png)

![image](https://user-images.githubusercontent.com/9944198/128017428-ebaa4208-a2df-42b6-b682-fb5d0e9f9867.png)
