# CSharp Projects

This project contains a remote process injection tehnique using basic Windows API calls. It supports x86 and x64 architecture and this can defined during the compilation on the Visual Studio. Moreover, outputs the memory address of the remote process where the shellcode injected as well as the ThreadId, which was created in order to facilitate the debugging process.

### Steps

- Open powershell (x86/x64) or any other process. See line 27.
- Add your shellcode to the project. 
- The solution platform must be the same as architecture of the process that you want to inject. 
    - For example, If the Powershell is x64 then the project must compiled under x64 platform.

