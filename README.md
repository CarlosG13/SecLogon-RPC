# Talking directly to SecLogon through RPC

## Introduction

This research focuses on analyzing the undocumented `_SECONDARYLOGONINFOW` structure and newly identified members of `_SECL_REQUEST`, and on developing an RPC client to interact directly with `SecLogon`. The goal is to dive into some interesting aspects of RPC and Windows internals in general.

## CreateProcessWithTokenW/LogonW

If we take a look at the main differences between `CreateProcessWithTokenW/LogonW (both part of advapi32.dll)` and `CreateProcessAsUser`, we may think that the only differ in the privileges that the caller must have in its token. According to Microsoft: 

> The process that calls `CreateProcessWithTokenW` must have the **SE_IMPERSONATE_NAME** privilege. If this function fails with **ERROR_PRIVILEGE_NOT_HELD (1314)**, use the `CreateProcessAsUser` or `CreateProcessWithLogonW` function instead. Typically, the process that calls `CreateProcessAsUser` must have the **SE_INCREASE_QUOTA_NAME** privilege and may require the **SE_ASSIGNPRIMARYTOKEN_NAME** privilege if the token is not assignable. 

Nevertheless, there are other crucial aspects that we must consider. For example, according to Windows Internals 7th edition:

Both `CreateProcessWithTokenW/LogonW` call the **Secondary Logon Service (seclogon.dll, hosted in SvcHost.exe)** by making a Remote Procedure Call (RPC) through the `SeclCreateProcessWithLogonW` function to do the actual process creation. `SeclCreateProcessWithLogonW` calls `SlrCreateProcessWithLogon` which in turn ends up calling `CreateProcessAsUser`.

<img width="1583" height="879" alt="image" src="https://github.com/user-attachments/assets/f8bd8466-5826-49bf-a4a0-c7c8b0c2f9f7" />

## PPID Spoofing Introduction

When do we use these functions of the windows subsystem? For example, when we leverage the `runas` utility to create a process by specifying new **logon credentials**. Take the following example:

> runas /netonly /user:internals.local\houdini notepad.exe

In the above example, we are creating a new process (notepad.exe) with new credentials and **logon type 9**. If we inspect the process tree, it will appear to have a non-existent parent process, since the original parent was **runas.exe**, even though **SvcHost.exe** was the process that actually spawned it through `CreateProcessAsUser`. This happens due to **PPID spoofing**.

<img width="579" height="467" alt="image" src="https://github.com/user-attachments/assets/e8e6a895-9177-4d81-8588-825efdac64ef" />

Before Windows Vista there was no way to perform **PPID spoofing** via the Windows APIs. Vista added opaque lists of process and thread attribute lists managed with an API: `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `DeleteProcThreadAttributeList`. This list is attached to process creation as member of `STARTUPINFOEX`:

```C++
typedef struct _STARTUPINFOEXW {
  STARTUPINFOW                 StartupInfo;
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXW, *LPSTARTUPINFOEXW;
```
Some example of process attributes are:

- Processor group affinity
- Parent process to inherit from (PPID Spoof)
- Mitigation policies


If we take a moment to analyze how **PPID spoofing** occurs with `Secondary Logon`, we might ask: how does **SvcHost.exe** actually do it if I never specified an attribute list through `STARTUPINFOEX`? Maybe `CreateProcessWithTokenW` or `CreateProcessWithLogonW` add this atttribute list internally? Not exactly. So what would happen if I do specify a **STARTUPINFOEX** to these APIs to spoof my parent? Would that work? Again, not exactly, even though the official Microsoft documentation states that you can pass a pointer to a `STARTUPINFOEX` structure:

```
[in] lpStartupInfo

A pointer to a STARTUPINFO or STARTUPINFOEX structure.
```

Unfortunately, in this case the documentation is not quite accurate :/, `CreateProcessWithLogonW/TokenW` do not like the idea of you passing a `STARTUPINFOEX` structure, why is that? As some of you may already know, the only way for the process creation APIs to take the `STARTUPINFOEX` (i.e., your attribute list) into account is that you MUST specify `EXTENDED_STARTUPINFO_PRESENT`; but both APIs sadly check for this flag and, if it is set, they refuse to make the RPC call to the `Secondary Logon` service and instead return `ERROR_INVALID_PARAMETER (87)`. What I mean is, the following code is going to fail:

```C
	CreateProcessWithTokenW(duplicateTokenHandle,
		0x0,
		nullptr,
		lpCommandLine,
		EXTENDED_STARTUPINFO_PRESENT,
		nullptr,
		nullptr,
		&sie.StartupInfo,
		&pi);
```

How do we prove this? First off, both APIs end up calling the `CreateProcessWithLogonCommonW` function, as shown below:

<img width="980" height="573" alt="CreateProcessWithLogonCommonW-Pt1" src="https://github.com/user-attachments/assets/0e72502c-a487-42bd-9068-afd774efe4e8" />

`CreateProcessWithLogonCommonW` performs a bitwise AND to test if `EXTENDED_STARTUPINFO_PRESENT` and other flags were present, and if they were, the function returns with `ERROR_INVALID_PARAMETER (87)`:

<img width="1112" height="356" alt="CreateProcessWithLogonCommonW-Pt2" src="https://github.com/user-attachments/assets/21858627-174b-4a9f-9ef2-7f05cc61520e" />

This does mean that, in practice, we can only perform **PPID spoofing** via `CreateProcess` or `CreateProcessAsUser`. When I realized this, several questions came to mind about why `CreateProcessWithToken/LogonW` have this limitation. My guess was:

1. Maybe it is not intended for us to leverage **SvcHost.exe** to perform **PPID spoofing** by specifying an arbitrary process (of course, assuming we have the required privileges to obtain a handle with PROCESS_CREATE_PROCESS).

2. Perhaps, the way that **SvcHost** handles this is through some other mechanisms and/or structures that we aren't completely aware of. 

The thing is, are we at a dead end? Or can we force **SvcHost.exe (SecLogon)** to perform **PPID spoofing** for us? Some may say: 'What's the whole point? Why not just leverage `CreateProcess` or `CreateProcessAsUser` instead?' The whole point is to use **SvcHost.exe (SecLogon)** as a proxy to do the work for us: `OpenProcess`, initialize the `attribute list`, and `CreateProcessAsUser`. So, spoiler alert, yes, we can. How? By developing our own **RPC client** to talk directly to the `Secondary Logon service`.

## Secondary Logon - Reverse Engineering 

At this point we are interested in developing our own **RPC client**, but to do that we must reverse-engineer and understand the RPC interface. Otherwise, functions like `NdrClientCall2` will not marshal our function calls in the way `NdrServerCall2` on the remote server expects, preventing us from successfully invoking the desired `RPC function (SeclCreateProcessWithLogonW)` and causing the server to report `Stub Received bad data (1783)`.

One tool that can greatly facilitate our reverse-engineering work is `RPCView`. This tool can decompile an RPC interface for us and show all its members and structures. Although it may not always specify the exact types for every structure, it is an excellent starting point.

```C
[
uuid(12b81e99-f207-4a4c-85d3-77b42f76fd14),
version(1.0),
]
interface DefaultIfName
{

	typedef struct Struct_44_t
	{
		[range(0,1024)] short 	StructMember0;
		[range(0,1025)] short 	StructMember1;
		[unique] [size_is(StructMember1)][length_is(StructMember0)]wchar_t *	StructMember2;
	}Struct_44_t;

	typedef struct Struct_114_t
	{
		long 	StructMember0;
		[unique][string][size_is(1025)] wchar_t* 	StructMember1;
		[unique][string][size_is(1025)] wchar_t* 	StructMember2;
		[unique][string][size_is(1025)] wchar_t* 	StructMember3;
		long 	StructMember4;
		long 	StructMember5;
		long 	StructMember6;
		long 	StructMember7;
		long 	StructMember8;
		long 	StructMember9;
		long 	StructMember10;
		long 	StructMember11;
		short 	StructMember12;
		[range(0,10240)] short 	StructMember13;
		[unique][size_is(StructMember13)]byte *	StructMember14;
		hyper 	StructMember15;
		hyper 	StructMember16;
		hyper 	StructMember17;
	}Struct_114_t;

	typedef struct Struct_184_t
	{
		[range(0,65536)] long 	StructMember0;
		[unique][size_is(StructMember0)]char *	StructMember1;
	}Struct_184_t;

	typedef struct Struct_204_t
	{
		struct Struct_44_t 	StructMember0;
		struct Struct_44_t 	StructMember1;
		struct Struct_44_t 	StructMember2;
		struct Struct_44_t 	StructMember3;
		struct Struct_44_t 	StructMember4;
		struct Struct_44_t 	StructMember5;
		struct Struct_114_t 	StructMember6;
		struct Struct_184_t 	StructMember7;
		long 	StructMember8;
		long 	StructMember9;
		long 	StructMember10;
		long 	StructMember11;
		long 	StructMember12;
		long 	StructMember13;
		hyper 	StructMember14;
		hyper 	StructMember15;
		hyper 	StructMember16;
	}Struct_204_t;

	typedef struct Struct_258_t
	{
		hyper 	StructMember0;
		hyper 	StructMember1;
		long 	StructMember2;
		long 	StructMember3;
		long 	StructMember4;
	}Struct_258_t;

void Proc0(
	[in]struct Struct_204_t* arg_1, 
	[out]struct Struct_258_t* arg_2);
} 
```

When it comes to reverse-engineering procedures or data structures that are not fully documented, we need to work smarter :) not harder. What I mean is: I followed 3 approaches.

1. ReactOS documentation. It contains the following definition of the `Secondary Logon` RPC interface:

The only thing is that these structures are from pre-Windows Vista. As stated before, there was no such thing as `STARTUPINFOEX` or a parent process to inherit from in XP and earlier versions. What I mean is that `_SECL_REQUEST` is an internal structure whose layout has evolved across Windows versions. In modern builds its layout no longer fully matches the one documented in ReactOS. Nevertheless, this work has been incredibly helpful in giving us insight into what to expect and in revealing which additional members were introduced and are required for us to perform the RPC call to achieve our goal.

```C++
typedef struct _SECL_REQUEST
{
    [string] WCHAR *Username;
    [string] WCHAR *Domain;
    [string] WCHAR *Password;
    [string] WCHAR *ApplicationName;
    [string] WCHAR *CommandLine;
    [string] WCHAR *CurrentDirectory;
    [size_is(dwEnvironmentSize)] BYTE *Environment;
    DWORD dwEnvironmentSize;
    DWORD dwLogonFlags;
    DWORD dwCreationFlags;
    DWORD dwProcessId;
} SECL_REQUEST, *PSECL_REQUEST;
 
typedef struct _SECL_RESPONSE
{
    DWORD_PTR hProcess;
    DWORD_PTR hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
    DWORD dwError;
} SECL_RESPONSE, *PSECL_RESPONSE;
 
[
    uuid(12b81e99-f207-4a4c-85d3-77b42f76fd14),
    version(1.0),
    pointer_default(unique),
    endpoint("ncacn_np:[\\pipe\\seclogon]")
]
interface ISeclogon
{
    /* Function 0 */
    void
    __stdcall
    SeclCreateProcessWithLogonW(
        [in] handle_t hBinding,
        [in, ref] SECL_REQUEST *pRequest,
        [out, ref] SECL_RESPONSE *pResponse);
 
    /* Function 1 */
/*
    void
    __stdcall
    SeclCreateProcessWithLogonExW(
        [in] handle_t hBinding,
        [in, ref] SECL_REQUEST *pRequest,
        [out, ref] SECL_RESPONSE *pResponse);
*/
}
```

2. Developed my own artifacts using `CreateProcessWithTokenW/LogonW`, where I specified my parameters in a way that made it easier to identify any missing members in the new layout of the structure.

4. The most obvious and important step was to attach with WinDbg to the `Secondary Logon service` to dynamically inspect how the server was receiving our structures and how it was parsing them, in order to determine if the offsets were correct and which required or otherwise interesting members I might be missing.

### SeclStartRpcServer()

As the name `SeclStartRpcServer()` suggests, it is responsible for starting the RPC server. Through `RpcServerUseProtseqEp`, `SecLogon` specifies that it supports the **ncalrpc** protocol sequence (ALPC), and the name of the endpoint is **SECLOGON**.

Next, the interface is registered with `RpcServerRegisterIfEx`, and a security callback function named `SeclSecurityCallback` is also passed. 

```C
uint64_t SeclStartRpcServer()

    {
        EnterCriticalSection(&csForProcessCount);
        RPC_STATUS rbx_1;
        
        if ((*(int64_t*)((char*)data_7ffafc5996d0 + 8)))
                rbx_1 = 0;
        else
            {
                RPC_STATUS rax_1 =
                RpcServerUseProtseqEpW(u"ncalrpc", 0xa, u"SECLOGON", nullptr);
                rbx_1 = 0;
                
                if (rax_1 != 0x6cc)
                    rbx_1 = rax_1;
    
                if (!rbx_1)
                    {
                        RPC_STATUS rax_2 = RpcServerRegisterIfEx(&data_7ffafc596360, nullptr, 
                        nullptr, rbx_1 + 9, 0x4d2, SeclSecurityCallback);
                        rbx_1 = rax_2;
                        .
                        .
                        .
                    }
            }
            .
            .
            .
    }
```

`SeclSecurityCallback` is a basic function, since it only checks whether the connection came from a local client. As the transport is **ncalrpc (ALPC)**, the connection will  be local.

```C
RPC_STATUS SeclSecurityCallback()

    {
        int32_t ClientLocalFlag = 0;
        RPC_STATUS result = I_RpcBindingIsClientLocal(nullptr, &ClientLocalFlag);
        
        if (result)
            return result;

        if (!ClientLocalFlag)
            return 5;
        
        return 0;
    }
```

### SeclCreateProcessWithLogonW, _SECL_REQUEST, _SECONDARYLOGONINFOW

As we can see in the following Pseudo C, `SeclCreateProcessWithLogonW` takes three parameters. From the ReactOS documentation, we can infer that they are the **RPC binding Handle**, **[In] * _SECL_REQUEST**, and **[Out] * _SECL_RESPONSE**. We can also observe that it creates another undocumented structure called **_SECONDARYLOGONINFOW** through the `To_SECONDARYLOGONINFOW` function, by passing **[In] * _SECL_REQUEST** as the first parameter (RCX) and a pointer to a pointer **(arg_20)** as the second parameter (RDX), meaning that **arg_20** is an out parameter which will contain a pointer to our populated `_SECONDARYLOGONINFOW` structure. 

```C
int64_t SeclCreateProcessWithLogonW(int64_t arg1, void* arg2, int128_t* arg3)
    {
        int128_t* arg_18 = arg3;
        int64_t* arg_20 = nullptr;
        int32_t var_24 = 0;
        int128_t s;
        __builtin_memset(&s, 0, 0x1c);
        EnterCriticalSection(&csForProcessCount);
        int96_t var_50;
        int32_t rdi_1;

        if (data_7ffafc5996a4 == 4)
            {
                HANDLE rax_1 = GetProcessHeap();
        
                    if (!rax_1)
                        {
                            rdi_1 = (int32_t)(rax_1 + 8);
                            goto label_7ffafc5910e5;
                        }

                    int32_t rax_2 = To_SECONDARYLOGONINFOW(arg2, &arg_20);
                .
                .
                .
            }
        .
        .
        .
    }
```

Thanks to WinDbg, we can easily place a breakpoint at `To_SECONDARYLOGONINFOW` to dissect `_SECL_REQUEST (RCX)` and inspect its layout:

> Note: This SecLogon request was sent using `CreateProcessWithLogonW`:

<img width="1163" height="536" alt="SeclCreateProcessWithLogonW-pt2" src="https://github.com/user-attachments/assets/358b0bcb-e51d-43a4-886f-76f72cab39d2" />

If we check the last members of the `_SECL_REQUEST` structure, after `_STARTUPINFO`, we will see the **dwProcessId**, **dwLogonFlags** and **dwCreationFlags** members:  

<img width="668" height="233" alt="SeclCreateProcessWithLogonW-pt5-first" src="https://github.com/user-attachments/assets/4626639a-a254-4623-b86d-5965aeb5f21c" />

However, if we send the request by using `CreateProcessWithTokenW` instead, we will find another interesting member at the end of  the `_SECL_REQUEST` structure:
The `hToken` field, the last member of the structure, is used when creating a new process based on an existing token instead of using logon credentials.

<img width="712" height="241" alt="SeclCreateProcessWithLogonW-pt4" src="https://github.com/user-attachments/assets/222b3601-6de1-4326-b411-ebc2a246094d" />

Finally, the `_SECONDARYLOGONINFOW` layout, built by `To_SECONDARYLOGONINFOW`, looks like this:

```C++
typedef struct _SECONDARYLOGONINFOW {

STARTUPINFOEXW * STARTUPINFOEXW;
WCHAR * Username;
WCHAR * Domain;
WCHAR * ApplicationName;
WCHAR * CommandLine;
WCHAR * Environment;
WCHAR * CurrentDirectory;
UNICODE_STRING Password;
DWORD dwProcessId;
DWORD dwLogonFlags;
DWORD dwCreationFlags;
DWORD dwCredentialFlags; // bit 0 = RequireCredentialLogon / ForceLogon, others unknown
HANDLE hToken; 

} SECONDARYLOGONINFOW, * PSECONDARYLOGONINFOW;
```

### SlrCreateProcessWithLogon

In this section, we are going to look at the good parts of `SlrCreateProcessWithLogon`. This function takes three arguments: an **RPC binding handle**, a **PSECONDARYLOGONINFOW**, and a pointer to a structure of **0x1C** bytes in length, which appears to be an output structure:

```C
int32_t rax_2 = To_SECONDARYLOGONINFOW(arg2, &arg_20);
rdi_1 = rax_2;
int32_t var_68_1 = rax_2;

if (rax_2)
    goto label_7ffafc5910e5;
            
SlrCreateProcessWithLogon(arg1, &arg_20, &s);
```

One of the first things the `SecLogon` server does is call `RpcImpersonateClient` to impersonate the caller. This step is crucial for security because **SvcHost.exe** runs as **LocalSystem**; by impersonating the client, the server limits subsequent operations to the client's privileges and prevents the service from using its **LocalSystem** rights to perform actions the client itself could not.

```C
RPC_STATUS uExitCode_5 = RpcImpersonateClient(arg1);
```

Next, `SecLogon` (using the client’s token) attempts to open a handle to the target process by dereferencing the DWORD at offset **0x48** of the  `_SECONDARYLOGONINFOW` structure, which is **dwProcessId**. In addition, **dwDesiredAccess** is set to **0x4c0** `(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION)`.

> **Note:** this step is important, since the handle will be used in subsequent calls. Also, when we leverage a tool like **runas** or develop our own utility that uses `CreateProcessWithTokenW/LogonW`, **dwProcessId** is **always** the **PID** of our client. However, if we develop our own **RPC client**, we might be able to influence this value. What does this mean? We could perform `PPID spoofing` through **SvcHost.exe** as our proxy process, thus 'circumventing' the `CreateProcessWithTokenW/LogonW` limitation that we analyzed earlier.

```C
HANDLE rax_2 = OpenProcess(0x4c0, 0, rsi[9]);
var_678 = rax_2;

if (!rax_2)
    {
        label_7ffafc592054:
        rbx_3 = var_694;
        label_7ffafc591d64:
        RPC_STATUS uExitCode_10 = GetLastError();
        uExitCode_2 = uExitCode_10;
        RPC_STATUS uExitCode_23 = uExitCode_10;
        lpMem_1 = lpMem_2;
    }
.
.
.
```

In the following code snippet, `SecLogon` checks whether the **hToken** field at offset **0x58** of the `_SECONDARYLOGONINFOW` structure is present. If it is, the server performs the following actions:

> **Note:** The following scenario applies when the client uses `CreateProcessWithTokenW`.

1. Open a handle to the target process's token.

2. Check whether the token's process has the `SeImpersonatePrivilege` enabled **(LUID 0x1d)**.

3. Duplicate the token handle.

```C

if (rsi[0xb])
    {
        if (!OpenProcessToken(var_678, 0xc, &ClientToken))
                {
                    label_7ffafc591fce:
                    RPC_STATUS uExitCode_15 = GetLastError();
                    uExitCode_2 = uExitCode_15;
                    RPC_STATUS uExitCode_28 = uExitCode_15;
                    lpMem_1 = lpMem_2;
                    rbx_3 = var_694;
                }
        else
                {
                    var_540.PrivilegeCount = 1;
                    var_540.Privilege[0].Luid.LowPart = 0x1d;
                    var_540.Privilege[0].Luid.HighPart = 0;
                    BOOL pfResult;

                    if (!PrivilegeCheck(ClientToken, &var_540, &pfResult))
                        pfResult = 0;

                    CloseHandle(ClientToken);
                                       
                    if (pfResult)
                    {
                        HANDLE rax_32 = GetCurrentProcess();
                        ReturnLength = 0;                                            

                        if (!DuplicateHandle(var_678, rsi[0xb], rax_32, &var_688, ReturnLength, 0, 2, SubAuthority5, SubAuthority6, SubAuthority7, Sid))
                        .
                        .
                        .
                    }
                }
    }
```

If the **hToken** field is **not** present, it means the client wants to create the new process using **logon credentials** instead of an existing token.

> **Note:** The following scenario applies when the client uses `CreateProcessWithLogonW`.

First, some checks are performed against the **dwLogonFlags (offset 0x4C)** and **dwCredentialFlags (offset 0x54)** fields. If **bit 0** of **dwCredentialFlags** is set, the code proceeds with `LogonUserWrap (a wrapper for LsaLogonUser)`. If it is clear, then **bit 1 (0x2, LOGON_NETCREDENTIALS_ONLY)** of **dwLogonFlags** is checked. If that bit is set, or if the call to `GetLogonSid` fails, the code also falls back to `LogonUserWrap`.


```C
    else
        {
            RPC_STATUS uExitCode_16;

            if (!(1 & (char)*(uint32_t*)((char*)rsi + 0x54)) && !(*(uint8_t*)((char*)rsi + 0x4c) & 2))
                {
                    uExitCode_16 = GetLogonSid(&lpMem_3);
                    uExitCode_2 = uExitCode_16;
                    RPC_STATUS uExitCode_29 = uExitCode_16;
                }

            if (!(1 & (char)*(uint32_t*)((char*)rsi + 0x54)) && !(*(uint8_t*)((char*)rsi + 0x4c) & 2) && uExitCode_16)
                {
                    lpMem_1 = lpMem_2;
                    rbx_3 = var_694;
                }
            else
                {
                    int128_t var_558 = *(uint128_t*)((char*)rsi + 0x38);
                    SubAuthority5 = &lpMem_2;
                    uint32_t lpReturnSize;
                    lpReturnSize = &var_688;
                    uint32_t var_6d0;
                    var_6d0 = lpMem_3;
                    RPC_STATUS uExitCode_8 = LogonUserWrap(rsi[1], rsi[2], &var_558, r12_1, ReturnLength, var_6d0, lpReturnSize);
                    .
                    .
                    .
                }
                .
                .
                .
        }

```

In the same vein, whether the client specifies `logon credentials (CreateProcessWithLogonW)` or provides a `handle to a token (CreateProcessWithTokenW)`, a new attribute list is created for **PPID spoofing**, and the process is launched via `CreateProcessAsUser`.

Also, **arg3** of `SlrCreateProcessWithLogon` is a pointer to a `PROCESS_INFORMATION` structure.

```C
int64_t* SlrCreateProcessWithLogon(int64_t arg1, int64_t* arg2, HANDLE* arg3)
.
.
.
size = 0x30;
BOOL rax_19 = InitializeProcThreadAttributeList(&var_528, 1, 0, &size);
BOOL rax_26;

if (rax_19)
     {
        lpReturnSize = 0;
        var_6d0 = 0;
        rax_26 = UpdateProcThreadAttribute(&var_528, 0, 0x20000, &var_678, 8, var_6d0, lpReturnSize);
    }
.
.
.

Sid = arg3;
SubAuthority7 = *(uint64_t*)rsi;
SubAuthority6 = rsi[6];
SubAuthority5 = rsi[5];

if (!CreateProcessAsUserW(var_688, rsi[3], rsi[4], &var_5d0, &var_5d0, 0, 
    rcx_26 | rsi[0xa], SubAuthority5, SubAuthority6, SubAuthority7, Sid))
.
.
.
```

Finally, the prototype of `SlrCreateProcessWithLogon` looks like this:

```C
int64_t* SlrCreateProcessWithLogon(RPC_BINDING_HANDLE hRpc, SECONDARYLOGONINFOW* SecondaryLogonInfoW, 
PROCESS_INFORMATION* ProcessInformation)
```

## Proof of Concept (PoC)

In the following Proof of Concept (PoC), we will talk directly to `SecLogon` with a RPC client instead of going through `CreateProcessWithTokenW/LogonW`. We will also achieve **PPID spoofing** via **SvcHost.exe**, so our client won't need to open a handle to the parent process, initialize an attribute list, or call `CreateProcessAsUser`.

### secondarylogon.idl (RPC Interface definition)

```c++

typedef struct _STARTUPINFOW_RPC
{
	long 	cb;
	[unique] [string] [size_is(1025)] wchar_t* lpReserved;
	[unique] [string] [size_is(1025)] wchar_t* lpDesktop;
	[unique] [string] [size_is(1025)] wchar_t* lpTitle;
	long 	dwX;
	long 	dwY;
	long 	dwXSize;
	long 	dwYSize;
	long 	dwXCountChars;
	long 	dwYCountChars;
	long 	dwFillAttribute;
	long 	dwFlags;
	short 	wShowWindow;
	[range(0, 10240)] short 	cbReserved2;
	[unique] [size_is(cbReserved2)] byte* lpReserved2;
	hyper 	hStdInput;
	hyper 	hStdOutput;
	hyper 	hStdError;
}STARTUPINFOW_RPC, *LPSTARTUPINFOW_RPC;

typedef struct _RPC_UNICODE_STRING
{
	[range(0, 1024)] short 	Length;
	[range(0, 1025)] short 	MaximumLength;
	[unique] [size_is(MaximumLength)] [length_is(Length)] wchar_t* Buffer;
}RPC_UNICODE_STRING;


typedef struct _RPC_ENV_BLOCKW {
    [range(0, 65536)] unsigned long Size;   
    [size_is(Size / 2)] wchar_t* Data;         
} RPC_ENV_BLOCKW;

typedef struct _SECL_REQUEST
{
	struct _RPC_UNICODE_STRING 	Username;
	struct _RPC_UNICODE_STRING 	Domain;
	struct _RPC_UNICODE_STRING 	Password;
	struct _RPC_UNICODE_STRING 	ApplicationName;
	struct _RPC_UNICODE_STRING 	CommandLine;
	struct _RPC_UNICODE_STRING 	CurrentDirectory;
	struct _STARTUPINFOW_RPC 	StartupInfo;
	struct _RPC_ENV_BLOCKW 	Environment;
	long 	dwProcessId; 
	long 	Reserved1;  
	long 	Reserved2; 
	long 	dwLogonFlags; 
	long 	dwCreationFlags; 
	long 	dwCredentialFlags; // bit 0 = RequireCredentialLogon / ForceLogon, others unknown
	hyper 	Reserved4; 
	hyper 	Reserved5; 
	hyper 	hToken; 
}SECL_REQUEST, *PSECL_REQUEST;

typedef struct _SECL_RESPONSE
{
    hyper hProcess;
    hyper hThread;
    long dwProcessId;
    long dwThreadId;
    long dwError;
} SECL_RESPONSE, * PSECL_RESPONSE;


[
    uuid(12b81e99-f207-4a4c-85d3-77b42f76fd14),
    version(1.0),
]

interface ISeclogon
{
    void
        __stdcall
        SeclCreateProcessWithLogonW(
            [in] handle_t hBinding,
            [in, ref] SECL_REQUEST* pRequest,
            [out, ref] SECL_RESPONSE* pResponse);
}
```

### RPCSecondaryLogon.cpp 

```c++
#define RPC_USE_NATIVE_WCHAR

#include <Windows.h>
#include <stdio.h>
#include <assert.h>


#include "secondarylogon_c.c"

#pragma comment(lib, "rpcrt4")


static void Init_UNICODE_STRING(const wchar_t* src, RPC_UNICODE_STRING* unicode_string) {

	
	if (!src) { 
		unicode_string->Length = unicode_string->MaximumLength = 0;
		unicode_string->Buffer = NULL;
		return; 
	}
	size_t cch = wcslen(src), bytes = (USHORT)(cch * 2), cap = bytes + 2;

	unicode_string->Buffer = (wchar_t*)MIDL_user_allocate(cap);
	memcpy(unicode_string->Buffer, src, bytes); 
	unicode_string->Buffer[cch] = L'\0';
	unicode_string->Length = (USHORT)bytes; 
	unicode_string->MaximumLength = (USHORT)cap;
}

int main(int argc, const char ** argv)
{
	printf("[+] Process Dechaining via Secondary Logon\n");
	
	DWORD PID_PARENT = 0x0;

	if (argc < 3) {
		printf("[!] Usage: .\\Dechaining.exe -pid <parent process>\n");
		return 1;
	}
	if (strcmp(argv[1], "-pid") == 0)
		PID_PARENT = atoi(argv[2]);

	else
		return 1;

    RPC_WSTR binding;
    handle_t hRpc = NULL;

	SECL_REQUEST seclReq = { 0 };
	SECL_RESPONSE seclRep = { 0 };

	STARTUPINFOW_RPC siRpc = { 0 };
	siRpc.cb = sizeof(STARTUPINFOW_RPC);

	seclReq.StartupInfo = siRpc;
	seclReq.dwProcessId = PID_PARENT;
	seclReq.dwLogonFlags = LOGON_NETCREDENTIALS_ONLY;
	seclReq.dwCreationFlags = CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_PROCESS_GROUP;

	Init_UNICODE_STRING(L"cmd.exe",
		&seclReq.ApplicationName);
	Init_UNICODE_STRING(L"\"C:\\Windows\\System32\\cmd.exe\" /k C:\\Windows\\System32\\whoami.exe",
		&seclReq.CommandLine);
	Init_UNICODE_STRING(L"C:\\Windows\\System32", 
		&seclReq.CurrentDirectory);

	Init_UNICODE_STRING(L"H0ud1n1", 
		&seclReq.Username);
	Init_UNICODE_STRING(L"houdini.local", 
		&seclReq.Domain);
	Init_UNICODE_STRING(L"", 
		&seclReq.Password);

    auto status = RpcStringBindingCompose(nullptr,
        (PWSTR)L"ncalrpc",
        nullptr,
        (PWSTR)L"SECLOGON",
        nullptr,
        &binding);

    assert(status == RPC_S_OK);

    status = RpcBindingFromStringBinding(binding,
        &hRpc);

    assert(status == RPC_S_OK);

	SeclCreateProcessWithLogonW(hRpc, (PSECL_REQUEST)&seclReq, (PSECL_RESPONSE)&seclRep);
	printf("\t\t[+] Parent Process - Pid: `%d`\n", PID_PARENT);
	printf("\t\t[+] Secondary Logon Response - Pid: `%d`\n", seclRep.dwProcessId);

	midl_user_free(seclReq.CommandLine.Buffer);
	midl_user_free(seclReq.ApplicationName.Buffer);
	midl_user_free(seclReq.CurrentDirectory.Buffer);
	midl_user_free(seclReq.Username.Buffer);
	midl_user_free(seclReq.Domain.Buffer);
	midl_user_free(seclReq.Password.Buffer);

	return 0;
	
}

void* midl_user_allocate(size_t size) {
    return malloc(size);
}

void midl_user_free(void* p) {
    free(p);
}
```

### Demonstration

<img width="1002" height="473" alt="image" src="https://github.com/user-attachments/assets/19dd55c2-d1ed-45af-9679-c59ec7101a65" />

<img width="637" height="692" alt="image" src="https://github.com/user-attachments/assets/7168cd05-401f-43ac-a576-50b1e8d4c391" />


