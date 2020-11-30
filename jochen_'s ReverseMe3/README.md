# ReverseMe3

## MainThread

```
0000000000401000 | mov rax,qword ptr ss:[rsp]              |
0000000000401004 | xor ax,ax                               |
0000000000401007 | sub rax,10000                           |
000000000040100D | mov qword ptr ds:[4015C4],rax           | 00000000004015C4:&"MZ"
0000000000401014 | mov eax,40                              | 40:'@'
0000000000401019 | bswap eax                               |
000000000040101B | cpuid                                   |
000000000040101D | mov eax,ecx                             |
000000000040101F | mov edx,reverseme3.401030               |
0000000000401024 | mov ecx,258                             |
0000000000401029 | xor byte ptr ds:[edx],al                |
000000000040102C | inc edx                                 |
000000000040102E | loop reverseme3.401029                  |
```

Firstly it fetches kernel32 base address by zeroing out the offset bits, which is 16 because the loader loads every module at a address which is a multiple of 64K. And the function that calls the entry point is kernel32!BaseThreadInitThunk

So, zeroing out the lower 16 bits of the return address, we get the kernel32 module base. This value is stored in 0x4015c4

cpuid of 0x40000000 corresponds to the first debug check.
From https://lwn.net/Articles/301888/ we have

Hypervisor CPUID Information Leaf:
        Leaf 0x40000000.

        This leaf returns the CPUID leaf range supported by the
        hypervisor and the hypervisor vendor signature.

        # EAX: The maximum input value for CPUID supported by the hypervisor.
        # EBX, ECX, EDX: Hypervisor vendor ID signature.

So with eax=0x40000000, we get the hypervisor vendor id in ebx:ecx:edx in the order.
Without hypervisor, it returns 0x64 in windows 10, major version: 1903, build: 18363

Then it proceeds to xor the block of 0x258 bytes from 0x401030 with the key 0x64

```
0000000000401030 | sub rsp,8                               |
0000000000401034 | mov rbx,4                               |
000000000040103B | mov rcx,<reverseme3.dwHandle>           |
0000000000401042 | mov rdx,1FFFFF                          |
0000000000401049 | mov r8,0                                |
0000000000401050 | mov r9,FFFFFFFFFFFFFFFF                 | r9:EntryPoint
0000000000401057 | lea rax,qword ptr ds:[4010CE]           | 00000000004010CE:"IÇÀ"
000000000040105E | mov qword ptr ss:[rsp+20],rax           |
0000000000401063 | mov qword ptr ss:[rsp+28],0             |
000000000040106C | mov qword ptr ss:[rsp+30],rbx           |
0000000000401071 | mov qword ptr ss:[rsp+38],0             |
000000000040107A | mov qword ptr ss:[rsp+40],0             |
0000000000401083 | mov qword ptr ss:[rsp+48],0             |
000000000040108C | mov qword ptr ss:[rsp+50],0             |
0000000000401095 | call qword ptr ds:[<&ZwCreateThreadEx>] |
```

Then the binary calls ZwCreateThreadEx with the standard params except for the CreateFlags
The signature for ZwCreateThreadEx is

```c
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateThreadEx (
    _Out_ PHANDLE ThreadHandle,                     // rcx
    _In_ ACCESS_MASK DesiredAccess,                 // rdx
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,   // r8
    _In_ HANDLE ProcessHandle,                      // r9
    _In_ PVOID StartRoutine,                        // [rsp + 0x20]
    _In_opt_ PVOID Argument,                        // [rsp + 0x28]
    _In_ ULONG CreateFlags,                         // [rsp + 0x30]
    _In_opt_ ULONG_PTR ZeroBits,
    _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList
);
```

from https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html at line 1340, we get
CreateFlags is assigned 4 which means THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER.
So this is the reason if you put a breakpoint on the address 0x4010CE (StartRoutine for the new thread),
debugger never breaks.

```
000000000040109B | mov rcx,qword ptr ds:[<dwHandle>]       |
00000000004010A2 | mov rdx,0                               |
00000000004010A9 | xor r8,r8                               |
00000000004010AC | mov r10,rcx                             |
00000000004010AF | mov eax,4                               |
00000000004010B4 | syscall                                 |    ZwWaitForSingleObject
00000000004010B6 | mov rcx,FFFFFFFFFFFFFFFF                |
00000000004010BD | mov rdx,0                               |
00000000004010C4 | mov r10,rcx                             |
00000000004010C7 | mov eax,2C                              | 2C:','
00000000004010CC | syscall                                 |    NtTerminateProcess
```

This code is pretty easy to understand except for how to identify the syscalls.
I opened ntdll in IDA, and quickly wrote a script to extract the syscalls. All the syscalls have the form
        mov eax, NNN
        ...
        syscall
        ...

Script:
```py
import idautils

fn = {}

for exp in idautils.Entries():
    start, end = exp[2], FindFuncEnd(exp[2])
    for i in Heads(start, end):
        d = GetDisasm(i).strip()
        if d.startswith('mov     eax,') and GetOpType(i, 1) == 5:
            eax = GetOperandValue(i, 1)
        elif d.startswith('syscall'):
            fnname = GetFunctionName(i)
            if eax not in fn:
                fn[eax] = []
            fn[eax].append(fnname)

syscalls = {}
for i, j in fn.items():
    t = list(set(j))
    if len(t) == 1:
        t = t[0]
    syscalls[i] = t
```

------------------------------------------------------------------

## Thread-1

```
00000000004010CE | mov r8,0                                |
00000000004010D5 | mov r9,0                                | r9:EntryPoint
00000000004010DC | mov rcx,FFFFFFFFFFFFFFFE                |
00000000004010E3 | lea edx,qword ptr ds:[r9+11]            |
00000000004010E7 | mov r10,rcx                             |
00000000004010EA | mov eax,D                               | D:'\r'
00000000004010EF | syscall                                 | NtSetInformationThread
```

So first the thread hides itself from the debugger using 0x11 (ThreadHideFromDebugger) option

```
00000000004010F1 | mov rax,qword ptr gs:[60]               |
00000000004010F9 | mov rbx,rax                             |
00000000004010FC | mov rax,qword ptr ds:[rbx+118]          | OSMajorVersion
0000000000401103 | cmp rax,A                               | A:'\n'
0000000000401107 | jne <reverseme3.kill_self>              |
000000000040110D | mov rax,qword ptr ds:[rbx+120]          | OSBuildNumber
0000000000401114 | movzx eax,ax                            |
0000000000401117 | cmp eax,47BB                            |
000000000040111C | jne reverseme3.401125                   |
```

It checks if the OS is windows 10 (using the major version) and whether the build is 18363

```
000000000040111E | mov byte ptr ds:[401149],A1             |
0000000000401125 | xor r9d,r9d                             | r9d:EntryPoint
0000000000401128 | lea r8,qword ptr ds:[401478]            |
000000000040112F | mov edx,1F000F                          |
0000000000401134 | lea rcx,qword ptr ds:[4015AC]           |
000000000040113B | mov dword ptr ds:[401478],30            | 30:'0'
0000000000401145 | mov r10,rcx                             |
0000000000401148 | mov eax,A5                              |
000000000040114D | syscall                                 |
```

If the build is 18363, the instruction at 0x401148 is changed to `mov eax, A1`
0xa1 means `ZwCreateDebugObject`
0xa5 means `NtCreateEnlistment`

If we see the signature of NtCreateEnlistment, the third param is a handle, but in this code,
the third param is a address which means the parameters correspond to `ZwCreateDebugObject`

Now, let's assume we aren't running inside a debugger, so this syscall creates the very first debug object
The handle is stored at 0x4015ac

```
0000000000401157 | mov qword ptr ss:[rsp+20],0             |
0000000000401160 | mov r9d,1000                            | r9d:EntryPoint
0000000000401166 | lea r8,qword ptr ds:[4014A8]            |
000000000040116D | mov edx,2                               | 
0000000000401172 | mov rcx,qword ptr ds:[4015AC]           |
0000000000401179 | mov r10,rcx                             |
000000000040117C | mov eax,10                              |
0000000000401181 | syscall                                 | ZwQueryObject
```

```c
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllTypesInformation,
    ObjectHandleInformation 
} OBJECT_INFORMATION;
```

So, we have 2 means ObjectTypeInformation, so 0x4014A8 must receive the structure 

```c
typedef struct _OBJECT_TYPE_INFORMATION { // Information Class 2
    UNICODE_STRING Name;        // +0 - len, +2 - cap, +0x8 - ptr to buffer
    ULONG ObjectCount;          // +0x10
    ULONG HandleCount;
    ULONG Reserved1[4];
    ULONG PeakObjectCount;
    ULONG PeakHandleCount;
    ULONG Reserved2[4];
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    UCHAR Unknown;
    BOOLEAN MaintainHandleDatabase;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;
```
```
0000000000401183 | mov qword ptr ss:[rsp+20],0             |
000000000040118C | mov r9,1                                | r9:EntryPoint
0000000000401193 | lea r8,qword ptr ds:[4015BC]            |
000000000040119A | lea edx,qword ptr ds:[r9+10]            | ThreadHideFromDebugger
000000000040119E | mov rcx,FFFFFFFFFFFFFFFE                | -2 => CurrentThread
00000000004011A5 | lea r8,qword ptr ds:[4015BC]            |
00000000004011AC | mov r10,rcx                             |
00000000004011AF | mov eax,25                              | 25:'%'
00000000004011B4 | syscall                                 | ZwQueryInformationThread
```
It now checks if you have intentionally skipped the first ThreadHideFromDebugger attribute using a debugger
Without a debugger, we have this thread hidden at the very start, so the call to ZwQueryInformationThread must
return 1 into the address 0x4015BC
```
00000000004011B6 | movsxd rcx,dword ptr ds:[4014B8]        | [0x4014A8].ObjectCount
00000000004011BD | add ecx,41                              |
00000000004011C0 | mov byte ptr ds:[401277],cl             | 0000000000401277:"LKe6Px8M2fN7iAlC"
00000000004011C6 | add ecx,E                               |
00000000004011C9 | mov rbx,qword ptr ds:[4015BC]           | ThreadHideFromDebugger?
00000000004011D0 | add ebx,ecx                             |
00000000004011D2 | mov byte ptr ds:[401286],bl             |
00000000004011D8 | sub rsp,20                              |
00000000004011DC | mov rcx,reverseme3.401288               |
00000000004011E3 | mov rdx,143                             |
00000000004011EA | mov r8,reverseme3.401273                | 401273:"1c4TLKe6Px8M2fN7iAlC"
00000000004011F1 | mov r9,14                               | r9:EntryPoint
00000000004011F8 | call reverseme3.401226                  | Plain xor decrypt
00000000004011FD | add rsp,20                              |
0000000000401201 | mov r15,qword ptr ds:[4015C4]           | m_hKernel32
0000000000401208 | push reverseme3.401288                  | return address
000000000040120D | ret                                     |
```

Since the program creates a debug object, the OBJECT_TYPE_INFORMATION must return ObjectCount = 1

So, [0x401277] = 0x41 + 1 = 'B' (at index 4) and [0x401286] = 0x41+1+0xE+1 = 'Q' (at index 19)
the function at 0x401226 takes 4 params - buffer, buf_size, key, key_len and xor's the buffer with the key

`key = '1c4TBKe6Px8M2fN7iAlQ'`

now xor the function using this key,

script:
```
code = []
code_size = 0x143
code = get_bytes(0x401288, code_size)
key = list('1c4TLKe6Px8M2fN7iAlC')
key[4] = 'B'
key[0x13] = 'Q'
for i in range(code_size):
    PatchByte(0x401288+i, ord(code[i])^ord(key[i%len(key)]))
```

and we get the code that's executed

```
// reverseme3.401288:
seg000:0000000000401288                 mov     rbx, r15
seg000:000000000040128B                 sub     rsp, 28h
seg000:000000000040128F                 mov     rcx, rbx
seg000:0000000000401292                 mov     rdx, 0A216A185h ; LoadLibraryA
seg000:000000000040129C                 call    ResolveFunction
seg000:00000000004012A1                 lea     rcx, aUser32Dll ; "user32.dll"
seg000:00000000004012A8                 call    rax
seg000:00000000004012AA                 mov     rcx, rax
seg000:00000000004012AD                 mov     rdx, 9A9C4525h  ; MessageBoxA
seg000:00000000004012B7                 call    ResolveFunction
seg000:00000000004012BC                 mov     rcx, 0
seg000:00000000004012C3                 lea     rdx, aEverythingsSee ; "Everythings seems fine (^_^)\n\rNo debu"...
seg000:00000000004012CA                 lea     r8, aClean      ; "Clean !"
seg000:00000000004012D1                 mov     r9, 40h
seg000:00000000004012D8                 call    rax
seg000:00000000004012DA                 retn
```

ResolveFunction iterates through kernel32's export to find the required function. Hashing algorithm is 

```py
def rol(a, b):
    b &= 0x1f
    return (a << b | a >> 32-b) & 0xffffffff

def go(name):
    a = 0
    for i in name+"\x00":
        a = rol(a+ord(i), ord(i))
    return a

>>> hex(go('LoadLibraryA'))
'0xa216a185'
>>> hex(go('MessageBoxA'))
'0x9a9c4525'
```

And this displays the expected message
