# Direct Syscall System

Usermode anti-cheat hooks ntdll.dll functions to intercept and log API calls. The direct syscall system bypasses these hooks entirely by resolving syscall numbers from a clean disk copy of ntdll and invoking them through polymorphic stubs that jump to a `syscall; ret` gadget in the loaded ntdll.

**Source:** `src/proxy/syscalls.cpp` (239 lines), `src/proxy/syscalls.h` (77 lines)

## Why Direct Syscalls

Anti-cheat systems hook ntdll functions like `NtReadVirtualMemory`, `NtOpenProcess`, and `NtAllocateVirtualMemory` to:
1. Log which processes call these APIs
2. Detect suspicious parameter patterns (e.g., opening cs2.exe with `PROCESS_VM_READ`)
3. Block calls outright

These hooks are placed at the function entry point — typically overwriting the first bytes with a `jmp` to the hook handler. The syscall number (`mov eax, <SSN>`) and the `syscall` instruction are pushed deeper into the function body.

By extracting the syscall number and jumping directly to the `syscall` instruction, the reader bypasses all usermode hooks.

## Syscall Number Resolution

### Disk Copy of ntdll

The reader reads `C:\Windows\System32\ntdll.dll` from disk into a buffer. This is a clean copy — not the loaded image in memory, which may be hooked. The export table is parsed to find each target function:

```
1. Read ntdll.dll from disk
2. Parse PE export directory
3. For each target function name:
   a. Find the export by name
   b. Read the function's first 28 bytes
   c. Search for the pattern: B8 <4-byte SSN> 00 00
      (mov eax, <syscall_number>)
   d. Extract the syscall number
```

The `mov eax, imm32` pattern is the standard ntdll prologue for syscall stubs on x64 Windows. The syscall number is the 4-byte immediate value.

### Resolved Syscalls

The system resolves 11 syscall numbers:

| Function | Purpose |
|----------|---------|
| `NtQuerySystemInformation` | Enumerate system handles, find proxy |
| `NtOpenProcess` | Open proxy process for injection |
| `NtDuplicateObject` | Duplicate handles for verification |
| `NtReadVirtualMemory` | Read proxy memory, game memory via shellcode |
| `NtWriteVirtualMemory` | Write proxy memory (ProxyData, shellcode, trampoline) |
| `NtAllocateVirtualMemory` | Allocate ProxyData, trampoline in proxy |
| `NtFreeVirtualMemory` | Free trampoline after de-execution |
| `NtProtectVirtualMemory` | Change page protections (stomp, de-exec) |
| `NtCreateThreadEx` | Launch shellcode thread in proxy |
| `NtClose` | Close handles |
| `NtSetInformationThread` | Rewrite thread start address, hide from debugger |

## The Syscall Gadget

The `syscall` instruction transitions from ring 3 to ring 0. It must execute from within ntdll's `.text` section for CFG compatibility. The reader scans the loaded ntdll's `.text` section for the byte sequence `0F 05 C3` (`syscall; ret`):

```cpp
void find_syscall_gadget() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    // Walk PE sections to find .text
    // Scan for 0F 05 C3 (syscall; ret)
    g_syscall_gadget = text + j;  // pointer to the gadget
}
```

This gadget exists in every ntdll on x64 Windows — it is the standard return path from syscall stubs. All polymorphic stubs jump to this single gadget.

## Polymorphic Stubs

Each resolved syscall gets a 32-byte stub. Four different prologue variants are used, rotating by stub index:

### Variant 0: Standard
```asm
mov r10, rcx          ; 4C 8B D1  (syscall convention: r10 = rcx)
mov eax, <SSN>        ; B8 <4 bytes>
jmp [syscall_gadget]  ; FF 25 00 00 00 00 <8 bytes>
```

### Variant 1: Reordered
```asm
mov eax, <SSN>        ; B8 <4 bytes>
mov r10, rcx          ; 4C 8B D1
jmp [syscall_gadget]
```

### Variant 2: Push/Pop
```asm
push rcx              ; 51
pop r10               ; 41 5A
mov eax, <SSN>        ; B8 <4 bytes>
jmp [syscall_gadget]
```

### Variant 3: XOR + ADD
```asm
mov r10, rcx          ; 4C 8B D1
xor eax, eax          ; 31 C0
add eax, <SSN>        ; 05 <4 bytes>
jmp [syscall_gadget]
```

All variants produce the same result: `r10 = rcx` and `eax = syscall_number`, then jump to the `syscall; ret` gadget. The polymorphism prevents pattern-based detection of the stubs.

### Indirect Jump

The jump to the syscall gadget uses `FF 25 00 00 00 00` (RIP-relative indirect jump) followed by the 8-byte absolute address of the gadget. This is an indirect jump through a pointer, which is the standard way to jump to an absolute address on x64.

## Page Protection

All stubs are allocated on a single 4096-byte page allocated with `VirtualAlloc(MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)`. After all stubs are written:

```cpp
void lock_stubs() {
    VirtualProtect(g_stub_page, 4096, PAGE_EXECUTE_READ, &old);
}
```

The page is locked to `PAGE_EXECUTE_READ` — executable but not writable. This eliminates the `RWX` memory flag, which is a detection vector. The stubs cannot be modified after locking.

## Wrapper Functions

The `sys_*` functions provide a clean C++ API over the raw syscall stubs:

```cpp
HANDLE sys_open(DWORD pid, ULONG access);           // NtOpenProcess
bool   sys_read(HANDLE h, uint64_t addr, ...);      // NtReadVirtualMemory
bool   sys_write(HANDLE h, uint64_t addr, ...);     // NtWriteVirtualMemory
void   sys_close(HANDLE h);                         // NtClose
bool   sys_protect(HANDLE h, uint64_t addr, ...);   // NtProtectVirtualMemory
bool   sys_free(HANDLE h, uint64_t addr);           // NtFreeVirtualMemory
uint64_t sys_alloc_remote(HANDLE h, size_t, ULONG); // NtAllocateVirtualMemory
HANDLE sys_create_thread(HANDLE proc, ...);          // NtCreateThreadEx
```

Each wrapper casts the stub's `code` pointer to the appropriate function typedef and calls it directly. The call goes through the polymorphic stub → syscall gadget → kernel, never touching ntdll's hooked entry points.

## Process Mitigation Policy

After resolving syscalls, the reader enables `MicrosoftSignedOnly` process mitigation:

```cpp
struct { ULONG MicrosoftSignedOnly : 1; ... } sp = {};
sp.MicrosoftSignedOnly = 1;
SetProcessMitigationPolicy(8, &sp, sizeof(sp));
```

This prevents any non-Microsoft-signed DLL from being injected into the reader process. This blocks anti-cheat from injecting monitoring DLLs into the reader.

## Thread Hiding

All reader threads are hidden from the debugger:

```cpp
NtSetInformationThread(GetCurrentThread(), 0x11, nullptr, 0);
```

Info class `0x11` is `ThreadHideFromDebugger`. This prevents debuggers (and some anti-cheat debug hooks) from receiving debug events for these threads.
