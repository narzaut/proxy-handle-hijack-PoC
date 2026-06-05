# Shellcode & Trampoline

The proxy shellcode is a minimal read loop that executes inside the proxy process, using a hijacked `PROCESS_VM_READ` handle to read cs2.exe memory on behalf of the reader. The trampoline is a short-lived launch pad that starts the shellcode thread and is then destroyed.

**Source:** `src/proxy/proxy.cpp` — shellcode encryption (lines 4–44), trampoline (lines 400–555)

## Shellcode Design

### Compile-Time Encryption

The shellcode is XOR-encrypted at compile time with key `0xA7`. Each byte in the `SHELLCODE_ENC` array is the plaintext byte XOR'd with the key:

```cpp
static constexpr uint8_t SC_KEY = 0xA7;
static const uint8_t SHELLCODE_ENC[] = {
    0x56 ^ SC_KEY, 0x48 ^ SC_KEY, 0x83 ^ SC_KEY, ...
};
```

This prevents the shellcode bytes from appearing in the binary's `.data` section. Static analysis tools scanning for known shellcode patterns will not match.

### Runtime Decryption

At startup, `decrypt_shellcode()` allocates a heap buffer, XOR-decrypts each byte, and stores the result in `g_sc_buf`. After injection into the proxy, `zero_shellcode()` calls `SecureZeroMemory` to wipe the decrypted bytes from the reader's own memory.

### Shellcode Functionality

The 62-byte shellcode is a spin-wait read loop:

```asm
; Prologue: save rsi, allocate stack space
push rsi
sub rsp, 0x30
mov rsi, rcx              ; rsi = ProxyData* (thread argument)

.loop:
mov eax, [rsi + 0x10]     ; read signal
test eax, eax
jz .loop                   ; spin while signal == 0

mov eax, [rsi + 0x00]     ; syscall_num (XOR'd)
xor eax, [rsi + 0x04]     ; XOR with key to recover real syscall number
mov rcx, [rsi + 0x08]     ; handle_value (raw handle from proxy's table)
mov rdx, [rsi + 0x18]     ; target_addr (address in cs2.exe to read)
lea r8, [rsi + 0x28]      ; buffer (output buffer in ProxyData)
mov r9, [rsi + 0x20]      ; size (bytes to read)
mov [rsp + 0x28], 0       ; bytes_read = NULL (6th arg on stack)
mov r10, rcx              ; r10 = rcx (syscall convention)
syscall                    ; NtReadVirtualMemory

mov [rsi + 0x14], eax     ; status = NTSTATUS result
mov dword [rsi + 0x10], 0 ; signal = 0 (read complete)
jmp .loop                  ; wait for next request
```

Key design decisions:
- **XOR-obfuscated syscall number**: The syscall number in ProxyData is XOR'd with `0x37E4A12B`. The shellcode XORs it back at runtime. This prevents static identification of which syscall is being invoked.
- **No function calls**: The shellcode uses only the `syscall` instruction. No `call` to any address, which avoids CFG validation issues.
- **Infinite loop**: The shellcode never returns. It spins waiting for signals until the process exits or the thread is terminated.
- **SwitchToThread**: After 100 spin iterations, the reader calls `SwitchToThread()` to yield to the shellcode thread, reducing CPU contention.

## The Trampoline

### Purpose

`NtCreateThreadEx` requires a thread start address. If the start address points to `MEM_PRIVATE` memory, CFG may reject it. The trampoline is a small `MEM_PRIVATE + ERW` allocation that serves only as the initial start address. It immediately jumps to the stomped shellcode.

### Structure (22 bytes)

```asm
mov rcx, <ProxyData address>    ; 48 B9 <8 bytes>
mov rax, <shellcode address>    ; 48 B8 <8 bytes>
jmp rax                          ; FF E0
```

The trampoline:
1. Loads the ProxyData pointer into `rcx` (first argument, x64 calling convention)
2. Loads the stomped shellcode address into `rax`
3. Jumps to the shellcode

### Lifecycle

```
1. Allocate 4096 bytes MEM_PRIVATE + PAGE_EXECUTE_READWRITE
2. Write 22-byte trampoline
3. Verify trampoline bytes (read-back compare)
4. NtCreateThreadEx with start = trampoline address, arg = ProxyData
5. Wait 500ms for shellcode to start
6. Verify shellcode is running (signal consumed, status == 0)
7. DE-EXECUTE trampoline:
   a. Zero all 64 bytes of trampoline memory
   b. Change protection to PAGE_READWRITE (remove execute)
   c. Write single 0xC3 (ret) byte at trampoline start
8. Rewrite thread start address via NtSetInformationThread
9. Restore stomped page to original protection
```

### De-Execution

After the thread launches, the trampoline is a liability — it is `MEM_PRIVATE + EXECUTABLE` memory. The de-execution sequence:

1. **Zero the trampoline**: Overwrite with zeros to remove the code
2. **Remove execute permission**: `NtProtectVirtualMemory` to `PAGE_READWRITE`
3. **Write `ret` byte**: A single `0xC3` at the start ensures that if anything accidentally calls this address, it returns immediately instead of executing garbage

After de-execution, the trampoline page is `MEM_PRIVATE + PAGE_READWRITE` — no longer suspicious.

### Thread Start Address Rewriting

Anti-cheat checks `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` to verify that a thread's start address falls within a legitimate module. After the trampoline launches the shellcode:

```cpp
ULONG_PTR new_start = (ULONG_PTR)shellcode_addr;  // stomped .text address
NtSetInformationThread(thread, 9, &new_start, sizeof(new_start));
```

Info class 9 (`ThreadHideFromDebugger` is 0x11, class 9 is `ThreadImpersonationToken` on some builds — the code tries both class 9 and class 0x0A as fallbacks). This rewrites the thread's reported start address to the stomped region inside a legitimate module's `.text` section.

After rewriting, any query of the thread's start address returns an address inside a known DLL — not the `MEM_PRIVATE` trampoline.

## Smoke Test

After launching the thread and de-executing the trampoline, the reader performs a smoke test:

1. Wait 500ms
2. Read `ProxyData.signal` — if it is still non-zero, the shellcode is not consuming signals (not running)
3. Read `ProxyData.status` — if non-zero, the shellcode ran but encountered an error
4. Check thread exit code — if not `STILL_ACTIVE`, the thread crashed (likely CFG violation: `0xC0000602` or access violation: `0xC0000005`)

If the smoke test fails, the reader terminates the thread, restores the stomped bytes, and exits rather than proceeding with a broken read path.
