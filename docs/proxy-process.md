# Proxy Process: Handle Hijacking

The proxy process is the cornerstone of usermode memory reading. Instead of opening a handle to cs2.exe (which anti-cheat detects), the reader finds a legitimate process that already holds a `PROCESS_VM_READ` handle to cs2.exe and hijacks it.

**Source:** `src/proxy/proxy.cpp` — `setup_proxy()` (lines 249–570)

## How Handle Hijacking Works

### Step 1: Enumerate All System Handles

The reader calls `NtQuerySystemInformation` with class 16 (`SystemHandleInformation`). This returns a `SYSTEM_HANDLE_INFORMATION` structure containing every open handle in the system — typically 500,000+ entries.

```cpp
struct SYSTEM_HANDLE_ENTRY {
    USHORT UniqueProcessId;    // PID that owns the handle
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;    // type (process, file, etc.)
    UCHAR  HandleAttributes;
    USHORT HandleValue;        // handle value in owner's handle table
    void*  Object;             // kernel object pointer
    ULONG  GrantedAccess;      // access rights (PROCESS_VM_READ, etc.)
};
```

### Step 2: Filter for PROCESS_VM_READ Handles

The reader iterates all handles and filters for:
- Not owned by the reader's own PID
- Not owned by the target PID (cs2.exe)
- Has `PROCESS_VM_READ` (0x0010) in `GrantedAccess`

### Step 3: Verify Handle Target

For each candidate handle, the reader:
1. Opens the handle owner with `PROCESS_DUP_HANDLE`
2. Duplicates the handle into the reader's own process using `NtDuplicateObject` with `DUPLICATE_SAME_ACCESS`
3. Calls `GetProcessId()` on the duplicated handle to check which process it points to
4. If it points to cs2.exe, this is the proxy

```cpp
HANDLE owner = sys_open(e.UniqueProcessId, PROCESS_DUP_HANDLE);
HANDLE duped = nullptr;
NtDuplicateObject(owner, (HANDLE)e.HandleValue,
    GetCurrentProcess(), &duped, 0, 0, DUPLICATE_SAME_ACCESS);
DWORD hpid = GetProcessId(duped);
sys_close(duped);
if (hpid == target_pid) { /* found proxy */ }
```

### Step 4: Retry Loop

Legitimate processes (Discord, OBS, AMD ReLive) may not have opened their cs2.exe handle yet when the reader starts. The reader retries up to 30 times with 1-second intervals, re-enumerating handles each time.

## Why the Handle Value Works Without Duplication

The `HandleValue` from `SYSTEM_HANDLE_ENTRY` is an index into the proxy process's handle table. It is valid in the proxy's process context. The shellcode running inside the proxy uses this raw handle value directly — it does not need to duplicate the handle. This is because `NtReadVirtualMemory` resolves handle values against the calling process's handle table, and the shellcode is executing in the proxy's context.

## Proxy Process Selection

The proxy is not chosen — it is discovered. Any process that holds a `PROCESS_VM_READ` handle to cs2.exe qualifies. Common candidates:

- **Discord overlay** (`discord.exe`, `DiscordOverlay.exe`)
- **OBS** (`obs64.exe`) — captures game windows
- **AMD ReLive** (`RadeonSoftware.exe`) — anti-lag feature
- **NVIDIA GeForce Experience** (`NVIDIA Share.exe`)
- **Steam overlay** (`GameOverlayUI.exe`) — though this may be detected

The reader does not care which process it is. It only needs the handle.

## Post-Discovery Setup

Once the proxy is found:

1. **Open the proxy process** with `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`
2. **Allocate ProxyData** — a shared communication struct in the proxy's address space (`NtAllocateVirtualMemory`, `PAGE_READWRITE`)
3. **Populate ProxyData** with the XOR-obfuscated syscall number, the raw handle value, and signal/status fields
4. **Inject shellcode** via module stomping (see `module-stomping.md`)
5. **Launch shellcode thread** via trampoline (see `shellcode-trampoline.md`)
6. **Verify shellcode is running** — poll `ProxyData.signal` and `ProxyData.status`
7. **De-execute trampoline** — zero it, set to `PAGE_READWRITE`, write single `ret` byte
8. **Rewrite thread start address** — `NtSetInformationThread` to point at stomped region
9. **Smoke test** — verify shellcode consumes signals after 500ms

## ProxyData Layout

```cpp
#pragma pack(push, 1)
struct ProxyData {
    uint32_t syscall_num;    // NtReadVirtualMemory syscall number XOR'd with key
    uint32_t xor_key;        // XOR key (zeroed after init)
    uint64_t handle_value;   // raw handle value from proxy's handle table
    int32_t  signal;         // 1 = read request pending, 0 = idle
    int32_t  status;         // NTSTATUS result of last read
    uint64_t target_addr;    // address to read from cs2.exe
    uint64_t size;           // bytes to read (max 4096)
    uint8_t  buffer[4096];   // read result buffer
};
#pragma pack(pop)
```

The syscall number is XOR-obfuscated with key `0x37E4A12B` to prevent static analysis from trivially identifying the shellcode's purpose. The key is zeroed after writing ProxyData.

## Failure Modes

| Failure | Cause | Behavior |
|---------|-------|----------|
| No proxy found | No process holds `PROCESS_VM_READ` to cs2.exe | Exit after 30 retries |
| Shellcode not responding | CFG violation, access violation, or shellcode crash | Exit with diagnostic (thread exit code, register dump) |
| Smoke test fails | Shellcode alive but not consuming signals | Terminate thread, exit |
| Trampoline verify fails | Write to proxy memory failed | Exit |

## Probe and Verify Modes

The proxy system includes two diagnostic modes:

- **`--probe`** (`do_probe()`): Enumerates proxy candidates and reports which modules have sufficient `.text` slack for shellcode injection. Does not inject anything.
- **`--verify`** (`do_verify()`): Scans the proxy process for `MEM_PRIVATE + EXECUTABLE` memory regions that would be suspicious to anti-cheat. Reports the forensic surface.
