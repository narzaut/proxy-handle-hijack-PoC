# ProxyData Spin-Wait Protocol

The ProxyData protocol is the communication channel between the reader process and the shellcode running inside the proxy process. It uses a shared memory region and a spin-wait loop to synchronize read requests.

**Source:** `src/proxy/reader.cpp:49-74` (game_read), `src/proxy/proxy.h:6-26` (ProxyData struct)

## Protocol Overview

The reader and shellcode share a `ProxyData` struct allocated in the proxy's address space. The reader writes read requests; the shellcode executes them and writes results.

```
Reader (wisrvmon.exe)                    Shellcode (proxy process)
─────────────────────                    ─────────────────────────
Write target_addr + size to ProxyData
Write signal = 1                         Spin: read signal
                                         signal != 0 → execute NtReadVirtualMemory
                                         Write result to buffer
                                         Write status = NTSTATUS
                                         Write signal = 0
Poll signal until == 0
Read status (check success)
Read buffer (copy result)
```

## The Spin-Wait Loop

### Reader Side

```cpp
bool game_read(const ProxyContext& ctx, uint64_t addr, void* out, size_t sz) {
    if (sz > 4096) return false;

    // Write request: target address and size
    sys_write(ctx.proxy_handle, ctx.remote_addr + 0x18, &req, sizeof(req));

    // Signal the shellcode
    int32_t sig = 1;
    sys_write(ctx.proxy_handle, ctx.remote_addr + 0x10, &sig, 4);

    // Poll for completion
    for (int tries = 0; tries < 10000; tries++) {
        sys_read(ctx.proxy_handle, ctx.remote_addr + 0x10, &sig, 4);
        if (sig == 0) {
            // Read complete — check status and copy result
            int32_t status = 0;
            sys_read(ctx.proxy_handle, ctx.remote_addr + 0x14, &status, 4);
            bool ok = sys_read(ctx.proxy_handle, ctx.remote_addr + 0x28, out, sz);
            if (!ok || status != 0) return false;
            return true;
        }
        if (tries > 100) SwitchToThread();  // yield after 100 spins
    }
    return false;  // timeout
}
```

### Shellcode Side

```asm
.loop:
    mov eax, [rsi + 0x10]     ; read signal
    test eax, eax
    jz .loop                   ; spin while signal == 0

    ; ... execute NtReadVirtualMemory ...

    mov [rsi + 0x14], eax     ; write status
    mov dword [rsi + 0x10], 0 ; signal = 0 (done)
    jmp .loop                  ; wait for next request
```

## Timing and Yielding

The shellcode spins tightly on the signal field. The reader polls via `NtReadVirtualMemory` (a cross-process read into the proxy). After 100 poll iterations without a response, the reader calls `SwitchToThread()` to yield its CPU time slice to the shellcode thread. This is important because:

1. Both threads may be on the same CPU core
2. The reader's tight poll loop can starve the shellcode thread
3. `SwitchToThread()` gives the shellcode a chance to execute and complete the read

## Maximum Read Size

The buffer in ProxyData is 4096 bytes. Reads larger than this are rejected at the `game_read` entry point. This limit exists because:

1. The buffer is a fixed-size array in the shared struct
2. Larger reads would require dynamic allocation in the proxy
3. 4096 bytes is sufficient for any single game data structure (entity, bone array, view matrix)

## Syscall Number Obfuscation

The `NtReadVirtualMemory` syscall number stored in ProxyData is XOR-obfuscated:

```cpp
pd.syscall_num = g_sys.NtReadVirtualMemory.number ^ XOR_KEY1;  // key = 0x37E4A12B
pd.xor_key = XOR_KEY1;
```

The shellcode XORs it back at runtime:

```asm
mov eax, [rsi + 0x00]     ; XOR'd syscall number
xor eax, [rsi + 0x04]     ; XOR with key → real syscall number
```

After writing ProxyData, the reader zeros `XOR_KEY1` in its own memory. The key exists only in the proxy's ProxyData struct after initialization.

## Performance Characteristics

Each `game_read` call involves:
1. **2 cross-process writes** (request + signal): ~2 syscall round-trips
2. **N cross-process reads** (polling signal): ~N syscall round-trips
3. **1 cross-process read** (status): ~1 syscall round-trip
4. **1 cross-process read** (buffer): ~1 syscall round-trip

Total: ~4+N cross-process operations per read. With the shellcode running on the same core, the signal is typically consumed within 1-5 poll iterations. The typical latency is 5-15 microseconds per read.

For comparison, the kernel driver path (`kernel_read`) involves a single `DeviceIoControl` call per read, with typical latency of 1-3 microseconds.

## Comparison with Kernel Driver Protocol

The kernel driver uses a different protocol — `METHOD_NEITHER` IOCTL with a command struct:

```cpp
struct TDMemReadCmd {
    uint32_t process_id;
    uint32_t directory_table_type;
    uint64_t address;
    uint8_t* buffer;
    size_t count;
    uint32_t result;
};
```

The IOCTL is a single synchronous call — the kernel driver performs the read and returns the result in one round-trip. This is fundamentally faster than the spin-wait protocol but requires a loaded kernel driver.

The `game_read_dispatch()` function in `main.cpp` abstracts both paths behind a single API:

```cpp
static bool game_read_dispatch(uint64_t addr, void* out, size_t sz) {
    if (g_use_kernel_read) {
        return kernel_read(addr, out, sz);
    } else {
        return game_read(*g_proxy_ctx, addr, out, sz);
    }
}
```
