# Module Stomping

Module stomping is the technique of writing shellcode into the unused slack space of a legitimate DLL's `.text` section inside the proxy process. This avoids creating `MEM_PRIVATE + EXECUTABLE` memory regions, which are a primary detection vector for injected code.

**Source:** `src/proxy/proxy.cpp` — `find_text_slack()` (lines 110–169), `stomp_shellcode()` (lines 171–206), `enum_proxy_modules()` (lines 90–108)

## Why Module Stomping

When you allocate memory with `NtAllocateVirtualMemory` and set it to `PAGE_EXECUTE_READWRITE`, you create a memory region with three suspicious properties:

1. **`MEM_PRIVATE`** — not backed by any file on disk
2. **`PAGE_EXECUTE_READWRITE`** — writable and executable simultaneously
3. **No backing module** — the memory address does not fall within any loaded DLL's range

Anti-cheat scans for these regions via `VirtualQueryEx`. Any `MEM_PRIVATE + EXECUTABLE` region in a process that interacts with the game is flagged.

Module stomping avoids all three: the shellcode lives inside a legitimate module's `.text` section (backed by a DLL on disk), the page protection is `PAGE_EXECUTE_READ` (normal for code), and the memory address resolves to a known module.

## The .text Slack Space

PE sections are aligned to page boundaries (typically 4096 bytes). The `.text` section's `VirtualSize` (actual code size) is often smaller than its `SizeOfRawData` (disk-aligned size) or the distance to the next section's RVA. The gap between `VirtualSize` and the next section's start is slack space — allocated, executable, but unused.

```
.text section:
  RVA: 0x1000
  VirtualSize: 0x3A4C  (actual code ends here)
  Next section (.rdata) RVA: 0x5000
  
  Slack space: 0x4A4C to 0x5000 = 1,460 bytes of unused executable memory
```

This slack is part of the module's memory mapping. It has `PAGE_EXECUTE_READ` protection. It is backed by the DLL file. Writing shellcode here creates no forensic anomaly — it looks like padding bytes at the end of the code section.

## Module Selection

### Blocklist

The stomping code maintains a 13-module blocklist of security-critical and anticheat-related DLLs that must not be stomped. The names are XOR-encoded at compile time with key `0x9C`:

```cpp
static const uint8_t B0[] = {0xF2,0xE8,0xF8,0xF0,0xF0,0xB2,0xF8,0xF0,0xF0}; // "kernel32.dll" etc.
// ... 12 more entries
```

The blocklist prevents stomping modules that:
- Are monitored by anti-cheat (security DLLs)
- Have integrity checks (system DLLs with code signing verification)
- Are small enough that slack space is insufficient

### Size Preference

Modules are sorted by size (ascending) after blocklist filtering. Smaller modules are preferred because:
- They tend to have proportionally more slack space
- They are less likely to have integrity monitoring
- The stomped region is a smaller fraction of the module

### Enumeration

Modules are enumerated via `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)` on the proxy process. Each module's PE headers are read from the proxy's memory to find the `.text` section boundaries.

## The Stomp Flow

```
1. Read PE headers from proxy memory
2. Find .text section: RVA, VirtualSize
3. Find next section by RVA (sorted)
4. Calculate slack = next_section.RVA - (.text.RVA + .text.VirtualSize)
5. If slack < shellcode_size: skip module, try next
6. Change page protection to PAGE_EXECUTE_READWRITE (sys_protect)
7. Save original bytes at slack address
8. Write shellcode to slack address
9. Read back and verify byte-for-byte match
10. FlushInstructionCache (ensure CPU sees new code)
11. Read back AGAIN and verify (post-flush check)
12. Keep ERW protection until thread launch, then restore original protection
```

### Double Verification

The stomp is verified twice:

1. **Pre-flush verify**: Immediately after writing, read back the shellcode bytes and compare. Catches write failures.
2. **Post-flush verify**: After `FlushInstructionCache`, read back again. This catches cases where the cache flush triggers a page fault that re-reads from the backing file (copy-on-write semantics).

If either verification fails, the stomp is aborted and the next module is tried.

### Original Byte Preservation

The original bytes at the stomp address are saved in `ProxyContext.saved_bytes`. On cleanup (normal exit or failure), these bytes are written back:

```cpp
sys_protect(proxy_h, shellcode_addr, saved_bytes.size(), PAGE_EXECUTE_READWRITE, &tmp);
sys_write(proxy_h, shellcode_addr, saved_bytes.data(), saved_bytes.size());
sys_protect(proxy_h, shellcode_addr, saved_bytes.size(), saved_prot, &tmp);
```

The page protection is also restored to its original value. After cleanup, the module looks exactly as it did before stomping — no forensic trace remains.

## CFG Compatibility

Control Flow Guard (CFG) maintains a bitmap of valid indirect call targets. Code within a module's `.text` section is CFG-valid by default because the module was loaded through the normal Windows loader. Shellcode stomped into `.text` slack inherits this validity — indirect calls to the stomped address pass CFG checks.

This is critical because `NtCreateThreadEx` on modern Windows validates the thread start address against CFG. A `MEM_PRIVATE` allocation would fail this check. A `.text` section address passes.

## Limitations

- **Shellcode size**: The shellcode is 62 bytes. Most modules have at least this much slack, but very small DLLs may not.
- **Module unloading**: If the proxy process unloads the stomped module while the shellcode thread is running, the thread crashes. The blocklist avoids modules known to be dynamically loaded/unloaded.
- **Code integrity**: Some modules have runtime integrity checks (e.g., `LdrVerifyImageMatchesChecksum`). The blocklist avoids these.
