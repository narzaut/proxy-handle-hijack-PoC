# Handle Revocation

The handle revocation system is a background thread that continuously enumerates all system handles and closes any that point back to the reader process. This prevents anti-cheat from discovering the reader by opening handles to other processes and checking what they reference.

**Source:** `src/proxy/revoke.cpp` (53 lines)

## The Threat

Anti-cheat can detect the reader by:
1. Enumerating all processes
2. For each process, enumerating all open handles
3. Duplicating each handle to check what it points to
4. If any handle in any process points to the reader process, the reader is identified

This is a handle back-reference attack. Even though the reader never opens a handle to cs2.exe, other processes may hold handles to the reader (e.g., a debugger, a monitoring tool, or the anti-cheat itself).

## Implementation

The revocation thread runs in an infinite loop with 5-second intervals:

```cpp
DWORD WINAPI revoke_handles_thread(LPVOID) {
    sys_hide_thread();  // ThreadHideFromDebugger
    DWORD my_pid = GetCurrentProcessId();

    for (;;) {
        Sleep(5000);

        // Enumerate all system handles
        NtQuerySystemInformation(class 16, buf, buf_size, &ret);

        for (ULONG i = 0; i < info->Count; i++) {
            auto& e = info->Handles[i];
            if (e.UniqueProcessId == my_pid) continue;  // skip own handles

            // Open the handle owner
            HANDLE owner = sys_open(e.UniqueProcessId, PROCESS_DUP_HANDLE);
            if (!owner) continue;

            // Duplicate the handle into our process to check its target
            HANDLE duped = nullptr;
            NtDuplicateObject(owner, (HANDLE)e.HandleValue,
                GetCurrentProcess(), &duped, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!duped) { sys_close(owner); continue; }

            // Check if the handle points to our process
            DWORD target_pid = GetProcessId(duped);
            sys_close(duped);

            if (target_pid == my_pid) {
                // This handle points to us — close it at the source
                NtDuplicateObject(owner, (HANDLE)e.HandleValue,
                    nullptr, nullptr, 0, 0, DUPLICATE_CLOSE_SOURCE);
            }
            sys_close(owner);
        }

        SecureZeroMemory(buf, buf_size);  // wipe handle list from memory
    }
}
```

## DUPLICATE_CLOSE_SOURCE

The key operation is `NtDuplicateObject` with the `DUPLICATE_CLOSE_SOURCE` flag (0x00000001). When called with `TargetProcessHandle = NULL` and `TargetHandle = NULL`, this closes the source handle in the source process without creating a duplicate. The handle ceases to exist.

This is a legitimate Windows API — it is used for handle inheritance cleanup. Using it to revoke handles is not suspicious in itself.

## Thread Hiding

The revocation thread hides itself from debuggers immediately on start:

```cpp
sys_hide_thread();  // NtSetInformationThread(GetCurrentThread(), 0x11, nullptr, 0)
```

Info class `0x11` is `ThreadHideFromDebugger`. This prevents debuggers from receiving debug events for this thread, making it harder for anti-cheat debug hooks to observe the revocation activity.

## Timing

The 5-second interval is a balance between:
- **Responsiveness**: Closing handles quickly reduces the window where anti-cheat can discover them
- **Stealth**: Frequent `NtQuerySystemInformation(class 16)` calls are expensive and visible. Every 5 seconds is infrequent enough to blend with normal system activity.
- **Performance**: Each enumeration scans 500,000+ handles and opens/closes a handle for each one. This takes 1-3 seconds.

## Buffer Wiping

After each enumeration, the handle list buffer is zeroed with `SecureZeroMemory`. This prevents the handle list from persisting in memory where it could be discovered by a memory scan. The buffer contains kernel object pointers and handle values for every process in the system — sensitive data that should not linger.

## Limitations

- **Race condition**: A handle can be opened, used, and closed between revocation scans. The 5-second interval means there is always a window.
- **Kernel handles**: Handles opened from kernel mode (e.g., by a kernel driver) are not visible in `SystemHandleInformation` class 16. They would require class 64 (`SystemExtendedHandleInformation`) or kernel-mode enumeration.
- **Performance on high-handle systems**: Systems with millions of handles (servers, database machines) will see longer scan times.
