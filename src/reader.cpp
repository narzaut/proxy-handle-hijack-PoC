#include "reader.h"

// Software-specific offset loading removed.
// Add your own Offsets struct and load_offsets() as needed.

extern int g_perf_read_count;

bool proxy_read(const ProxyContext& ctx, uint64_t addr, void* out, size_t sz) {
    if (sz > 4096) return false;
    g_perf_read_count++;

    struct { uint64_t target_addr; uint64_t size; } req = { addr, sz };
    if (!sys_write(ctx.proxy_handle, ctx.remote_addr + 0x18, &req, sizeof(req)))
        return false;

    int32_t sig = 1;
    if (!sys_write(ctx.proxy_handle, ctx.remote_addr + 0x10, &sig, 4))
        return false;

    for (int tries = 0; tries < 10000; tries++) {
        if (!sys_read(ctx.proxy_handle, ctx.remote_addr + 0x10, &sig, 4))
            return false;
        if (sig == 0) {
            int32_t status = 0;
            sys_read(ctx.proxy_handle, ctx.remote_addr + 0x14, &status, 4);
            bool ok = sys_read(ctx.proxy_handle, ctx.remote_addr + 0x28, out, sz);
            if (!ok || status != 0) return false;
            return true;
        }
        if (tries > 100) SwitchToThread();
    }
    return false;
}

DWORD find_pid(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        std::string target(name);
        do {
            if (_stricmp(pe.szExeFile, target.c_str()) == 0) {
                DWORD pid = pe.th32ProcessID;
                CloseHandle(snap);
                return pid;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

uint64_t get_module_base(DWORD pid, const char* mod) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        LOG( "CreateToolhelp32Snapshot failed for pid %lu, error %lu\n",
                (unsigned long)pid, (unsigned long)GetLastError());
        return 0;
    }
    MODULEENTRY32 me{}; me.dwSize = sizeof(me);
    int count = 0;
    if (Module32First(snap, &me)) {
        do {
            count++;
            if (_stricmp(me.szModule, mod) == 0) {
                uint64_t base = (uint64_t)me.modBaseAddr;
                CloseHandle(snap);
                return base;
            }
        } while (Module32Next(snap, &me));
    } else {
        LOG( "Module32First failed, error %lu\n", (unsigned long)GetLastError());
    }
    LOG( "Enumerated %d modules in pid %lu, '%s' not found\n",
            count, (unsigned long)pid, mod);
    CloseHandle(snap);
    return 0;
}