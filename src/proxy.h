#pragma once
#include "common.h"
#include "syscalls.h"

#pragma pack(push, 1)
struct ProxyData {
    uint32_t syscall_num;
    uint32_t xor_key;
    uint64_t handle_value;
    int32_t  signal;
    int32_t  status;
    uint64_t target_addr;
    uint64_t size;
    uint8_t  buffer[4096];
};
#pragma pack(pop)

static_assert(offsetof(ProxyData, syscall_num)  == 0x00, "layout");
static_assert(offsetof(ProxyData, xor_key)      == 0x04, "layout");
static_assert(offsetof(ProxyData, handle_value) == 0x08, "layout");
static_assert(offsetof(ProxyData, signal)       == 0x10, "layout");
static_assert(offsetof(ProxyData, status)       == 0x14, "layout");
static_assert(offsetof(ProxyData, target_addr)  == 0x18, "layout");
static_assert(offsetof(ProxyData, size)         == 0x20, "layout");
static_assert(offsetof(ProxyData, buffer)       == 0x28, "layout");

struct ProxyContext {
    HANDLE   proxy_handle;
    uint64_t remote_addr;
    uint64_t shellcode_addr;
    uint64_t trampoline_addr;
    HANDLE   thread_handle;
    bool     stomped;
    std::vector<uint8_t> saved_bytes;
    ULONG    saved_prot;
};

extern ProxyContext* g_proxy_ctx;
extern uint32_t XOR_KEY1;

void decrypt_shellcode();
void zero_shellcode();
ProxyContext setup_proxy(DWORD target_pid);
void proxy_cleanup(ProxyContext& ctx);

