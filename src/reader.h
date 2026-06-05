#pragma once
#include "common.h"
#include "proxy.h"

// Generic process/module utilities.
// Software-specific offset loading removed — add your own Offsets struct.

DWORD find_pid(const char* name);
uint64_t get_module_base(DWORD pid, const char* mod);
bool proxy_read(const ProxyContext& ctx, uint64_t addr, void* out, size_t sz);
