#pragma once
#include "common.h"

typedef long NTSTATUS;

struct CLIENT_ID {
    void* UniqueProcess;
    void* UniqueThread;
};

struct OBJECT_ATTRIBUTES {
    ULONG  Length;
    HANDLE RootDirectory;
    void*  ObjectName;
    ULONG  Attributes;
    void*  SecurityDescriptor;
    void*  SecurityQualityOfService;
};

struct SYSTEM_HANDLE_ENTRY {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    void*  Object;
    ULONG  GrantedAccess;
};

struct SYSTEM_HANDLE_INFORMATION {
    ULONG                Count;
    SYSTEM_HANDLE_ENTRY  Handles[1];
};

struct SyscallStub { uint32_t number; void* code; };

struct SyscallTable {
    SyscallStub NtQuerySystemInformation;
    SyscallStub NtOpenProcess;
    SyscallStub NtDuplicateObject;
    SyscallStub NtReadVirtualMemory;
    SyscallStub NtWriteVirtualMemory;
    SyscallStub NtAllocateVirtualMemory;
    SyscallStub NtFreeVirtualMemory;
    SyscallStub NtProtectVirtualMemory;
    SyscallStub NtCreateThreadEx;
    SyscallStub NtClose;
    SyscallStub NtSetInformationThread;
    SyscallStub NtCreateSection;
    SyscallStub NtMapViewOfSection;
};

typedef NTSTATUS (*fn_NtQuerySystemInformation)(ULONG, void*, ULONG, ULONG*);
typedef NTSTATUS (*fn_NtOpenProcess)(HANDLE*, ULONG, OBJECT_ATTRIBUTES*, CLIENT_ID*);
typedef NTSTATUS (*fn_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, HANDLE*, ULONG, ULONG, ULONG);
typedef NTSTATUS (*fn_NtReadVirtualMemory)(HANDLE, void*, void*, SIZE_T, SIZE_T*);
typedef NTSTATUS (*fn_NtWriteVirtualMemory)(HANDLE, void*, void*, SIZE_T, SIZE_T*);
typedef NTSTATUS (*fn_NtAllocateVirtualMemory)(HANDLE, void**, ULONG_PTR, SIZE_T*, ULONG, ULONG);
typedef NTSTATUS (*fn_NtFreeVirtualMemory)(HANDLE, void**, SIZE_T*, ULONG);
typedef NTSTATUS (*fn_NtProtectVirtualMemory)(HANDLE, void**, SIZE_T*, ULONG, ULONG*);
typedef NTSTATUS (*fn_NtCreateThreadEx)(HANDLE*, ULONG, void*, HANDLE, void*, void*, ULONG, SIZE_T, SIZE_T, SIZE_T, void*);
typedef NTSTATUS (*fn_NtClose)(HANDLE);
typedef NTSTATUS (*fn_NtSetInformationThread)(HANDLE, ULONG, void*, ULONG);
typedef NTSTATUS (*fn_NtCreateSection)(HANDLE*, ULONG, OBJECT_ATTRIBUTES*, LARGE_INTEGER*, ULONG, ULONG, HANDLE);
typedef NTSTATUS (*fn_NtMapViewOfSection)(HANDLE, HANDLE, void**, ULONG_PTR, SIZE_T, LARGE_INTEGER*, SIZE_T*, ULONG, ULONG, ULONG);

extern SyscallTable g_sys;

void find_syscall_gadget();
SyscallTable resolve_syscalls();
void lock_stubs();
HANDLE sys_open(DWORD pid, ULONG access);
bool sys_read(HANDLE h, uint64_t addr, void* buf, size_t sz);
bool sys_write(HANDLE h, uint64_t addr, const void* buf, size_t sz);
void sys_close(HANDLE h);
bool sys_protect(HANDLE h, uint64_t addr, size_t sz, ULONG new_prot, ULONG* old_prot);
bool sys_free(HANDLE h, uint64_t addr);
uint64_t sys_alloc_remote(HANDLE h, size_t size, ULONG prot);
uint64_t sys_alloc_remote_backed(HANDLE h, size_t size, const wchar_t* backing_file);
HANDLE sys_create_thread(HANDLE process, LPTHREAD_START_ROUTINE start, PVOID param);
bool enable_mitigation_policy();
void sys_hide_thread();