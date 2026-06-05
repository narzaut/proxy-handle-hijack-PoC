#include "revoke.h"
#include "syscalls.h"

DWORD WINAPI revoke_handles_thread(LPVOID) {
    sys_hide_thread();
    DWORD my_pid = GetCurrentProcessId();
    for (;;) {
        Sleep(5000);
        ULONG buf_size = 4 * 1024 * 1024;
        std::vector<uint8_t> buf(buf_size);
        NTSTATUS status;
        ULONG ret = 0;
        do {
            buf.resize(buf_size);
            status = ((fn_NtQuerySystemInformation)g_sys.NtQuerySystemInformation.code)(
                16, buf.data(), buf_size, &ret);
            if (status == (NTSTATUS)0xC0000004L) buf_size *= 2;
        } while (status == (NTSTATUS)0xC0000004L);
        if (status != 0) continue;

        auto* info = (SYSTEM_HANDLE_INFORMATION*)buf.data();
        for (ULONG i = 0; i < info->Count; i++) {
            auto& e = info->Handles[i];
            if (e.UniqueProcessId == (USHORT)my_pid) continue;

            HANDLE owner = sys_open(e.UniqueProcessId, PROCESS_DUP_HANDLE);
            if (!owner) continue;

            HANDLE duped = nullptr;
            NTSTATUS ds = ((fn_NtDuplicateObject)g_sys.NtDuplicateObject.code)(
                owner, (HANDLE)(uintptr_t)e.HandleValue,
                GetCurrentProcess(), &duped, 0, 0, 0x00000002);
            if (ds != 0 || !duped) {
                sys_close(owner);
                continue;
            }

            DWORD target_pid = GetProcessId(duped);
            sys_close(duped);

            if (target_pid == my_pid) {
                NTSTATUS rs = ((fn_NtDuplicateObject)g_sys.NtDuplicateObject.code)(
                    owner, (HANDLE)(uintptr_t)e.HandleValue,
                    nullptr, nullptr, 0, 0, 0x00000001);
                if (rs == 0) {
                    LOG("Revoked handle 0x%x from pid %u\n", e.HandleValue, (unsigned)e.UniqueProcessId);
                }
            }
            sys_close(owner);
        }
        SecureZeroMemory(buf.data(), buf.size());
    }
}