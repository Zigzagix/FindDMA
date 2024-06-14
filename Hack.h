#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <tchar.h>
#include <vector>
#include <stdlib.h>

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName) {
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32FirstW(hSnap, &modEntry)) {
            do {
                if (!_wcsicmp(modEntry.szModule, modName)) {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

DWORD GetProcIdByModuleName(const wchar_t* moduleName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32FirstW(hSnap, &procEntry)) {
            do {
                HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procEntry.th32ProcessID);
                if (hModSnap != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32W modEntry;
                    modEntry.dwSize = sizeof(modEntry);
                    if (Module32FirstW(hModSnap, &modEntry)) {
                        do {
                            if (!_wcsicmp(modEntry.szModule, moduleName)) {
                                procId = procEntry.th32ProcessID;
                                CloseHandle(hModSnap);
                                CloseHandle(hSnap);
                                return procId;
                            }
                        } while (Module32NextW(hModSnap, &modEntry));
                    }
                    CloseHandle(hModSnap);
                }
            } while (Process32NextW(hSnap, &procEntry));
        }
        CloseHandle(hSnap);
    }
    return procId;
}

uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets) {
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i) {
        if (!ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0)) {
            std::cerr << "Error reading memory at address: " << std::hex << addr << std::endl;
            return 0;
        }
        addr += offsets[i];
    }
    return addr;
}
