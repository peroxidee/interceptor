#include <stdio.h>
#include <processthreadsapi.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <bits/time.h>
#include <errno.h>
#include <wchar.h>


BOOL (__cdecl *HookFunction)(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction);
VOID (__cdecl *UnhookFunction)(ULONG_PTR Function);
ULONG_PTR (__cdecl *GetOriginalFunction)(ULONG_PTR Hook);

typedef struct {
    DWORD processId;
    TCHAR processName[MAX_PATH];
} ProcessInfo;

#define k(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define w(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define i(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define e(msg, ...) printf("[err] " msg "\n", ##__VA_ARGS__)

void HooksMan::hookFunctions() {
    if (HookFunction == NULL || UnhookFunction == NULL || GetOrginalFunction = NULL) {
        w("null detected (func)");
        return;
    }

    hLibrary = LoadLibrary(L"Iphlpapi.dll");
    if (hLibrary == NULL) {
        w("null detected (lib)");
        return;
    }
}


ProcessInfo procFinder(DWORD ProcessId) {
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (hProcess == NULL) {
        w("Failed to open process: %s", ProcessId);
    }
    else {
        HMODULE hMod;
        DWORD cbNeeded;
        unsigned char *bytes = (unsigned char*)&hMod;
        if ( EnumProcessModulesEx( hProcess, &hMod, bytes, sizeof(hMod),
             &cbNeeded) ) {
            GetModuleBaseName( hProcess, hMod, szProcessName,
                               sizeof(szProcessName)/sizeof(TCHAR) );

            if (szProcessName == "notepad.exe"){

                ProcessInfo procInfo;
                procInfo.processId = ProcessId;
                procInfo.processName = szProcessName;

                return(procInfo);

            }
        }



    }


    _tprintf( TEXT("%s  (PID: %u)\n"), szProcessName, ProcessId );


    CloseHandle(hProcess );
}

int main(int argc, char *argv[]) {

    //Obtain the target process handle.


    if (argc < 2) {
        e("not enough args.");
        printf("Usage: %s <proc id>\n", argv[0]);
    }
    DWORD *pid = argv[1];
    ProcessInfo target = procFinder(pid);


    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target.processId);

    // Allocate memory within a target process and write the external DLL path into it (here we mean writing the dynamic library path that contains the hook).


    lpRemoteString str = VirtualAllocEx(hProcess, NULL, 1024,MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!str) {
        e("Failed to allocate memory.");
        CloseHandle(hProcess);
        return 1;
    }




    if (!WriteProcessMemory()) {
        e("Failed to write memory.");
        VirtualFreeEx(hProcess, str, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    LPVOID lpLoadLibraryW = NULL;
    lpLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (!lpLoadLibraryW) {
        e("Failed to load kernel32.dll.");
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL,  (LPTHREAD_START_ROUTINE)lpLoadLibraryW, lpRemoteString, NULL, NULL);

    if (!hThread) {
        DWORD error = GetLastError();
        e("Failed to create remote thread, %s",error );
        return 1;
    } else {
        WaitForSingleObject(hThread, 400);
        ResumeThread(hThread);
    }



    //Create a thread inside the target process that would load the library and set up the hook.


    return 0;
}