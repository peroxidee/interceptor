#include <stdio.h>
#include <processthreadsapi.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

typedef struct {
    DWORD processId;
    TCHAR processName[MAX_PATH];
} ProcessInfo;

#define k(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define w(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define i(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define e(msg, ...) printf("[err] " msg "\n", ##__VA_ARGS__)

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


    VirtualAllocEx();
    WriteProcessMemory();



    //Create a thread inside the target process that would load the library and set up the hook.


   STATUS stat = CreateRemoteThreadEx();
    return 0;
}