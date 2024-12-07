#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <processthreadsapi.h>



#pragma comment(lib, "user32.lib")

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;    // Should be MZ (0x5A4D)
    WORD e_cblp;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD Magic;      // PE file signature
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

// External function declaration
__declspec(dllimport) VOID WINAPI ExternalFunction();

// DLL entry point
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved
)
{
    switch(fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded
                break;
        case DLL_PROCESS_DETACH:
            // DLL is being unloaded
                break;
    }
    return TRUE;

}

DWORD FakeGetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) {
    DWORD(*OriginalGetAdaptersInfo)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);

    OriginalGetAdaptersInfo = (DWORD(*)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen)) HooksManager::GetOriginalFunction((ULONG_PTR)FakeGetAdaptersInfo);

    DWORD result = OriginalGetAdaptersInfo(pAdapterInfo, pOutBufLen);
    std::string fakeAdapterName = {"11111111-2222-3333-4444-555555555555"};
    std::string fakeAdapterDescription = "LOOOL";

    if (pAdapterInfo != NULL) {
        strcpy_s(pAdapterInfo->AdapterName, sizeof(pAdapterInfo->AdapterName), fakeAdapterName.c_str());
        strcpy_s(pAdapterInfo->Description, sizeof(pAdapterInfo->Description), fakeAdapterDescription.c_str());

        for (int i=0; i<pAdapterInfo->NumberOfDevices; i++) {
            pAdapterInfo->Address[i] = (BYTE)i;
           MessageBoxW(NULL,
                L"Do you want to continue?",
                L"Warning",
                MB_OK);
        }

    }
    return result;

}

