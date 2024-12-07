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

int MakeMessage() {

    int result = MessageBoxW(NULL,
        L"Do you want to continue?",
        L"Malware Test",
        MB_YESNO | MB_ICONWARNING);

    return result;
}