#include <windows.h>
#include <stdio.h>

void PrintPEInfo(const char* filePath) {
    // Open the file
    HANDLE fileHandle = CreateFileA(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (fileHandle == INVALID_HANDLE_VALUE) {
        printf("Couldn't open file\n");
        return;
    }

    // Create file mapping
    HANDLE mapHandle = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapHandle) {
        CloseHandle(fileHandle);
        printf("Couldn't create file mapping\n");
        return;
    }

    // Map the file into memory
    LPVOID fileBase = MapViewOfFile(mapHandle, FILE_MAP_READ, 0, 0, 0);
    if (!fileBase) {
        CloseHandle(mapHandle);
        CloseHandle(fileHandle);
        printf("Couldn't map view of file\n");
        return;
    }

    // Get DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Not a valid PE file\n");
        UnmapViewOfFile(fileBase);
        CloseHandle(mapHandle);
        CloseHandle(fileHandle);
        return;
    }

    // Get PE header
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)fileBase + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid PE file\n");
        UnmapViewOfFile(fileBase);
        CloseHandle(mapHandle);
        CloseHandle(fileHandle);
        return;
    }

    // Print information
    printf("DOS Magic: %X\n", dosHeader->e_magic);
    printf("PE Signature: %X\n", ntHeader->Signature);
    printf("Machine type: %X\n", ntHeader->FileHeader.Machine);
    printf("Number of sections: %d\n", ntHeader->FileHeader.NumberOfSections);
    printf("Timestamp: %X\n", ntHeader->FileHeader.TimeDateStamp);
    printf("Size of optional header: %X\n", ntHeader->FileHeader.SizeOfOptionalHeader);
    printf("Characteristics: %X\n", ntHeader->FileHeader.Characteristics);

    // Print Optional Header info
    printf("\nOptional Header:\n");
    printf("Magic: %X\n", ntHeader->OptionalHeader.Magic);
    printf("Entry point: %X\n", ntHeader->OptionalHeader.AddressOfEntryPoint);
    printf("Image base: %llX\n", ntHeader->OptionalHeader.ImageBase);
    printf("Section alignment: %X\n", ntHeader->OptionalHeader.SectionAlignment);
    printf("File alignment: %X\n", ntHeader->OptionalHeader.FileAlignment);

    // Get section headers
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    printf("\nSections:\n");
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++) {
        printf("Section: %.8s\n", section->Name);
        printf("  Virtual size: %X\n", section->Misc.VirtualSize);
        printf("  Virtual address: %X\n", section->VirtualAddress);
        printf("  Raw size: %X\n", section->SizeOfRawData);
        printf("  Raw address: %X\n", section->PointerToRawData);
        printf("  Characteristics: %X\n", section->Characteristics);
        printf("\n");
    }

    // Cleanup
    UnmapViewOfFile(fileBase);
    CloseHandle(mapHandle);
    CloseHandle(fileHandle);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <path_to_dll_or_exe>\n", argv[0]);
        return 1;
    }

    PrintPEInfo(argv[1]);
    return 0;
}