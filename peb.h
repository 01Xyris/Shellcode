#include <Windows.h>

#define memset my_memset
#ifndef __NTDLL_H__

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a' : c1)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

#endif

int my_stricmp(const char* s1, const char* s2) {
    while (*s1 && *s2) {
        char c1 = *s1++;
        char c2 = *s2++;

        if (c1 >= 'A' && c1 <= 'Z') {
            c1 += 'a' - 'A';
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 += 'a' - 'A';
        }

        if (c1 != c2) {
            return (unsigned char)c1 - (unsigned char)c2;
        }
    }

    return (unsigned char)(*s1) - (unsigned char)(*s2);
}

void strncpy_safe(char* dest, const char* src, size_t max_len) {
    size_t i = 0;
    for (; i < max_len - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

size_t mbstowcs_safe(wchar_t* dest, const char* src, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1 && src[i] != '\0') {
        dest[i] = (wchar_t)src[i];
        i++;
    }
    dest[i] = L'\0';
    return i;
}

LPVOID get_module_by_name(WCHAR* module_name) {
    PPEB peb = NULL;
    peb = (PPEB)__readfsdword(0x30);

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* listHead = &ldr->InLoadOrderModuleList;

    PLDR_DATA_TABLE_ENTRY currentModule = (PLDR_DATA_TABLE_ENTRY)listHead->Flink;

    while (&currentModule->InLoadOrderModuleList != listHead) {
        if (currentModule->BaseDllName.Buffer != NULL) {
            WCHAR* curr_name = currentModule->BaseDllName.Buffer;

            size_t i;
            for (i = 0; module_name[i] != 0 && curr_name[i] != 0; i++) {
                WCHAR c1, c2;
                TO_LOWERCASE(c1, module_name[i]);
                TO_LOWERCASE(c2, curr_name[i]);
                if (c1 != c2) {
                    break;
                }
            }

            if (module_name[i] == 0 && curr_name[i] == 0) {
                return currentModule->BaseAddress;
            }
        }
        currentModule = (PLDR_DATA_TABLE_ENTRY)currentModule->InLoadOrderModuleList.Flink;
    }
    return NULL;
}

void* my_memset(void* dest, int c, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    while (count--) {
        *p++ = (unsigned char)c;
    }
    return dest;
}

LPVOID get_func_by_name(LPVOID module, const char* func_name) {
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (exportsDir->VirtualAddress == 0) {
        return NULL;
    }

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module + exportsDir->VirtualAddress);
    DWORD* nameRVAs = (DWORD*)((BYTE*)module + exp->AddressOfNames);
    DWORD* funcRVAs = (DWORD*)((BYTE*)module + exp->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)module + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* currentName = (char*)((BYTE*)module + nameRVAs[i]);

        if (my_stricmp(currentName, func_name) == 0) {
            DWORD funcRVA = funcRVAs[ordinals[i]];
            LPVOID funcAddr = (BYTE*)module + funcRVA;

            if (funcRVA >= exportsDir->VirtualAddress && funcRVA < exportsDir->VirtualAddress + exportsDir->Size) {
                char* forwarderStr = (char*)funcAddr;

                char dllName[MAX_PATH];
                my_memset(dllName, 0, sizeof(dllName));

                char funcName[MAX_PATH];
                my_memset(funcName, 0, sizeof(funcName));
                char* p = forwarderStr;
                size_t dllNameLen = 0;

                while (*p && *p != '.' && dllNameLen < sizeof(dllName) - 1) {
                    dllName[dllNameLen++] = *p++;
                }

                if (*p++ != '.') return NULL;
                dllName[dllNameLen] = '\0';

                strncpy_safe(funcName, p, MAX_PATH);

                wchar_t wDllName[MAX_PATH];
                mbstowcs_safe(wDllName, dllName, MAX_PATH);
                LPVOID forwardedModule = get_module_by_name(wDllName);
                if (forwardedModule == NULL) {
                    return NULL;
                }

                return get_func_by_name(forwardedModule, funcName);
            }

            return funcAddr;
        }
    }
    return NULL;
}