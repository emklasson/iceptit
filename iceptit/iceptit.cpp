// Copyright (c) 2000-2020 Mikael Klasson
// License: MIT
//
// Intercept calls to functions in dll files.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Name of the dll file you're replacing functions in.
const char* dll_name = "kernel32.dll";

//*****************************************************************************
// Write your functions below. The included samples should tell you how.
// For each function you want to replace you need to #define FIX_<FunctionName>
// and then write the function fix<FunctionName> with its proper declaration.
//*****************************************************************************

// This can be used to trick old programs into thinking they're running on an
// older version of windows.
#define FIX_GetVersionExA
BOOL WINAPI fixGetVersionExA(OSVERSIONINFO* p) {
#pragma warning(suppress : 4996)    // GetVersionEx is deprecated nowadays.
    BOOL b = GetVersionEx(p);

    p->dwMajorVersion = 4;
    p->dwMinorVersion = 0;
    p->dwPlatformId = VER_PLATFORM_WIN32_WINDOWS;

    return b;
}

// MessageBox is in user32.dll and requires dll_name to be set to "user32.dll".
// The target exe also needs to have the "user32.dll" string patched instead of
// "kernel32.dll".
#define FIX_MessageBoxA
int WINAPI fixMessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    return MessageBox(hWnd, lpText, "iceptit", MB_OK);
}

//#define FIX_GetUserDefaultLCID
//LCID WINAPI fixGetUserDefaultLCID(void) {
//    MessageBox(NULL, "beep", "GetUserDefaultLCID", MB_OK);
//
//    return 0x409;
//}
//
//#define FIX_GetDiskFreeSpaceExA
//BOOL WINAPI fixGetDiskFreeSpaceExA(
//    LPCTSTR lpDirectoryName,
//    ULARGE_INTEGER* lpFreeBytesAvailableToCaller,
//    ULARGE_INTEGER* lpTotalNumberOfBytes,
//    ULARGE_INTEGER* lpTotalNumberOfFreeBytes) {
//    lpFreeBytesAvailableToCaller->QuadPart = 0;
//    lpTotalNumberOfBytes->QuadPart = 0;
//    lpTotalNumberOfFreeBytes->QuadPart = 0;
//
//    return TRUE;
//}

//*****************************************************************************
// End of custom functions. System code below. No need to touch. Move along.
//*****************************************************************************

#include "functions.h"

unsigned int __stdcall DllMain(HANDLE hmain, unsigned int ureason, void* pres) {
    if (ureason == DLL_PROCESS_ATTACH || ureason == DLL_THREAD_ATTACH) {
        for (int j = 0; j < num_functions; j++) {
            function_ptrs[j] = GetProcAddress(
                GetModuleHandle(dll_name),
                function_names[j]);
        }
    }

    return TRUE;
}
