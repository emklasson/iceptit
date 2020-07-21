// Copyright (c) 2000-2020 Mikael Klasson
// License: MIT

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

// GetVersionEx is deprecated nowadays so disable warning to get it to compile.
#pragma warning(disable : 4996)

int WINAPI WinMain(HINSTANCE hinst, HINSTANCE hprev, char* pcmdline, int ncmd) {
    OSVERSIONINFO osvi;
    char abuff[256];

    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionEx(&osvi);
    snprintf(abuff, sizeof(abuff), "v%d.%d", osvi.dwMajorVersion, osvi.dwMinorVersion);
    MessageBox(NULL, abuff, "GetVersionEx returned", MB_OK);

    return 0;
}
