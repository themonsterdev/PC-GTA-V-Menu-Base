#include "pch.h"

static DWORD g_dwThreadId   = 0;
static HANDLE g_hThread     = nullptr;

typedef BOOL(WINAPIV* IS_DLC_PRESENT)(uint32_t);
static IS_DLC_PRESENT   fpIsDLCPresentTarget    = nullptr;
IS_DLC_PRESENT		    fpIsDLCPresentOriginal  = nullptr;

BOOL WINAPIV HK_IS_DLC_PRESENT(uint32_t dlcHash)
{
    return fpIsDLCPresentOriginal(dlcHash);
}

DWORD WINAPI MainThread(HMODULE hModule)
{
    AllocConsole();
    FILE* pFile;
    freopen_s(&pFile, "CONIN$", "r", stdin);
    freopen_s(&pFile, "CONOUT$", "w", stderr);
    freopen_s(&pFile, "CONOUT$", "w", stdout);

    InitPattern(GetModuleHandle(nullptr));

    fpIsDLCPresentTarget = reinterpret_cast<IS_DLC_PRESENT>(FindPattern(
        (PBYTE)"\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x20\x81\xF9\x00\x00\x00\x00",
        "xxxx?xxxxxxx????"
    ));

    InstallHook(
        fpIsDLCPresentTarget,
        HK_IS_DLC_PRESENT,
        reinterpret_cast<LPVOID*>(&fpIsDLCPresentOriginal)
    );

    while (true)
    {
        if (GetAsyncKeyState(VK_ESCAPE))
        {
            printf("Exit Hack\n");
            break;
        }

        Sleep(50);
    }

    FreeLibrary(hModule);
    return 0;
}

VOID ProcessAttach(HMODULE hModule)
{
    DisableThreadLibraryCalls(hModule);
    g_hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, &g_dwThreadId);
}

VOID ProcessDetach()
{
    UninstallHook(fpIsDLCPresentTarget);

    if (g_hThread != nullptr)
    {
        CloseHandle(g_hThread);
    }

    FreeConsole();
    ExitThread(0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ProcessAttach(hModule);
        break;
    case DLL_PROCESS_DETACH:
        ProcessDetach();
        break;
    }
    return TRUE;
}
