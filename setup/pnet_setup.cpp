/*
 * PNet Setup.exe — installs packaged app into LocalAppData and launches it.
 */
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")

static void fail(const wchar_t *msg)
{
    MessageBoxW(NULL, msg, L"PNet Setup", MB_ICONERROR | MB_OK);
    ExitProcess(1);
}

static int path_exists(const wchar_t *p)
{
    return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
}

static void join_path(wchar_t *out, size_t n, const wchar_t *a, const wchar_t *b)
{
    _snwprintf(out, n, L"%s\\%s", a, b);
    out[n - 1] = 0;
}

static int copy_tree(const wchar_t *from, const wchar_t *to)
{
    wchar_t from_double[MAX_PATH * 2];
    wchar_t to_double[MAX_PATH * 2];
    memset(from_double, 0, sizeof(from_double));
    memset(to_double, 0, sizeof(to_double));
    _snwprintf(from_double, MAX_PATH * 2 - 2, L"%s\\*", from);
    _snwprintf(to_double, MAX_PATH * 2 - 2, L"%s", to);

    SHFILEOPSTRUCTW op;
    memset(&op, 0, sizeof(op));
    op.wFunc = FO_COPY;
    op.pFrom = from_double;
    op.pTo = to_double;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_SILENT;
    return SHFileOperationW(&op) == 0 && !op.fAnyOperationsAborted;
}

static int create_shortcut(const wchar_t *target, const wchar_t *linkPath, const wchar_t *workdir)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return 0;

    IShellLinkW *psl = NULL;
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void **)&psl);
    if (FAILED(hr)) { CoUninitialize(); return 0; }

    psl->SetPath(target);
    psl->SetWorkingDirectory(workdir);
    psl->SetDescription(L"PNet Wi-Fi scanner");

    IPersistFile *ppf = NULL;
    hr = psl->QueryInterface(IID_IPersistFile, (void **)&ppf);
    int ok = 0;
    if (SUCCEEDED(hr)) {
        ok = SUCCEEDED(ppf->Save(linkPath, TRUE));
        ppf->Release();
    }
    psl->Release();
    CoUninitialize();
    return ok;
}

static int find_payload(wchar_t *out, size_t n)
{
    wchar_t exe[MAX_PATH];
    wchar_t try_path[MAX_PATH];
    wchar_t app[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    PathRemoveFileSpecW(exe);

    join_path(try_path, MAX_PATH, exe, L"payload");
    join_path(app, MAX_PATH, try_path, L"PNet.exe");
    if (path_exists(app)) {
        wcsncpy(out, try_path, n - 1);
        out[n - 1] = 0;
        return 1;
    }

    _snwprintf(try_path, MAX_PATH, L"%s\\desktop\\dist\\win-unpacked", exe);
    join_path(app, MAX_PATH, try_path, L"PNet.exe");
    if (path_exists(app)) {
        wcsncpy(out, try_path, n - 1);
        out[n - 1] = 0;
        return 1;
    }

    _snwprintf(try_path, MAX_PATH, L"%s\\..\\desktop\\dist\\win-unpacked", exe);
    wchar_t full[MAX_PATH];
    GetFullPathNameW(try_path, MAX_PATH, full, NULL);
    join_path(app, MAX_PATH, full, L"PNet.exe");
    if (path_exists(app)) {
        wcsncpy(out, full, n - 1);
        out[n - 1] = 0;
        return 1;
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    wchar_t payload[MAX_PATH];
    wchar_t dest[MAX_PATH];
    wchar_t appdata[MAX_PATH];
    wchar_t desktop[MAX_PATH];
    wchar_t startmenu[MAX_PATH];
    wchar_t target[MAX_PATH];
    wchar_t link[MAX_PATH];
    wchar_t menu[MAX_PATH];

    if (!find_payload(payload, MAX_PATH))
        fail(L"PNet payload not found.\n\nRun build-setup-exe.bat first.");

    if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata)))
        fail(L"Cannot resolve AppData folder.");

    join_path(dest, MAX_PATH, appdata, L"PNet");
    CreateDirectoryW(dest, NULL);

    if (!copy_tree(payload, dest))
        fail(L"Could not copy PNet files.\nClose any running PNet window and try again.");

    join_path(target, MAX_PATH, dest, L"PNet.exe");
    if (!path_exists(target))
        fail(L"Install incomplete: PNet.exe missing.");

    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktop))) {
        join_path(link, MAX_PATH, desktop, L"PNet.lnk");
        create_shortcut(target, link, dest);
    }
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAMS, NULL, 0, startmenu))) {
        join_path(menu, MAX_PATH, startmenu, L"PNet");
        CreateDirectoryW(menu, NULL);
        join_path(link, MAX_PATH, menu, L"PNet.lnk");
        create_shortcut(target, link, dest);
    }

    MessageBoxW(NULL,
        L"PNet installed.\n\nA desktop shortcut was created.\nThe app will open now.",
        L"PNet Setup", MB_ICONINFORMATION | MB_OK);

    ShellExecuteW(NULL, L"open", target, NULL, dest, SW_SHOWNORMAL);
    return 0;
}
