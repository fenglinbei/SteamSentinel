#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef NOUSER
#define NOUSER
#endif
#ifndef NOGDI
#define NOGDI
#endif
#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace
{
constexpr wchar_t kWorkerAssemblyName[] = L"SteamSentinel.ArchiveWorker.dll";
constexpr size_t kMaxPathChars = 32768;

void WriteStdErr(const char* text)
{
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    if (err == nullptr || err == INVALID_HANDLE_VALUE || text == nullptr) return;
    DWORD len = 0;
    while (text[len] != '\0') ++len;
    if (len == 0) return;
    DWORD written = 0;
    WriteFile(err, text, len, &written, nullptr);
}

wchar_t ToLowerAscii(wchar_t c)
{
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + (L'a' - L'A')) : c;
}

bool EqualsAsciiIgnoreCase(const std::wstring& a, const wchar_t* b)
{
    if (b == nullptr) return false;
    size_t i = 0;
    while (b[i] != L'\0')
    {
        if (i >= a.size() || ToLowerAscii(a[i]) != ToLowerAscii(b[i])) return false;
        ++i;
    }
    return i == a.size();
}

bool IsRedirectingReparseTag(DWORD tag)
{
    // 识别符号链接/挂载点（Surrogate 位）与 AppExecLink，放行 WOF/CompactOS 等非重定向系统标签。
    return (tag & 0x20000000u) != 0u || tag == 0x8000001Bu;
}

bool CheckLocalObject(const std::wstring& path, bool expectDirectory, bool& exists)
{
    exists = false;
    if (path.empty()) return false;
    HANDLE handle = CreateFileW(
        path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return true;
        return false;
    }
    exists = true;
    FILE_ATTRIBUTE_TAG_INFO info{};
    BOOL ok = GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info));
    CloseHandle(handle);
    if (!ok) return false;
    bool isDir = (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (isDir != expectDirectory) return false;
    if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 && IsRedirectingReparseTag(info.ReparseTag))
    {
        return false;
    }
    return true;
}

bool VerifyRequiredFile(const std::wstring& path)
{
    bool exists = false;
    return CheckLocalObject(path, false, exists) && exists;
}

bool VerifyRequiredDirectory(const std::wstring& path)
{
    bool exists = false;
    return CheckLocalObject(path, true, exists) && exists;
}

bool GetModulePath(std::wstring& outPath)
{
    DWORD cap = 512;
    while (cap <= kMaxPathChars)
    {
        std::wstring buf(cap, L'\0');
        DWORD len = GetModuleFileNameW(nullptr, &buf[0], cap);
        if (len == 0) return false;
        if (len < cap)
        {
            buf.resize(len);
            outPath = std::move(buf);
            return true;
        }
        if (cap == kMaxPathChars) return false;
        cap = (cap <= kMaxPathChars / 2) ? (cap * 2) : static_cast<DWORD>(kMaxPathChars);
    }
    return false;
}

bool IsAllowedWorkerExeName(const std::wstring& exeName)
{
    // 严格限定合法入口文件名，防止宿主被重命名为通用 DLL 启动器。
    return EqualsAsciiIgnoreCase(exeName, L"SteamSentinel.ArchiveWorker.exe") ||
           EqualsAsciiIgnoreCase(exeName, L"SteamSentinel.ArchiveWorker.Standard.exe") ||
           EqualsAsciiIgnoreCase(exeName, L"SteamSentinel.ArchiveWorker.Compat.exe");
}

struct FxVersion
{
    uint64_t major = 0;
    uint64_t minor = 0;
    uint64_t patch = 0;
    bool stable = false;
    std::wstring folder;
};

bool ParseUIntPart(const std::wstring& s, size_t start, size_t end, uint64_t& outVal)
{
    if (start >= end) return false;
    uint64_t val = 0;
    for (size_t i = start; i < end; ++i)
    {
        if (s[i] < L'0' || s[i] > L'9') return false;
        uint64_t digit = static_cast<uint64_t>(s[i] - L'0');
        if (val > (UINT64_MAX - digit) / 10u) return false;
        val = val * 10u + digit;
    }
    outVal = val;
    return true;
}

bool TryParseFxVersion(const std::wstring& name, FxVersion& outVer)
{
    size_t dash = name.find(L'-');
    std::wstring core = (dash == std::wstring::npos) ? name : name.substr(0, dash);
    size_t dot1 = core.find(L'.');
    if (dot1 == std::wstring::npos) return false;
    size_t dot2 = core.find(L'.', dot1 + 1);
    if (dot2 == std::wstring::npos) return false;
    if (core.find(L'.', dot2 + 1) != std::wstring::npos) return false;
    if (!ParseUIntPart(core, 0, dot1, outVer.major) ||
        !ParseUIntPart(core, dot1 + 1, dot2, outVer.minor) ||
        !ParseUIntPart(core, dot2 + 1, core.size(), outVer.patch))
    {
        return false;
    }
    outVer.stable = (dash == std::wstring::npos);
    outVer.folder = name;
    return true;
}

bool IsHigherVersion(const FxVersion& a, const FxVersion& b)
{
    if (a.major != b.major) return a.major > b.major;
    if (a.minor != b.minor) return a.minor > b.minor;
    if (a.patch != b.patch) return a.patch > b.patch;
    if (a.stable != b.stable) return a.stable;
    return a.folder > b.folder;
}

#ifndef STEAMSENTINEL_SELF_CONTAINED_ONLY
bool GetEnvVar(const wchar_t* name, std::wstring& outVal)
{
    DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0 || needed > kMaxPathChars) return false;
    std::wstring buf(needed, L'\0');
    DWORD actual = GetEnvironmentVariableW(name, &buf[0], needed);
    if (actual == 0 || actual >= needed) return false;
    buf.resize(actual);
    outVal = std::move(buf);
    return !outVal.empty();
}

bool ResolveDevelopmentHostFxr(std::wstring& outHostFxrPath, std::wstring& outDotnetRoot)
{
    // 开发构建仅读取受信任系统 ProgramFiles\dotnet，不采信环境覆写。
    std::wstring programFiles;
    if (!GetEnvVar(L"ProgramFiles", programFiles)) return false;
    while (!programFiles.empty() && (programFiles.back() == L'\\' || programFiles.back() == L'/'))
    {
        programFiles.pop_back();
    }
    std::wstring dotnetRoot = programFiles + L"\\dotnet";
    if (!VerifyRequiredDirectory(dotnetRoot)) return false;
    std::wstring fxrBase = dotnetRoot + L"\\host\\fxr";
    if (!VerifyRequiredDirectory(fxrBase)) return false;

    std::wstring pattern = fxrBase + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE find = FindFirstFileW(pattern.c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) return false;

    std::vector<FxVersion> candidates;
    do
    {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 && IsRedirectingReparseTag(fd.dwReserved0))
        {
            continue;
        }
        FxVersion ver;
        if (TryParseFxVersion(name, ver))
        {
            candidates.push_back(std::move(ver));
        }
    }
    while (FindNextFileW(find, &fd));
    FindClose(find);

    std::sort(candidates.begin(), candidates.end(), IsHigherVersion);
    for (const FxVersion& ver : candidates)
    {
        std::wstring verDir = fxrBase + L"\\" + ver.folder;
        std::wstring candidateFxr = verDir + L"\\hostfxr.dll";
        if (VerifyRequiredDirectory(verDir) && VerifyRequiredFile(candidateFxr))
        {
            outHostFxrPath = std::move(candidateFxr);
            outDotnetRoot = std::move(dotnetRoot);
            return true;
        }
    }
    return false;
}
#endif

struct HostfxrInitializeParameters
{
    size_t size;
    const wchar_t* host_path;
    const wchar_t* dotnet_root;
};

using HostfxrHandle = void*;
using FnHostfxrInitializeForCommandLine = int(__cdecl*)(
    int argc,
    const wchar_t** argv,
    const HostfxrInitializeParameters* parameters,
    HostfxrHandle* host_context_handle);
using FnHostfxrRunApp = int(__cdecl*)(HostfxrHandle host_context_handle);
using FnHostfxrClose = int(__cdecl*)(HostfxrHandle host_context_handle);
}

int wmain(int argc, wchar_t* argv[])
{
    std::wstring exePath;
    if (!GetModulePath(exePath))
    {
        WriteStdErr("SteamSentinel.ArchiveWorker host path query failed.\n");
        return 2;
    }
    if (!VerifyRequiredFile(exePath))
    {
        WriteStdErr("SteamSentinel.ArchiveWorker executable path verification failed.\n");
        return 2;
    }

    size_t lastSlash = exePath.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos || lastSlash + 1 >= exePath.size())
    {
        WriteStdErr("SteamSentinel.ArchiveWorker executable path is invalid.\n");
        return 2;
    }
    std::wstring exeDir = exePath.substr(0, lastSlash);
    std::wstring exeName = exePath.substr(lastSlash + 1);
    if (!IsAllowedWorkerExeName(exeName))
    {
        WriteStdErr("SteamSentinel.ArchiveWorker host name is not permitted.\n");
        return 2;
    }
    if (!VerifyRequiredDirectory(exeDir))
    {
        WriteStdErr("SteamSentinel.ArchiveWorker directory verification failed.\n");
        return 2;
    }

    std::wstring dllPath = exeDir + L"\\" + kWorkerAssemblyName;
    if (!VerifyRequiredFile(dllPath))
    {
        WriteStdErr("SteamSentinel.ArchiveWorker managed assembly is missing or redirected.\n");
        return 2;
    }

    std::wstring localHostFxr = exeDir + L"\\hostfxr.dll";
    bool localFxrExists = false;
    if (!CheckLocalObject(localHostFxr, false, localFxrExists))
    {
        WriteStdErr("SteamSentinel.ArchiveWorker local hostfxr verification failed.\n");
        return static_cast<int>(0x80008081u);
    }

    std::wstring hostfxrPath;
    std::wstring dotnetRoot;
    if (localFxrExists)
    {
        hostfxrPath = std::move(localHostFxr);
        dotnetRoot = exeDir;
    }
    else
    {
#ifdef STEAMSENTINEL_SELF_CONTAINED_ONLY
        WriteStdErr("SteamSentinel.ArchiveWorker self-contained hostfxr.dll is missing.\n");
        return static_cast<int>(0x80008081u);
#else
        if (!ResolveDevelopmentHostFxr(hostfxrPath, dotnetRoot))
        {
            WriteStdErr("SteamSentinel.ArchiveWorker could not locate a verified .NET hostfxr.dll.\n");
            return static_cast<int>(0x80008081u);
        }
#endif
    }

    HMODULE fxrModule = LoadLibraryExW(
        hostfxrPath.c_str(),
        nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (fxrModule == nullptr)
    {
        WriteStdErr("SteamSentinel.ArchiveWorker failed to load hostfxr.dll.\n");
        return static_cast<int>(0x80008082u);
    }

    auto initFn = reinterpret_cast<FnHostfxrInitializeForCommandLine>(
        GetProcAddress(fxrModule, "hostfxr_initialize_for_dotnet_command_line"));
    auto runAppFn = reinterpret_cast<FnHostfxrRunApp>(
        GetProcAddress(fxrModule, "hostfxr_run_app"));
    auto closeFn = reinterpret_cast<FnHostfxrClose>(
        GetProcAddress(fxrModule, "hostfxr_close"));
    if (initFn == nullptr || runAppFn == nullptr || closeFn == nullptr)
    {
        FreeLibrary(fxrModule);
        WriteStdErr("SteamSentinel.ArchiveWorker hostfxr exports are incomplete.\n");
        return static_cast<int>(0x80008082u);
    }

    std::vector<const wchar_t*> childArgs;
    childArgs.reserve(static_cast<size_t>(argc > 0 ? argc : 1));
    childArgs.push_back(dllPath.c_str());
    for (int i = 1; i < argc; ++i)
    {
        childArgs.push_back(argv[i]);
    }

    HostfxrInitializeParameters params{};
    params.size = sizeof(HostfxrInitializeParameters);
    params.host_path = exePath.c_str();
    params.dotnet_root = dotnetRoot.c_str();

    HostfxrHandle hostContext = nullptr;
    int initRc = initFn(static_cast<int>(childArgs.size()), childArgs.data(), &params, &hostContext);
    if (initRc < 0 || hostContext == nullptr)
    {
        if (hostContext != nullptr) closeFn(hostContext);
        FreeLibrary(fxrModule);
        return initRc != 0 ? initRc : 1;
    }

    int exitCode = runAppFn(hostContext);
    closeFn(hostContext);
    return exitCode;
}
