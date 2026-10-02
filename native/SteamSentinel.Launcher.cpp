// The bootstrap never loads CoreCLR. Only fixed, manifest-verified hosts can run.
#include <windows.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <shlobj.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr DWORD ProbeTimeoutMs = 20000;
constexpr int BrokerPreflightNotStarted = 0x53530001;
constexpr size_t OutputLimit = 262144;
constexpr char CetError[] = "Your Windows doesn't fully support CET. Please install all available Windows updates.";
constexpr char ReadyPrefix[] = "STEAMSENTINEL_STARTUP_READY/1|";

struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (valid()) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(other.value) { other.value = INVALID_HANDLE_VALUE; }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { if (valid()) CloseHandle(value); value = other.value; other.value = INVALID_HANDLE_VALUE; }
        return *this;
    }
    bool valid() const { return value != INVALID_HANDLE_VALUE && value != nullptr; }
};

std::string Utf8(const std::wstring& value) {
    if (value.empty()) return {};
    int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) throw std::runtime_error("Invalid Unicode path.");
    std::string result(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count, nullptr, nullptr);
    return result;
}

std::wstring Wide(const std::string& value) {
    if (value.empty()) return {};
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) throw std::runtime_error("Manifest contains invalid UTF-8.");
    std::wstring result(static_cast<size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count);
    return result;
}

std::wstring Join(const std::wstring& root, const std::wstring& child) { return root + L"\\" + child; }

std::wstring FileSystemPath(const std::wstring& path) {
    // File APIs need extended paths independently of the machine's LongPathsEnabled
    // policy. Keep normal paths for diagnostics, argument forwarding and validation.
    if (path.rfind(L"\\\\?\\", 0) == 0) return path;
    if (path.size() >= 3 && path[1] == L':' && path[2] == L'\\') return L"\\\\?\\" + path;
    return path;
}

std::string ErrorCode(const char* message) { return std::string(message) + " (Win32=" + std::to_string(GetLastError()) + ")"; }

bool Equals(const std::wstring& left, const std::wstring& right) {
    return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_EQUAL;
}

std::wstring Quote(const std::wstring& value) {
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') { ++slashes; continue; }
        result.append(slashes * (c == L'\"' ? 2 : 1), L'\\');
        if (c == L'\"') result += L'\\';
        result += c;
        slashes = 0;
    }
    result.append(slashes * 2, L'\\');
    return result + L'\"';
}

std::string RandomNonce() {
    std::array<UCHAR, 16> bytes{};
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("Cannot generate startup nonce.");
    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (UCHAR byte : bytes) result << std::setw(2) << static_cast<unsigned>(byte);
    return result.str();
}

void RejectReparsePath(const std::wstring& path) {
    // Inspect every existing path component, including parents of the package.
    for (size_t index = 3; index <= path.size(); ++index) {
        if (index != path.size() && path[index] != L'\\' && path[index] != L'/') continue;
        std::wstring part = path.substr(0, index);
        DWORD attributes = GetFileAttributesW(FileSystemPath(part).c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("Missing or redirected package path: " + Utf8(part));
    }
}

Handle OpenRead(const std::wstring& path) {
    RejectReparsePath(path);
    Handle file(CreateFileW(FileSystemPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file.valid()) throw std::runtime_error(ErrorCode("Cannot read package file"));
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file.value, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        throw std::runtime_error("Package entry is not a regular file.");
    return file;
}

std::string ReadBounded(HANDLE file, size_t limit) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || static_cast<unsigned long long>(size.QuadPart) > limit)
        throw std::runtime_error("Manifest exceeds the size limit.");
    std::string result(static_cast<size_t>(size.QuadPart), '\0');
    DWORD count = 0;
    if (!ReadFile(file, result.data(), static_cast<DWORD>(result.size()), &count, nullptr) || count != result.size())
        throw std::runtime_error("Cannot read the complete manifest.");
    return result;
}

std::string Hash(HANDLE file) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("SHA-256 provider unavailable.");
    if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("SHA-256 initialization failed.");
    }
    bool success = true;
    std::array<UCHAR, 65536> buffer{};
    DWORD count = 0;
    for (;;) {
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr)) { success = false; break; }
        if (count == 0) break;
        if (BCryptHashData(hash, buffer.data(), count, 0) < 0) { success = false; break; }
    }
    std::array<UCHAR, 32> digest{};
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) success = false;
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!success) throw std::runtime_error("Package SHA-256 calculation failed.");
    std::ostringstream text;
    text << std::uppercase << std::hex << std::setfill('0');
    for (UCHAR byte : digest) text << std::setw(2) << static_cast<unsigned>(byte);
    return text.str();
}

bool SafeRelative(const std::wstring& path) {
    if (path.empty() || path.front() == L'\\' || path.front() == L'/' || path.find(L':') != std::wstring::npos || path.find(L'\0') != std::wstring::npos)
        return false;
    size_t offset = 0;
    while (offset < path.size()) {
        size_t end = path.find_first_of(L"\\/", offset);
        if (end == std::wstring::npos) end = path.size();
        std::wstring component = path.substr(offset, end - offset);
        if (component.empty() || component == L"." || component == L".." || component.back() == L'.' || component.back() == L' ')
            return false;
        offset = end + 1;
    }
    return path.back() != L'\\' && path.back() != L'/';
}

bool Listed(const std::vector<std::wstring>& paths, const std::wstring& path) {
    return std::any_of(paths.begin(), paths.end(), [&](const auto& entry) { return Equals(entry, path); });
}

void RejectUnlistedCode(const std::wstring& root, const std::wstring& relative, const std::vector<std::wstring>& listed, unsigned depth = 0) {
    if (depth > 32) throw std::runtime_error("Package directory nesting exceeds the limit.");
    WIN32_FIND_DATAW data{};
    HANDLE search = FindFirstFileW(FileSystemPath(Join(relative.empty() ? root : Join(root, relative), L"*")).c_str(), &data);
    if (search == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot inspect package directory.");
    try {
        do {
            if (Equals(data.cFileName, L".") || Equals(data.cFileName, L"..")) continue;
            std::wstring child = relative.empty() ? data.cFileName : Join(relative, data.cFileName);
            if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) throw std::runtime_error("Redirected package entry.");
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { RejectUnlistedCode(root, child, listed, depth + 1); continue; }
            size_t dot = child.find_last_of(L'.');
            std::wstring extension = dot == std::wstring::npos ? L"" : child.substr(dot);
            const wchar_t* loadable[] = { L".exe", L".dll", L".com", L".scr", L".cpl", L".ocx", L".sys", L".winmd", L".json", L".config" };
            bool code = std::any_of(std::begin(loadable), std::end(loadable), [&](auto item) { return Equals(extension, item); });
            std::wstring lower = child;
            std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
            code = code || lower.find(L".deps.") != std::wstring::npos || lower.find(L".runtimeconfig.") != std::wstring::npos;
            // Match InstallationSecurity's sole Inno-created executable exception.
            if (code && !Listed(listed, child) && !Equals(child, L"unins000.exe"))
                throw std::runtime_error("Unlisted loadable package file: " + Utf8(child));
        } while (FindNextFileW(search, &data));
        if (GetLastError() != ERROR_NO_MORE_FILES) throw std::runtime_error("Package enumeration failed.");
    } catch (...) { FindClose(search); throw; }
    FindClose(search);
}

std::vector<Handle> VerifyPackage(const std::wstring& root, std::ostringstream& report) {
    std::vector<Handle> locks;
    locks.push_back(OpenRead(Join(root, L"SHA256SUMS.txt")));
    std::string manifest = ReadBounded(locks.back().value, 2 * 1024 * 1024);
    if (manifest.compare(0, 3, "\xEF\xBB\xBF") == 0) manifest.erase(0, 3);
    std::istringstream lines(manifest);
    std::string line;
    std::vector<std::wstring> paths;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (paths.size() >= 10000 || line.size() < 67 || line[64] != ' ' || (line[65] != '*' && line[65] != ' '))
            throw std::runtime_error("Invalid package manifest format.");
        std::string expected = line.substr(0, 64);
        for (char& c : expected) {
            if (c >= 'a' && c <= 'f') c = static_cast<char>(c - 'a' + 'A');
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) throw std::runtime_error("Invalid SHA-256 digest.");
        }
        std::wstring relative = Wide(line.substr(66));
        std::replace(relative.begin(), relative.end(), L'/', L'\\');
        if (!SafeRelative(relative) || Listed(paths, relative) || Equals(relative, L"SHA256SUMS.txt"))
            throw std::runtime_error("Unsafe or duplicate manifest path.");
        Handle file = OpenRead(Join(root, relative));
        if (Hash(file.value) != expected) throw std::runtime_error("Package integrity mismatch: " + Utf8(relative));
        paths.push_back(relative);
        locks.push_back(std::move(file));
    }
    const wchar_t* required[] = {
        L"SteamSentinel.exe", L"SteamSentinel.Broker.exe",
        L"SteamSentinel.Standard.exe", L"SteamSentinel.Compat.exe",
        L"SteamSentinel.Broker.Standard.exe", L"SteamSentinel.Broker.Compat.exe",
        L"SteamSentinel.ArchiveWorker.Standard.exe", L"SteamSentinel.ArchiveWorker.Compat.exe",
        L"SteamSentinel.dll", L"SteamSentinel.Core.dll", L"SteamSentinel.Broker.dll", L"SteamSentinel.ArchiveWorker.dll",
        L"SteamSentinel.deps.json", L"SteamSentinel.runtimeconfig.json", L"SteamSentinel.Broker.deps.json",
        L"SteamSentinel.Broker.runtimeconfig.json", L"SteamSentinel.ArchiveWorker.deps.json", L"SteamSentinel.ArchiveWorker.runtimeconfig.json",
        L"coreclr.dll", L"hostfxr.dll", L"hostpolicy.dll", L"System.Private.CoreLib.dll"
    };
    for (auto path : required) if (!Listed(paths, path)) throw std::runtime_error("Required package file is not in the manifest: " + Utf8(path));
    RejectUnlistedCode(root, L"", paths);
    report << "ManifestVerified=" << paths.size() << "\n";
    return locks;
}

struct ProbeResult {
    DWORD exitCode = 0;
    DWORD startError = 0;
    bool timedOut = false;
    bool overflow = false;
    bool ready = false;
    std::string output;
    std::string error;
    bool cetFailure() const {
        return !ready && !timedOut && !overflow && startError == 0 && exitCode == 0x80131506UL &&
            output.find(ReadyPrefix) == std::string::npos && error.find(CetError) != std::string::npos;
    }
};

void Drain(HANDLE pipe, std::string& output, bool& overflow) {
    DWORD available = 0;
    while (PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) && available > 0) {
        std::array<char, 4096> buffer{};
        DWORD read = 0;
        if (!ReadFile(pipe, buffer.data(), std::min(available, static_cast<DWORD>(buffer.size())), &read, nullptr) || read == 0) break;
        size_t capacity = OutputLimit - output.size();
        output.append(buffer.data(), std::min(capacity, static_cast<size_t>(read)));
        if (read > capacity) { overflow = true; break; }
    }
}

std::wstring HostName(const std::string& role, const std::string& mode) {
    std::wstring base = role == "app" ? L"SteamSentinel" : role == "broker" ? L"SteamSentinel.Broker" : L"SteamSentinel.ArchiveWorker";
    return base + (mode == "compat" ? L".Compat.exe" : L".Standard.exe");
}

std::vector<wchar_t> ProbeEnvironment() {
    LPWCH environment = GetEnvironmentStringsW();
    if (environment == nullptr) throw std::runtime_error("Cannot prepare the probe environment.");
    std::vector<std::wstring> entries;
    for (const wchar_t* value = environment; *value != L'\0'; value += wcslen(value) + 1) {
        std::wstring entry(value);
        size_t equals = entry.find(L'=');
        std::wstring name = entry.substr(0, equals);
        if (Equals(name, L"DOTNET_HOST_TRACE") || Equals(name, L"DOTNET_HOST_TRACEFILE") || Equals(name, L"DOTNET_HOST_TRACE_VERBOSITY") ||
            Equals(name, L"COREHOST_TRACE") || Equals(name, L"COREHOST_TRACEFILE") || Equals(name, L"COREHOST_TRACE_VERBOSITY")) continue;
        entries.push_back(std::move(entry));
    }
    FreeEnvironmentStringsW(environment);
    // Trace to the bounded private stderr pipe only. Neither the parent process
    // nor the subsequently launched business process has its environment changed.
    entries.insert(entries.end(), { L"DOTNET_HOST_TRACE=1", L"DOTNET_HOST_TRACE_VERBOSITY=3", L"COREHOST_TRACE=1", L"COREHOST_TRACE_VERBOSITY=3" });
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_LESS_THAN;
    });
    std::vector<wchar_t> block;
    for (const auto& entry : entries) { block.insert(block.end(), entry.begin(), entry.end()); block.push_back(L'\0'); }
    block.push_back(L'\0');
    return block;
}

ProbeResult Probe(const std::wstring& root, const std::string& role, const std::string& mode, std::ostringstream& report) {
    ProbeResult result;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE outRead = nullptr, outWrite = nullptr, errRead = nullptr, errWrite = nullptr;
    if (!CreatePipe(&outRead, &outWrite, &attributes, 0)) throw std::runtime_error(ErrorCode("Cannot create probe pipe"));
    Handle stdoutRead(outRead), stdoutWrite(outWrite);
    if (!CreatePipe(&errRead, &errWrite, &attributes, 0)) throw std::runtime_error(ErrorCode("Cannot create probe pipe"));
    Handle stderrRead(errRead), stderrWrite(errWrite);
    if (!SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0) || !SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0))
        throw std::runtime_error("Cannot restrict probe handles.");
    Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, OPEN_EXISTING, 0, nullptr));
    if (!input.valid()) throw std::runtime_error("Cannot open probe input.");
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<unsigned char> storage(bytes);
    auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(list, 1, 0, &bytes)) throw std::runtime_error("Cannot initialize probe handle list.");
    HANDLE handles[] = { input.value, outWrite, errWrite };
    if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(list);
        throw std::runtime_error("Cannot set probe handle list.");
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.value;
    startup.StartupInfo.hStdOutput = outWrite;
    startup.StartupInfo.hStdError = errWrite;
    startup.lpAttributeList = list;
    Handle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job.valid() || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        DeleteProcThreadAttributeList(list);
        throw std::runtime_error("Cannot contain startup probe.");
    }
    std::string nonce = RandomNonce();
    std::wstring executable = Join(root, HostName(role, mode));
    std::wstring command = Quote(executable) + L" --startup-probe " + Wide(nonce);
    auto environment = ProbeEnvironment();
    PROCESS_INFORMATION process{};
    BOOL started = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, environment.data(), root.c_str(), &startup.StartupInfo, &process);
    result.startError = started ? 0 : GetLastError();
    DeleteProcThreadAttributeList(list);
    stdoutWrite = Handle(); stderrWrite = Handle();
    if (started) {
        Handle child(process.hProcess), thread(process.hThread);
        if (!AssignProcessToJobObject(job.value, child.value)) {
            TerminateProcess(child.value, 125);
            throw std::runtime_error("Cannot contain startup probe process.");
        }
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy{};
        if (GetProcessMitigationPolicy(child.value, ProcessUserShadowStackPolicy, &policy, sizeof(policy)))
            report << "ProbeShadowStack=" << role << "/" << mode << ":" << policy.EnableUserShadowStack << "\n";
        else report << "ProbeShadowStack=" << role << "/" << mode << ":unavailable(" << GetLastError() << ")\n";
        if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) throw std::runtime_error("Cannot resume startup probe.");
        ULONGLONG began = GetTickCount64();
        for (;;) {
            Drain(stdoutRead.value, result.output, result.overflow);
            Drain(stderrRead.value, result.error, result.overflow);
            DWORD wait = WaitForSingleObject(child.value, 20);
            if (wait == WAIT_OBJECT_0) break;
            if (wait == WAIT_FAILED) throw std::runtime_error("Cannot wait for startup probe.");
            if (result.overflow || GetTickCount64() - began >= ProbeTimeoutMs) {
                result.timedOut = !result.overflow;
                TerminateJobObject(job.value, 124);
                WaitForSingleObject(child.value, 2000);
                break;
            }
        }
        Drain(stdoutRead.value, result.output, result.overflow);
        Drain(stderrRead.value, result.error, result.overflow);
        if (!GetExitCodeProcess(child.value, &result.exitCode)) throw std::runtime_error("Cannot read startup probe exit code.");
        std::string expected = std::string(ReadyPrefix) + role + "|" + mode + "|" + nonce + "\n";
        std::string output = result.output;
        output.erase(std::remove(output.begin(), output.end(), '\r'), output.end());
        result.ready = !result.timedOut && !result.overflow && result.exitCode == 0 && output == expected;
    }
    report << "Probe=" << role << "/" << mode << " ready=" << result.ready << " exit=0x" << std::hex << result.exitCode << std::dec
        << " startError=" << result.startError << " timeout=" << result.timedOut << " overflow=" << result.overflow << "\n";
    if (!result.ready && !result.error.empty()) report << "ProbeStderrAndHostTrace (bounded):\n" << result.error << "\n";
    if (!result.ready && !result.output.empty()) report << "ProbeStdout:\n" << result.output << "\n";
    return result;
}

std::string SelectMode(const std::wstring& root, bool broker, const std::string& preferred, std::ostringstream& report) {
    const std::vector<std::string> roles = broker ? std::vector<std::string>{"broker"} : std::vector<std::string>{"app", "worker"};
    std::string mode = preferred;
    for (;;) {
        bool retry = false;
        for (const auto& role : roles) {
            ProbeResult probe = Probe(root, role, mode, report);
            if (probe.ready) continue;
            if (mode == "standard" && probe.cetFailure()) {
                report << "SelectionReason=confirmed-cet-failure:" << role << "\n";
                mode = "compat";
                retry = true;
                break;
            }
            throw std::runtime_error("Startup preflight failed for " + role + "/" + mode + ". No business operation was started.");
        }
        if (!retry) { report << "SelectedMode=" << mode << "\n"; return mode; }
    }
}

void WriteAll(HANDLE file, const std::string& text) {
    DWORD count = 0;
    if (!WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &count, nullptr) || count != text.size())
        throw std::runtime_error("Cannot write startup report.");
}

std::wstring WriteReportAt(std::wstring folder, const std::vector<std::wstring>& components, const std::string& text) {
    try {
        while (!folder.empty() && (folder.back() == L'\\' || folder.back() == L'/')) folder.pop_back();
        RejectReparsePath(folder);
        for (const auto& component : components) {
            folder = Join(folder, component);
            if (!CreateDirectoryW(FileSystemPath(folder).c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return {};
            RejectReparsePath(folder);
        }
        SYSTEMTIME time{};
        GetSystemTime(&time);
        wchar_t date[40]{};
        swprintf_s(date, L"%04u%02u%02uT%02u%02u%02u", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
        std::wstring path = Join(folder, L"startup-" + std::wstring(date) + L"-" + Wide(RandomNonce()) + L".txt");
        Handle file(CreateFileW(FileSystemPath(path).c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!file.valid()) return {};
        WriteAll(file.value, text);
        return path;
    } catch (...) { return {}; }
}

std::wstring WriteReport(const std::string& text) {
    PWSTR known = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &known))) {
        std::wstring folder(known);
        CoTaskMemFree(known);
        auto path = WriteReportAt(folder, { L"SteamSentinel", L"Logs" }, text);
        if (!path.empty()) return path;
    }
    std::vector<wchar_t> temporary(32768);
    DWORD count = GetTempPathW(static_cast<DWORD>(temporary.size()), temporary.data());
    if (count == 0 || count >= temporary.size()) return {};
    return WriteReportAt(std::wstring(temporary.data(), count), { L"SteamSentinel-Startup-Reports" }, text);
}

void Print(const std::string& text) {
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output != nullptr && output != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(output, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    }
}

void ShowCompatibilityNotice(const std::wstring& reportPath) {
    if (reportPath.empty()) return;
    std::wstring marker = Join(reportPath.substr(0, reportPath.find_last_of(L'\\')), L"compatibility-notice-v1.txt");
    Handle file(CreateFileW(FileSystemPath(marker).c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) return; // An existing notice marker is not a startup authorization.
    bool chinese = PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE;
    MessageBoxW(nullptr, chinese ?
        L"检测到当前环境无法以标准 CET 模式启动，已自动选择兼容模式。\n\n兼容模式减少了本程序的一项硬件堆栈保护，扫描和处置功能保持一致。建议安装可用的 Windows 更新。\n\n诊断信息已保存在本地日志中，不会自动上传。" :
        L"This environment could not start with standard CET protection. Compatibility mode was selected automatically.\n\nThis reduces one hardware stack protection for this application. Scanning and remediation features remain available. Installing available Windows updates is recommended.\n\nDiagnostics stay in local logs and are not uploaded automatically.",
        L"SteamSentinel", MB_OK | MB_ICONINFORMATION);
}

int Launch(const std::wstring& root, bool broker, const std::string& mode, const std::vector<std::wstring>& arguments, bool& businessStarted) {
    std::wstring executable = Join(root, HostName(broker ? "broker" : "app", mode));
    std::wstring command = Quote(executable);
    for (const auto& argument : arguments) command += L" " + Quote(argument);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, 0, nullptr, root.c_str(), &startup, &process))
        throw std::runtime_error(ErrorCode("Cannot launch selected application host"));
    businessStarted = true;
    Handle child(process.hProcess), thread(process.hThread);
    if (!broker) return 0;
    // A broker is dispatched once. Never replay a plan after any business exit.
    if (WaitForSingleObject(child.value, INFINITE) != WAIT_OBJECT_0) return 126;
    DWORD code = 0;
    if (!GetExitCodeProcess(child.value, &code)) return 126;
    return code == static_cast<DWORD>(BrokerPreflightNotStarted) ? 126 : static_cast<int>(code);
}
} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    std::ostringstream report;
    SYSTEMTIME began{}; GetSystemTime(&began);
    report << "SteamSentinel.Startup/1\nUTC=" << began.wYear << "-" << began.wMonth << "-" << began.wDay << "T" << began.wHour << ":" << began.wMinute << ":" << began.wSecond
        << "\nProcessId=" << GetCurrentProcessId() << "\nArchitecture=x64\nHostTrace=probe-only, bounded, local\n";
    bool checkOnly = false;
    bool brokerRole = false;
    bool businessStarted = false;
    try {
        std::vector<wchar_t> module(32768);
        DWORD length = GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size()));
        if (length == 0 || length >= module.size()) throw std::runtime_error("Cannot resolve the startup executable.");
        std::wstring path(module.data(), length);
        size_t separator = path.find_last_of(L"\\/");
        if (separator == std::wstring::npos) throw std::runtime_error("Invalid startup executable path.");
        std::wstring root = path.substr(0, separator), filename = path.substr(separator + 1);
        bool broker = Equals(filename, L"SteamSentinel.Broker.exe");
        brokerRole = broker;
        if (!broker && !Equals(filename, L"SteamSentinel.exe")) throw std::runtime_error("Unrecognized bootstrap role.");
        int count = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &count);
        if (argv == nullptr) throw std::runtime_error("Cannot parse startup arguments.");
        std::vector<std::wstring> arguments;
        for (int i = 1; i < count; ++i) arguments.emplace_back(argv[i]);
        LocalFree(argv);
        std::string preferred = "standard";
        if (broker && arguments.size() >= 2 && arguments[0] == L"--startup-mode") {
            if (arguments[1] != L"standard" && arguments[1] != L"compat") throw std::runtime_error("Invalid requested startup mode.");
            preferred = Utf8(arguments[1]);
            arguments.erase(arguments.begin(), arguments.begin() + 2);
        }
        checkOnly = arguments.size() == 1 && arguments[0] == L"--startup-check";
        if (!checkOnly) {
            for (const auto& argument : arguments)
                if (argument.rfind(L"--startup-", 0) == 0) throw std::runtime_error("Reserved startup argument.");
        }
        report << "Role=" << (broker ? "broker" : "app") << "\nPreferredMode=" << preferred << "\n";
        using VersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
        auto versionFunction = reinterpret_cast<VersionFunction>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
        OSVERSIONINFOW version{}; version.dwOSVersionInfoSize = sizeof(version);
        if (versionFunction != nullptr && versionFunction(&version) == 0)
            report << "Windows=" << version.dwMajorVersion << "." << version.dwMinorVersion << "." << version.dwBuildNumber << "\n";
        DWORD revision = 0, revisionBytes = sizeof(revision);
        if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR", RRF_RT_REG_DWORD,
            nullptr, &revision, &revisionBytes) == ERROR_SUCCESS) report << "WindowsUBR=" << revision << "\n";
        auto packageLocks = VerifyPackage(root, report);
        DWORD versionAttributes = GetFileAttributesW(FileSystemPath(Join(root, L"VERSION.txt")).c_str());
        if (versionAttributes != INVALID_FILE_ATTRIBUTES) {
            Handle versionFile = OpenRead(Join(root, L"VERSION.txt"));
            report << "PackageVersion:\n" << ReadBounded(versionFile.value, 32768) << "\n";
        }
        std::string mode = SelectMode(root, broker, preferred, report);
        std::wstring reportPath = WriteReport(report.str());
        Print("STEAMSENTINEL_STARTUP_SELECTED/1|" + mode + "\nReport=" + Utf8(reportPath) + "\n");
        if (checkOnly) return 0;
        if (!broker && mode == "compat") ShowCompatibilityNotice(reportPath);
        return Launch(root, broker, mode, arguments, businessStarted);
    } catch (const std::exception& error) {
        report << "Failure=" << error.what() << "\n";
        std::wstring reportPath = WriteReport(report.str());
        Print("STEAMSENTINEL_STARTUP_FAILED/1\nReport=" + Utf8(reportPath) + "\n" + error.what() + "\n");
        if (!checkOnly) {
            bool chinese = PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE;
            std::wstring message = chinese ? L"SteamSentinel 启动失败，未自动重试业务操作。\n\n" : L"SteamSentinel could not start. Business operations were not retried.\n\n";
            message += Wide(error.what());
            if (!reportPath.empty()) message += (chinese ? L"\n\n请将诊断报告发给维护者：\n" : L"\n\nPlease send this diagnostic report to support:\n") + reportPath;
            MessageBoxW(nullptr, message.c_str(), L"SteamSentinel", MB_OK | MB_ICONERROR);
        }
        return brokerRole && !businessStarted ? BrokerPreflightNotStarted : 125;
    }
}
