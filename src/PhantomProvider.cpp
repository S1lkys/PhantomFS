#include "PhantomProvider.h"
#include <cstdarg>
#include <algorithm>
#include <objbase.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static PhantomProvider* GetInstance(const PRJ_CALLBACK_DATA* cbd) {
    return reinterpret_cast<PhantomProvider*>(cbd->InstanceContext);
}

void PhantomProvider::Log(const wchar_t* fmt, ...) {
    if (!m_Config.Verbose) return;
    va_list args;
    va_start(args, fmt);
    vwprintf(fmt, args);
    va_end(args);
}

const char* PhantomProvider::PolicyToStr(ProcessPolicy p) {
    switch (p) {
    case ProcessPolicy::SERVE_PAYLOAD: return "PAYLOAD";
    case ProcessPolicy::SERVE_DECOY:   return "DECOY";
    case ProcessPolicy::DENY_READ:     return "DENY";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

PhantomProvider::PhantomProvider(PhantomConfig config)
    : m_Config(std::move(config)), m_Shutdown(false) {
}

PhantomProvider::~PhantomProvider() {
    Stop();
}

HRESULT PhantomProvider::Init(PCWSTR rootDir) {
    if (!CreateDirectoryW(rootDir, nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS)
            return HRESULT_FROM_WIN32(GetLastError());
    }

    std::wstring guidFile(rootDir);
    guidFile += L"\\.phantomfs.guid";

    GUID instanceId = {};
    ZeroMemory(&instanceId, sizeof(GUID));

    HANDLE hFile = CreateFileW(guidFile.c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesRead = 0;
        if (GetFileSize(hFile, nullptr) == sizeof(GUID)) {
            ReadFile(hFile, &instanceId, sizeof(GUID), &bytesRead, nullptr);
        }
        CloseHandle(hFile);
    }

    GUID zeroGuid = {};
    ZeroMemory(&zeroGuid, sizeof(GUID));
    if (memcmp(&instanceId, &zeroGuid, sizeof(GUID)) == 0) {
        CoCreateGuid(&instanceId);
        hFile = CreateFileW(guidFile.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(hFile, &instanceId, sizeof(GUID), &written, nullptr);
            CloseHandle(hFile);
        }
    }

    HRESULT hr = PrjMarkDirectoryAsPlaceholder(rootDir, nullptr, nullptr, &instanceId);
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_ALREADY_INITIALIZED))
        return hr;

    m_InstanceId = instanceId;
    m_RootDir = rootDir;
    return S_OK;
}

HRESULT PhantomProvider::Start() {
    m_Shutdown = false;
    m_WorkerThread = std::thread(&PhantomProvider::RehydrationWorker, this);

    PRJ_CALLBACKS cb{};
    cb.StartDirectoryEnumerationCallback = CbStartEnum;
    cb.EndDirectoryEnumerationCallback = CbEndEnum;
    cb.GetDirectoryEnumerationCallback = CbGetEnum;
    cb.GetPlaceholderInfoCallback = CbGetPlaceholder;
    cb.GetFileDataCallback = CbGetFileData;
    cb.NotificationCallback = CbNotification;

    PRJ_NOTIFICATION_MAPPING notifMap{};
    notifMap.NotificationRoot = L"";
    notifMap.NotificationBitMask =
        PRJ_NOTIFY_FILE_OPENED |
        PRJ_NOTIFY_PRE_DELETE |
        PRJ_NOTIFY_PRE_RENAME |
        PRJ_NOTIFY_PRE_SET_HARDLINK |
        PRJ_NOTIFY_FILE_HANDLE_CLOSED_NO_MODIFICATION |
        PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_MODIFIED |
        PRJ_NOTIFY_FILE_HANDLE_CLOSED_FILE_DELETED |
        PRJ_NOTIFY_FILE_PRE_CONVERT_TO_FULL;

    PRJ_STARTVIRTUALIZING_OPTIONS opts{};
    opts.NotificationMappings = &notifMap;
    opts.NotificationMappingsCount = 1;

    HRESULT hr = PrjStartVirtualizing(
        m_RootDir.c_str(), &cb, this, &opts, &m_VirtCtx);

    if (SUCCEEDED(hr)) {
        Log(L"[+] Virtualizing at: %s\n", m_RootDir.c_str());
        Log(L"[+] Projected files: %zu\n", m_Config.Files.size());
        Log(L"[+] Process rules:   %zu\n", m_Config.Rules.size());
        Log(L"[+] Rehydration worker: running (debounce: %lu ms)\n", DEBOUNCE_MS);
    }
    else {
        {
            std::lock_guard<std::mutex> lock(m_RehydrateMutex);
            m_Shutdown = true;
        }
        m_RehydrateCV.notify_one();
        if (m_WorkerThread.joinable()) m_WorkerThread.join();
    }

    return hr;
}

void PhantomProvider::Stop() {
    if (m_VirtCtx) {
        PrjStopVirtualizing(m_VirtCtx);
        m_VirtCtx = nullptr;
        Log(L"[-] Virtualization stopped.\n");
    }

    {
        std::lock_guard<std::mutex> lock(m_RehydrateMutex);
        m_Shutdown = true;
    }
    m_RehydrateCV.notify_one();
    if (m_WorkerThread.joinable()) {
        m_WorkerThread.join();
        Log(L"[-] Rehydration worker stopped.\n");
    }
}

// ---------------------------------------------------------------------------
// Debounced rehydration
// ---------------------------------------------------------------------------

void PhantomProvider::SignalRehydration(PCWSTR relativePath) {
    if (!relativePath) return;
    std::wstring path(relativePath);

    {
        std::lock_guard<std::mutex> lock(m_RehydrateMutex);
        m_LastCloseTick[path] = GetTickCount64();
        m_PendingFiles.insert(path);
    }
    m_RehydrateCV.notify_one();
}

void PhantomProvider::RehydrationWorker() {
    Log(L" [~] Rehydration worker started\n");

    while (true) {
        // Phase 1: Wait until there is at least one pending file or shutdown
        {
            std::unique_lock<std::mutex> lock(m_RehydrateMutex);
            m_RehydrateCV.wait(lock, [this] {
                return m_Shutdown || !m_PendingFiles.empty();
                });
            if (m_Shutdown && m_PendingFiles.empty())
                break;
        }

        // Phase 2: Sleep for the debounce period outside the lock
        Sleep(DEBOUNCE_MS);

        // Phase 3: Collect files whose last close was >= DEBOUNCE_MS ago
        std::vector<std::wstring> ready;
        {
            std::lock_guard<std::mutex> lock(m_RehydrateMutex);
            if (m_Shutdown) break;

            ULONGLONG now = GetTickCount64();
            auto it = m_PendingFiles.begin();
            while (it != m_PendingFiles.end()) {
                auto tickIt = m_LastCloseTick.find(*it);
                if (tickIt != m_LastCloseTick.end()) {
                    ULONGLONG elapsed = now - tickIt->second;
                    if (elapsed >= DEBOUNCE_MS) {
                        ready.push_back(*it);
                        m_LastCloseTick.erase(tickIt);
                        it = m_PendingFiles.erase(it);
                        continue;
                    }
                }
                ++it;
            }
        }

        // Phase 4: Rehydrate collected files (outside lock)
        for (const auto& path : ready) {
            ForceRehydration(path.c_str());
        }

        // If nothing was ready yet (still within debounce window),
        // loop back and the CV wait will re-trigger from pending files
    }

    Log(L" [~] Rehydration worker exiting\n");
}

// ---------------------------------------------------------------------------
// Re-hydration: delete cached content, revert to placeholder
// ---------------------------------------------------------------------------

void PhantomProvider::ForceRehydration(PCWSTR relativePath) {
    if (!relativePath || !m_VirtCtx) return;

    ULONGLONG startTick = GetTickCount64();
    Log(L" [~] Entering ForceRehydration for %s (tick: %llu)\n", relativePath, startTick);

    const int maxRetries = 5;
    HRESULT hr = E_FAIL;

    for (int attempt = 0; attempt < maxRetries; attempt++) {
        hr = PrjDeleteFile(
            m_VirtCtx,
            relativePath,
            PRJ_UPDATE_ALLOW_DIRTY_DATA | PRJ_UPDATE_ALLOW_DIRTY_METADATA |
            PRJ_UPDATE_ALLOW_READ_ONLY | PRJ_UPDATE_ALLOW_TOMBSTONE,
            nullptr);

        if (SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
            break;
        }

        Log(L" [~] PrjDeleteFile attempt %d failed: 0x%08X, retrying...\n", attempt + 1, hr);
        Sleep(150);
    }

    if (SUCCEEDED(hr)) {
        Log(L" [~] Re-hydrated: %s (total time: %llu ms)\n",
            relativePath, GetTickCount64() - startTick);
    }
    else if (hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        Log(L" [!] Re-hydration failed: %s (0x%08X) (total time: %llu ms)\n",
            relativePath, hr, GetTickCount64() - startTick);
    }
}

// ---------------------------------------------------------------------------
// Static trampolines
// ---------------------------------------------------------------------------

HRESULT CALLBACK PhantomProvider::CbStartEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId) {
    return GetInstance(cbd)->DoStartEnum(cbd, enumId);
}
HRESULT CALLBACK PhantomProvider::CbEndEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId) {
    return GetInstance(cbd)->DoEndEnum(cbd, enumId);
}
HRESULT CALLBACK PhantomProvider::CbGetEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId,
    PCWSTR searchExpr, PRJ_DIR_ENTRY_BUFFER_HANDLE bufHandle) {
    return GetInstance(cbd)->DoGetEnum(cbd, enumId, searchExpr, bufHandle);
}
HRESULT CALLBACK PhantomProvider::CbGetPlaceholder(const PRJ_CALLBACK_DATA* cbd) {
    return GetInstance(cbd)->DoGetPlaceholder(cbd);
}
HRESULT CALLBACK PhantomProvider::CbGetFileData(const PRJ_CALLBACK_DATA* cbd, UINT64 offset, UINT32 length) {
    return GetInstance(cbd)->DoGetFileData(cbd, offset, length);
}
HRESULT CALLBACK PhantomProvider::CbNotification(const PRJ_CALLBACK_DATA* cbd, BOOLEAN isDir,
    PRJ_NOTIFICATION notification, PCWSTR destFileName, PRJ_NOTIFICATION_PARAMETERS* params) {
    return GetInstance(cbd)->DoNotification(cbd, isDir, notification, destFileName, params);
}

// ---------------------------------------------------------------------------
// Directory enumeration
// ---------------------------------------------------------------------------

HRESULT PhantomProvider::DoStartEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId) {
    std::lock_guard lock(m_EnumLock);
    m_Enumerations[*enumId] = {};
    return S_OK;
}

HRESULT PhantomProvider::DoEndEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId) {
    std::lock_guard lock(m_EnumLock);
    m_Enumerations.erase(*enumId);
    return S_OK;
}

HRESULT PhantomProvider::DoGetEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId,
    PCWSTR searchExpr, PRJ_DIR_ENTRY_BUFFER_HANDLE bufHandle) {

    std::lock_guard lock(m_EnumLock);
    auto it = m_Enumerations.find(*enumId);
    if (it == m_Enumerations.end()) return E_INVALIDARG;

    auto& session = it->second;

    if (session.Entries.empty() || (cbd->Flags & PRJ_CB_DATA_FLAG_ENUM_RESTART_SCAN)) {
        session.Entries.clear();
        session.Index = 0;

        std::wstring dir(cbd->FilePathName ? cbd->FilePathName : L"");
        if (dir.empty() || dir == L"\\") {
            for (const auto& f : m_Config.Files) {
                if (PrjFileNameMatch(f.FileName.c_str(), searchExpr)) {
                    session.Entries.push_back(&f);
                }
            }
            std::sort(session.Entries.begin(), session.Entries.end(),
                [](const ProjectedFileEntry* a, const ProjectedFileEntry* b) {
                    return PrjFileNameCompare(a->FileName.c_str(), b->FileName.c_str()) < 0;
                });
        }
    }

    if (session.Entries.empty()) return S_OK;

    while (session.Index < session.Entries.size()) {
        const auto* entry = session.Entries[session.Index];

        size_t maxSize = entry->PayloadData.size();
        if (entry->DecoyData.size() > maxSize) maxSize = entry->DecoyData.size();

        PRJ_FILE_BASIC_INFO info{};
        info.IsDirectory = FALSE;
        info.FileSize = static_cast<INT64>(maxSize);

        HRESULT hr = PrjFillDirEntryBuffer(
            entry->FileName.c_str(), &info, bufHandle);
        if (FAILED(hr)) break;

        session.Index++;
    }

    return S_OK;
}

// ---------------------------------------------------------------------------
// Placeholder - always max size, content switching only in GetFileData
// ---------------------------------------------------------------------------

HRESULT PhantomProvider::DoGetPlaceholder(const PRJ_CALLBACK_DATA* cbd) {
    const auto* entry = m_Config.FindFile(cbd->FilePathName);
    if (!entry) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    size_t fileSize = entry->PayloadData.size();
    if (entry->DecoyData.size() > fileSize)
        fileSize = entry->DecoyData.size();

    ProcessPolicy policy = m_Config.GetReadPolicy(cbd->TriggeringProcessImageFileName);

    Log(L"[*] PLACEHOLDER: %s | PID: %lu | Image: %s | Size: %llu | Policy: %hs\n",
        cbd->FilePathName,
        cbd->TriggeringProcessId,
        cbd->TriggeringProcessImageFileName ? cbd->TriggeringProcessImageFileName : L"(null)",
        fileSize,
        PolicyToStr(policy));

    PRJ_PLACEHOLDER_INFO info{};
    info.FileBasicInfo.IsDirectory = FALSE;
    info.FileBasicInfo.FileSize = static_cast<INT64>(fileSize);

    return PrjWritePlaceholderInfo(m_VirtCtx, cbd->FilePathName, &info, sizeof(info));
}

// ---------------------------------------------------------------------------
// GetFileData - per-process content switching
// ---------------------------------------------------------------------------

HRESULT PhantomProvider::DoGetFileData(const PRJ_CALLBACK_DATA* cbd, UINT64 offset, UINT32 length) {
    const auto* entry = m_Config.FindFile(cbd->FilePathName);
    if (!entry) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    ProcessPolicy policy = m_Config.GetReadPolicy(cbd->TriggeringProcessImageFileName);

    Log(L"[*] FILE_READ: %s | PID: %lu | Image: %s | Policy: %hs\n",
        cbd->FilePathName,
        cbd->TriggeringProcessId,
        cbd->TriggeringProcessImageFileName ? cbd->TriggeringProcessImageFileName : L"(null)",
        PolicyToStr(policy));

    if (policy == ProcessPolicy::DENY_READ) {
        Log(L"    [!] ACCESS DENIED to PID %lu\n", cbd->TriggeringProcessId);
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }

    const std::vector<BYTE>& data =
        (policy == ProcessPolicy::SERVE_PAYLOAD) ? entry->PayloadData : entry->DecoyData;

    if (data.empty()) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);

    UINT64 dataSize = data.size();

    void* buffer = PrjAllocateAlignedBuffer(m_VirtCtx, length);
    if (!buffer) return E_OUTOFMEMORY;

    ZeroMemory(buffer, length);

    UINT32 bytesToCopy = 0;
    if (offset < dataSize) {
        UINT64 remaining = dataSize - offset;
        bytesToCopy = (remaining < static_cast<UINT64>(length))
            ? static_cast<UINT32>(remaining) : length;
        memcpy(buffer, data.data() + offset, bytesToCopy);
    }

    
    HRESULT hr = PrjWriteFileData(
        m_VirtCtx, &cbd->DataStreamId, buffer, offset, length);

    PrjFreeAlignedBuffer(buffer);

    if (SUCCEEDED(hr)) {
        Log(L"    [+] Served %lu bytes (%hs, src=%llu) to PID %lu\n",
            length,
            (policy == ProcessPolicy::SERVE_PAYLOAD) ? "PAYLOAD+XOR" : "DECOY",
            dataSize,
            cbd->TriggeringProcessId);
    }

    return hr;
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

HRESULT PhantomProvider::DoNotification(const PRJ_CALLBACK_DATA* cbd, BOOLEAN isDir,
    PRJ_NOTIFICATION notification, PCWSTR destFileName,
    PRJ_NOTIFICATION_PARAMETERS* params) {

    switch (notification) {

    case PRJ_NOTIFICATION_FILE_OPENED: {
        Log(L"[*] FILE_OPENED: %s | PID: %lu | Image: %s\n",
            cbd->FilePathName ? cbd->FilePathName : L"",
            cbd->TriggeringProcessId,
            cbd->TriggeringProcessImageFileName ? cbd->TriggeringProcessImageFileName : L"(null)");
        break;
    }

    case PRJ_NOTIFICATION_PRE_DELETE: {
        bool deny = m_Config.ShouldDenyDelete(cbd->TriggeringProcessImageFileName);
        Log(L"[*] PRE_DELETE: %s | PID: %lu | %hs\n",
            cbd->FilePathName, cbd->TriggeringProcessId,
            deny ? "DENIED" : "ALLOWED");
        if (deny) return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        break;
    }

    case PRJ_NOTIFICATION_PRE_RENAME: {
        bool deny = m_Config.ShouldDenyRename(cbd->TriggeringProcessImageFileName);
        Log(L"[*] PRE_RENAME: %s -> %s | PID: %lu | %hs\n",
            cbd->FilePathName,
            destFileName ? destFileName : L"(null)",
            cbd->TriggeringProcessId,
            deny ? "DENIED" : "ALLOWED");
        if (deny) return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        break;
    }

    case PRJ_NOTIFICATION_PRE_SET_HARDLINK: {
        Log(L"[*] PRE_HARDLINK: %s | PID: %lu | DENIED\n",
            cbd->FilePathName, cbd->TriggeringProcessId);
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }

    case PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_NO_MODIFICATION:
    case PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_MODIFIED:
    case PRJ_NOTIFICATION_FILE_HANDLE_CLOSED_FILE_DELETED: {
        const auto* entry = m_Config.FindFile(cbd->FilePathName);
        if (entry) {
            // Must rehydrate after EVERY close, regardless of process policy.
            // ProjFS caches hydrated content on NTFS. Without rehydration,
            // the next process gets stale content from disk instead of
            // going through GetFileData for fresh policy-based switching.
            Log(L"[*] HANDLE_CLOSED: %s | PID: %lu | Policy: %hs | Signaling rehydration\n",
                cbd->FilePathName, cbd->TriggeringProcessId,
                PolicyToStr(m_Config.GetReadPolicy(cbd->TriggeringProcessImageFileName)));
            SignalRehydration(cbd->FilePathName);
        }
        break;
    }

    case PRJ_NOTIFICATION_FILE_PRE_CONVERT_TO_FULL: {
        Log(L"[*] PRE_CONVERT_TO_FULL: %s | PID: %lu | DENIED\n",
            cbd->FilePathName, cbd->TriggeringProcessId);
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }

    default:
        break;
    }

    return S_OK;
}