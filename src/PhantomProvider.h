#pragma once
#include <Windows.h>
#include <projectedfslib.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include "Config.h"

#pragma comment(lib, "projectedfslib.lib")
#pragma comment(lib, "ole32.lib")

struct EnumSession {
    std::vector<const ProjectedFileEntry*> Entries;
    size_t Index = 0;
};

struct GUIDLess {
    bool operator()(const GUID& a, const GUID& b) const {
        return memcmp(&a, &b, sizeof(GUID)) < 0;
    }
};

// Case-insensitive wstring hash/compare
struct WStringIHash {
    size_t operator()(const std::wstring& s) const {
        size_t h = 0;
        for (wchar_t c : s)
            h = h * 31 + towlower(c);
        return h;
    }
};
struct WStringIEqual {
    bool operator()(const std::wstring& a, const std::wstring& b) const {
        return _wcsicmp(a.c_str(), b.c_str()) == 0;
    }
};

class PhantomProvider {
public:
    explicit PhantomProvider(PhantomConfig config);
    ~PhantomProvider();

    HRESULT Init(PCWSTR rootDir);
    HRESULT Start();
    void Stop();

private:
    PhantomConfig m_Config;
    std::wstring m_RootDir;
    PRJ_NAMESPACE_VIRTUALIZATION_CONTEXT m_VirtCtx = nullptr;
    GUID m_InstanceId = {};

    // Enumeration state
    std::map<GUID, EnumSession, GUIDLess> m_Enumerations;
    std::mutex m_EnumLock;

    // Debounced rehydration:
    // Only triggered when a PAYLOAD process closes a file handle.
    // Debounce ensures Defender's scan storm settles before PrjDeleteFile.
    static constexpr DWORD DEBOUNCE_MS = 300;

    std::unordered_map<std::wstring, ULONGLONG, WStringIHash, WStringIEqual> m_LastCloseTick;
    std::unordered_set<std::wstring, WStringIHash, WStringIEqual> m_PendingFiles;
    std::mutex                  m_RehydrateMutex;
    std::condition_variable     m_RehydrateCV;
    std::thread                 m_WorkerThread;
    bool                        m_Shutdown;

    // Helpers
    void Log(const wchar_t* fmt, ...);
    const char* PolicyToStr(ProcessPolicy p);

    // Rehydration
    void SignalRehydration(PCWSTR relativePath);
    void RehydrationWorker();
    void ForceRehydration(PCWSTR relativePath);

    // Callback implementations
    HRESULT DoStartEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId);
    HRESULT DoEndEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId);
    HRESULT DoGetEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId,
        PCWSTR searchExpr, PRJ_DIR_ENTRY_BUFFER_HANDLE bufHandle);
    HRESULT DoGetPlaceholder(const PRJ_CALLBACK_DATA* cbd);
    HRESULT DoGetFileData(const PRJ_CALLBACK_DATA* cbd, UINT64 offset, UINT32 length);
    HRESULT DoNotification(const PRJ_CALLBACK_DATA* cbd, BOOLEAN isDir,
        PRJ_NOTIFICATION notification, PCWSTR destFileName,
        PRJ_NOTIFICATION_PARAMETERS* params);

    // Static ProjFS trampolines
    static HRESULT CALLBACK CbStartEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId);
    static HRESULT CALLBACK CbEndEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId);
    static HRESULT CALLBACK CbGetEnum(const PRJ_CALLBACK_DATA* cbd, const GUID* enumId,
        PCWSTR searchExpr, PRJ_DIR_ENTRY_BUFFER_HANDLE bufHandle);
    static HRESULT CALLBACK CbGetPlaceholder(const PRJ_CALLBACK_DATA* cbd);
    static HRESULT CALLBACK CbGetFileData(const PRJ_CALLBACK_DATA* cbd, UINT64 offset, UINT32 length);
    static HRESULT CALLBACK CbNotification(const PRJ_CALLBACK_DATA* cbd, BOOLEAN isDir,
        PRJ_NOTIFICATION notification, PCWSTR destFileName,
        PRJ_NOTIFICATION_PARAMETERS* params);
};