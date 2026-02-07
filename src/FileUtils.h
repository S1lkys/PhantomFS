#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <cstdio>

namespace FileUtils {

    inline std::vector<BYTE> ReadFileBytes(const std::wstring& path) {
        std::vector<BYTE> data;

        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            wprintf(L"[!] Failed to open: %s (error: %lu)\n", path.c_str(), GetLastError());
            return data;
        }

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
            CloseHandle(hFile);
            return data;
        }

        data.resize(static_cast<size_t>(fileSize.QuadPart));

        DWORD totalRead = 0;
        while (totalRead < data.size()) {
            DWORD remaining = static_cast<DWORD>(data.size() - totalRead);
            DWORD toRead = (remaining > 0x10000000) ? 0x10000000 : remaining;
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, data.data() + totalRead, toRead, &bytesRead, nullptr)) {
                wprintf(L"[!] ReadFile failed: %s (error: %lu)\n", path.c_str(), GetLastError());
                CloseHandle(hFile);
                return {};
            }
            totalRead += bytesRead;
        }

        CloseHandle(hFile);
        return data;
    }

    inline bool WriteFileBytes(const std::wstring& path, const std::vector<BYTE>& data) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD written = 0;
        BOOL ok = WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
        CloseHandle(hFile);
        return ok && written == data.size();
    }

} // namespace FileUtils
