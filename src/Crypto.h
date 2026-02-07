#pragma once
#include <Windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace Crypto {

    // Parse hex string to bytes: "AABB01" -> {0xAA, 0xBB, 0x01}
    inline std::vector<BYTE> HexToBytes(const std::wstring& hex) {
        std::vector<BYTE> bytes;
        if (hex.size() % 2 != 0) return bytes;
        bytes.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            wchar_t buf[3] = { hex[i], hex[i + 1], 0 };
            bytes.push_back(static_cast<BYTE>(wcstoul(buf, nullptr, 16)));
        }
        return bytes;
    }

    // AES-256-CBC decrypt
    // Encrypted blob format: [16 bytes IV][ciphertext with PKCS7 padding]
    inline std::vector<BYTE> AesDecrypt(
        const std::vector<BYTE>& encData,
        const std::vector<BYTE>& key)
    {
        std::vector<BYTE> result;

        if (key.size() != 32) {
            wprintf(L"[!] AES key must be 32 bytes (256-bit), got %zu\n", key.size());
            return result;
        }
        if (encData.size() <= 16) {
            wprintf(L"[!] Encrypted data too small (need IV + ciphertext)\n");
            return result;
        }

        // First 16 bytes = IV, rest = ciphertext
        std::vector<BYTE> iv(encData.begin(), encData.begin() + 16);
        std::vector<BYTE> ciphertext(encData.begin() + 16, encData.end());

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        NTSTATUS status;

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) {
            wprintf(L"[!] BCryptOpenAlgorithmProvider failed: 0x%08X\n", status);
            return result;
        }

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (!NT_SUCCESS(status)) {
            wprintf(L"[!] BCryptSetProperty CBC failed: 0x%08X\n", status);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
        if (!NT_SUCCESS(status)) {
            wprintf(L"[!] BCryptGenerateSymmetricKey failed: 0x%08X\n", status);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        // Query output size
        ULONG plainSize = 0;
        status = BCryptDecrypt(hKey,
            ciphertext.data(), static_cast<ULONG>(ciphertext.size()),
            nullptr,
            iv.data(), static_cast<ULONG>(iv.size()),
            nullptr, 0, &plainSize,
            BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) {
            wprintf(L"[!] BCryptDecrypt (size query) failed: 0x%08X\n", status);
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        result.resize(plainSize);

        // IV gets modified during decrypt, reset it
        std::vector<BYTE> ivCopy(encData.begin(), encData.begin() + 16);

        ULONG bytesDecrypted = 0;
        status = BCryptDecrypt(hKey,
            ciphertext.data(), static_cast<ULONG>(ciphertext.size()),
            nullptr,
            ivCopy.data(), static_cast<ULONG>(ivCopy.size()),
            result.data(), plainSize, &bytesDecrypted,
            BCRYPT_BLOCK_PADDING);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (!NT_SUCCESS(status)) {
            wprintf(L"[!] BCryptDecrypt failed: 0x%08X\n", status);
            result.clear();
            return result;
        }

        result.resize(bytesDecrypted);
        return result;
    }

    // AES-256-CBC encrypt (for the companion encrypt tool)
    // Output format: [16 bytes IV][ciphertext with PKCS7 padding]
    inline std::vector<BYTE> AesEncrypt(
        const std::vector<BYTE>& plainData,
        const std::vector<BYTE>& key)
    {
        std::vector<BYTE> result;

        if (key.size() != 32) {
            wprintf(L"[!] AES key must be 32 bytes (256-bit)\n");
            return result;
        }

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        NTSTATUS status;

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) return result;

        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        // Generate random IV
        BYTE iv[16] = {};
        BCryptGenRandom(nullptr, iv, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
            const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        // Query cipher size
        ULONG cipherSize = 0;
        BYTE ivCopy[16];
        memcpy(ivCopy, iv, 16);

        status = BCryptEncrypt(hKey,
            const_cast<PUCHAR>(plainData.data()), static_cast<ULONG>(plainData.size()),
            nullptr, ivCopy, 16,
            nullptr, 0, &cipherSize,
            BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) {
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

        // [IV][ciphertext]
        result.resize(16 + cipherSize);
        memcpy(result.data(), iv, 16);

        memcpy(ivCopy, iv, 16);
        ULONG bytesEncrypted = 0;
        status = BCryptEncrypt(hKey,
            const_cast<PUCHAR>(plainData.data()), static_cast<ULONG>(plainData.size()),
            nullptr, ivCopy, 16,
            result.data() + 16, cipherSize, &bytesEncrypted,
            BCRYPT_BLOCK_PADDING);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (!NT_SUCCESS(status)) {
            result.clear();
            return result;
        }

        result.resize(16 + bytesEncrypted);
        return result;
    }

} // namespace Crypto
