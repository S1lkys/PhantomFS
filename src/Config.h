#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cwctype>

enum class ProcessPolicy {
    SERVE_PAYLOAD,
    SERVE_DECOY,
    DENY_READ,
};

struct ProcessRule {
    std::wstring ImageNameSubstring;
    ProcessPolicy ReadPolicy;
    bool DenyDelete;
    bool DenyRename;
};

struct ProjectedFileEntry {
    std::wstring FileName;
    std::vector<BYTE> PayloadData;
    std::vector<BYTE> DecoyData;
};

class PhantomConfig {
public:
    std::vector<ProcessRule> Rules;
    std::vector<ProjectedFileEntry> Files;
    ProcessPolicy DefaultReadPolicy = ProcessPolicy::DENY_READ;
    bool DefaultDenyDelete = true;
    bool DefaultDenyRename = true;
    bool Verbose = true;

    ProcessPolicy GetReadPolicy(PCWSTR triggeringImage) const {
        if (!triggeringImage) return DefaultReadPolicy;
        std::wstring img(triggeringImage);
        std::transform(img.begin(), img.end(), img.begin(), ::towlower);
        for (const auto& rule : Rules) {
            std::wstring pattern = rule.ImageNameSubstring;
            std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::towlower);
            if (img.find(pattern) != std::wstring::npos) {
                return rule.ReadPolicy;
            }
        }
        return DefaultReadPolicy;
    }

    bool ShouldDenyDelete(PCWSTR triggeringImage) const {
        if (!triggeringImage) return DefaultDenyDelete;
        std::wstring img(triggeringImage);
        std::transform(img.begin(), img.end(), img.begin(), ::towlower);
        for (const auto& rule : Rules) {
            std::wstring pattern = rule.ImageNameSubstring;
            std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::towlower);
            if (img.find(pattern) != std::wstring::npos) {
                return rule.DenyDelete;
            }
        }
        return DefaultDenyDelete;
    }

    bool ShouldDenyRename(PCWSTR triggeringImage) const {
        if (!triggeringImage) return DefaultDenyRename;
        std::wstring img(triggeringImage);
        std::transform(img.begin(), img.end(), img.begin(), ::towlower);
        for (const auto& rule : Rules) {
            std::wstring pattern = rule.ImageNameSubstring;
            std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::towlower);
            if (img.find(pattern) != std::wstring::npos) {
                return rule.DenyRename;
            }
        }
        return DefaultDenyRename;
    }

    const ProjectedFileEntry* FindFile(PCWSTR relativePath) const {
        if (!relativePath) return nullptr;
        std::wstring path(relativePath);
        if (!path.empty() && path[0] == L'\\') {
            path = path.substr(1);
        }
        for (const auto& f : Files) {
            if (_wcsicmp(path.c_str(), f.FileName.c_str()) == 0) {
                return &f;
            }
        }
        return nullptr;
    }
};