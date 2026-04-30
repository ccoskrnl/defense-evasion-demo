#include <windows.h>
#include <shlobj.h>      // IsUserAnAdmin
#include <sddl.h>        // Sid 相关函数
#include <iostream>
#include <vector>
#include <memory>
#include <string>

// 如果使用 MSVC，可自动链接 shell32.lib（IsUserAnAdmin 需要）
#pragma comment(lib, "shell32.lib")

// ==================== 方法 1：CheckTokenMembership ====================
bool IsAdmin_CheckTokenMembership() {
    // 构造 Administrators 组的 SID
    PSID adminGroupSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroupSid)) {
        return false;
    }

    BOOL isAdmin = FALSE;
    // 检查当前进程的令牌是否包含管理员组（已启用）
    if (!CheckTokenMembership(nullptr, adminGroupSid, &isAdmin)) {
        isAdmin = FALSE;
    }

    FreeSid(adminGroupSid);
    return isAdmin != FALSE;
}

// ==================== 方法 2：IsUserAnAdmin（Shell 便捷函数） ====================
bool IsAdmin_IsUserAnAdmin() {
    // 直接调用 shell32 提供的便捷函数
    return IsUserAnAdmin() != FALSE;
}

// ==================== 方法 3：TokenElevation（令牌提升状态） ====================
bool IsAdmin_TokenElevation() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_ELEVATION elevation = {};
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    BOOL result = GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize);
    CloseHandle(hToken);

    if (!result) {
        return false;
    }
    return elevation.TokenIsElevated != 0;
}

// ==================== 方法 4：TokenIntegrityLevel（完整性级别 >= High） ====================
bool IsAdmin_TokenIntegrityLevel() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    // 获取所需缓冲区大小
    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLength);
    if (dwLength == 0) {
        CloseHandle(hToken);
        return false;
    }

    std::vector<BYTE> buffer(dwLength);
    PTOKEN_MANDATORY_LABEL pTIL = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.data());

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);

    // 获取最后一个子权限，即完整性级别 RID
    DWORD subAuthorityCount = *GetSidSubAuthorityCount(pTIL->Label.Sid);
    DWORD integrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, subAuthorityCount - 1);

    // 高完整性 (0x3000) 或系统完整性 (0x4000) 均视为管理员
    return integrityLevel >= SECURITY_MANDATORY_HIGH_RID;
}

// ==================== 方法 5：手动枚举令牌组，查找已启用的 Administrators SID ====================
bool IsAdmin_TokenGroups() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    // 获取 TokenGroups 大小
    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenGroups, nullptr, 0, &dwLength);
    if (dwLength == 0) {
        CloseHandle(hToken);
        return false;
    }

    std::vector<BYTE> buffer(dwLength);
    PTOKEN_GROUPS pGroups = reinterpret_cast<PTOKEN_GROUPS>(buffer.data());

    if (!GetTokenInformation(hToken, TokenGroups, pGroups, dwLength, &dwLength)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);

    // 构造 Administrators 组 SID
    PSID adminSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminSid)) {
        return false;
    }

    bool isAdmin = false;
    for (DWORD i = 0; i < pGroups->GroupCount; ++i) {
        if (EqualSid(pGroups->Groups[i].Sid, adminSid)) {
            // 检查该组是否被启用
            if (pGroups->Groups[i].Attributes & SE_GROUP_ENABLED) {
                isAdmin = true;
            }
            break;
        }
    }

    FreeSid(adminSid);
    return isAdmin;
}

// ==================== 辅助函数：打印结果 ====================
void PrintResult(const std::string& methodName, bool isAdmin) {
    std::cout << methodName << ": " << (isAdmin ? "是" : "否") << std::endl;
}

// ==================== 主函数 ====================
int main() {
    std::cout << "=== 管理员权限检测汇总 ===" << std::endl;
    std::cout << "（以管理员权限运行的结果）" << std::endl;
    std::cout << "--------------------------" << std::endl;

    PrintResult("方法1 - CheckTokenMembership", IsAdmin_CheckTokenMembership());
    PrintResult("方法2 - IsUserAnAdmin", IsAdmin_IsUserAnAdmin());
    PrintResult("方法3 - TokenElevation", IsAdmin_TokenElevation());
    PrintResult("方法4 - TokenIntegrityLevel", IsAdmin_TokenIntegrityLevel());
    PrintResult("方法5 - 手动枚举 TokenGroups", IsAdmin_TokenGroups());

    std::cout << "--------------------------" << std::endl;
    std::cout << "按回车键退出...";
    std::cin.get();
    return 0;
}