#include <windows.h>
#include <shellapi.h>   // ShellExecuteExW
#include <iostream>
#include <string>

#pragma comment(lib, "shell32.lib")

// 以管理员权限启动一个外部程序
bool RunAsAdmin(const std::wstring& exePath,
    const std::wstring& params = L"",
    const std::wstring& workingDir = L"",
    DWORD* outExitCode = nullptr)
{
    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(SHELLEXECUTEINFOW);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;  // 需要进程句柄以等待
    sei.hwnd = NULL;                    // UAC 对话框的所有者窗口
    sei.lpVerb = L"runas";                // 关键：请求管理员权限
    sei.lpFile = exePath.c_str();
    sei.lpParameters = params.empty() ? nullptr : params.c_str();
    sei.lpDirectory = workingDir.empty() ? nullptr : workingDir.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            std::wcerr << L"用户取消了 UAC 提权。" << std::endl;
        }
        else {
            std::wcerr << L"ShellExecuteEx 失败，错误码: " << err << std::endl;
        }
        return false;
    }

    std::wcout << L"成功以管理员权限启动进程，PID: "
        << GetProcessId(sei.hProcess) << std::endl;

    // 等待进程结束（可选）
    WaitForSingleObject(sei.hProcess, INFINITE);

    // 获取退出码
    if (outExitCode) {
        GetExitCodeProcess(sei.hProcess, outExitCode);
    }

    CloseHandle(sei.hProcess);
    return true;
}

int main() {
    std::wcout << L"正在尝试以管理员权限启动（is_admin.exe）..." << std::endl;

    DWORD exitCode = 0;
    if (RunAsAdmin(L"D:\\code\\cpp\\defense-evasion-demo\\defense-evasion\\x64\\Debug\\is_admin.exe", L"", L"", &exitCode)) {
        std::wcout << L"is_admin.exe 已退出，退出码: " << exitCode << std::endl;
    }

    std::wcout << L"按回车键退出...";
    std::cin.get();
    return 0;
}