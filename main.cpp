#include <cstdint>
#include <iomanip>
#include <iostream>
#include <ranges>
#include <sstream>

#include <processthreadsapi.h>
#include <windows.h>

using namespace std;

constexpr const char *EFI_GLOBAL_VARIABLE_GUID = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
constexpr int MAX_LOAD_OPTIONS = UINT16_MAX;

typedef uint16_t LoadOptionId;
struct LoadOption {
    uint32_t attributes;
    uint16_t filePathListLength;
    wchar_t description[];
};

// Based on:
// https://github.com/microsoft/Windows-classic-samples/blob/98185/Samples/ManagementInfrastructure/cpp/Process/Provider/WindowsProcess.c#L49
BOOL enablePrivilege() {
    LUID privilegeRequired;
    DWORD dwLen = 0, iCount = 0;
    BOOL bRes = FALSE;
    HANDLE hToken = NULL;
    BYTE *pBuffer = NULL;
    TOKEN_PRIVILEGES *pPrivs = NULL;

    bRes = LookupPrivilegeValue(NULL, SE_SYSTEM_ENVIRONMENT_NAME, &privilegeRequired);
    if (!bRes) {
        return FALSE;
    }

    bRes = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (!bRes) {
        return FALSE;
    }

    bRes = GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLen);
    if (bRes) {
        CloseHandle(hToken);
        return FALSE;
    }

    pBuffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
    if (!pBuffer) {
        CloseHandle(hToken);
        return FALSE;
    }

    bRes = GetTokenInformation(hToken, TokenPrivileges, pBuffer, dwLen, &dwLen);
    if (!bRes) {
        CloseHandle(hToken);
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return FALSE;
    }

    // Iterate through all the privileges and enable the one required
    bRes = FALSE;
    pPrivs = (TOKEN_PRIVILEGES *)pBuffer;
    for (iCount = 0; iCount < pPrivs->PrivilegeCount; iCount++) {
        if (pPrivs->Privileges[iCount].Luid.LowPart == privilegeRequired.LowPart &&
            pPrivs->Privileges[iCount].Luid.HighPart == privilegeRequired.HighPart) {
            pPrivs->Privileges[iCount].Attributes |= SE_PRIVILEGE_ENABLED;
            // here it's found
            bRes = AdjustTokenPrivileges(hToken, FALSE, pPrivs, dwLen, NULL, NULL);
            break;
        }
    }

    if (iCount == pPrivs->PrivilegeCount) {
        // not found, no specific error
        SetLastError(ERROR_SUCCESS);
        bRes = FALSE;
    }

    CloseHandle(hToken);
    HeapFree(GetProcessHeap(), 0, pBuffer);
    return bRes;
}

DWORD getUEFIVar(const char *varName, auto &buffer, bool required = true) {
    DWORD length = GetFirmwareEnvironmentVariableA(varName, EFI_GLOBAL_VARIABLE_GUID, buffer, sizeof(buffer));
    if (length == 0) {
        DWORD err = GetLastError();
        if (err == ERROR_ENVVAR_NOT_FOUND) {
            if (required) {
                cerr << "GetFirmwareEnvironmentVariable failed because the variable was not found." << endl;
            }
        } else {
            cerr << "GetFirmwareEnvironmentVariable failed with error code: " << err << endl;
        }
    }
    return length;
}

string optionNameFromId(LoadOptionId i) {
    stringstream s;
    s << "Boot" << hex << setw(4) << setfill('0') << uppercase << i;
    return s.str();
}

int mainNoPause() {
    LoadOptionId bootOrder[MAX_LOAD_OPTIONS];
    uint8_t loadOptionBuffer[1024];
    DWORD bootOrderLength, bootNextLength;
    DWORD err;

    if (!enablePrivilege()) {
        err = GetLastError();
        // When run without admin privileges the required system privilege doesn't exist but no error code is set.
        if (err == ERROR_SUCCESS) {
            cerr << "This program must be run with administrator privileges." << endl;
        } else {
            cerr << "Failed to enable privilege with error code: " << err << endl;
        }
        return 1;
    }

    /*
    Boot#### NV, BS, RT A boot load option. #### is a printed hex value. No 0x or h is
    included in the hex value.
    BootNext NV, BS, RT The boot option for the next boot only.
    BootOrder NV, BS, RT The ordered boot option load list
    */
    bootOrderLength = getUEFIVar("BootOrder", bootOrder);
    if (bootOrderLength == 0) {
        return 2;
    }

    cout << "BootOrder:\n";
    for (auto e : bootOrder | std::views::take(bootOrderLength / sizeof(bootOrder[0]))) {
        const char *optionName = optionNameFromId(e).c_str();
        cout << "> " << optionName << ":" << endl;
        auto len = getUEFIVar(optionName, loadOptionBuffer);
        if (len == 0) {
            return 3;
        }
        LoadOption *option = (LoadOption *)loadOptionBuffer;
        wcout << L">> Description: " << option->description << endl;
        cout << ">> Attributes: " << option->attributes << endl;
    }

    bootNextLength = getUEFIVar("BootNext", loadOptionBuffer, false);
    if (bootNextLength == 0) {
        strcpy((char *)loadOptionBuffer, "(not set)");
    }
    cout << "BootNext: " << (char *)loadOptionBuffer << endl;
    return 0;
}

int main() {
    int r = mainNoPause();
    system("pause");
    return r;
}
