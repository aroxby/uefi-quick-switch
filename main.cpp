#include <cstdint>
#include <iomanip>
#include <iostream>
#include <ranges>
#include <sstream>
#include <windows.h>
#include <processthreadsapi.h>
using namespace std;


constexpr int MAX_LOAD_OPTIONS = UINT16_MAX;
typedef uint16_t LoadOptionId;
struct LoadOption {
    uint32_t attributes;
    uint16_t filePathListLength;
    wchar_t description[];
};


// Based on:
// https://github.com/microsoft/Windows-classic-samples/blob/98185/Samples/ManagementInfrastructure/cpp/Process/Provider/WindowsProcess.c#L49
BOOL EnablePrivilege() {
    LUID PrivilegeRequired;
    DWORD dwLen = 0, iCount = 0;
    BOOL bRes = FALSE;
    HANDLE hToken = NULL;
    BYTE *pBuffer = NULL;
    TOKEN_PRIVILEGES* pPrivs = NULL;

    bRes = LookupPrivilegeValue(NULL, SE_SYSTEM_ENVIRONMENT_NAME, &PrivilegeRequired);
    if(!bRes) {
        return FALSE;
    }

    bRes = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
    if(!bRes) {
        return FALSE;
    }

    bRes = GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwLen);
    if(bRes)
    {
        CloseHandle(hToken);
        return FALSE;
    }

    pBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
    if(!pBuffer) {
        CloseHandle(hToken);
        return FALSE;
    }

    bRes = GetTokenInformation(hToken, TokenPrivileges, pBuffer, dwLen, &dwLen);
    if (!bRes)
    {
        CloseHandle(hToken);
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return FALSE;
    }

    // Iterate through all the privileges and enable the one required
    bRes = FALSE;
    pPrivs = (TOKEN_PRIVILEGES*)pBuffer;
    for(iCount = 0; iCount < pPrivs->PrivilegeCount; iCount++)
    {
        if (pPrivs->Privileges[iCount].Luid.LowPart == PrivilegeRequired.LowPart &&
          pPrivs->Privileges[iCount].Luid.HighPart == PrivilegeRequired.HighPart )
        {
            pPrivs->Privileges[iCount].Attributes |= SE_PRIVILEGE_ENABLED;
            // here it's found
            bRes = AdjustTokenPrivileges(hToken, FALSE, pPrivs, dwLen, NULL, NULL);
            break;
        }
    }

    CloseHandle(hToken);
    HeapFree(GetProcessHeap(), 0, pBuffer);
    return bRes;
}

DWORD GetUEFIVar(const char *varName, auto &buffer) {
    constexpr const char *EFI_GLOBAL_VARIABLE_GUID = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
    DWORD length = GetFirmwareEnvironmentVariableA(varName, EFI_GLOBAL_VARIABLE_GUID, buffer, sizeof(buffer));
    if (length == 0) {
        DWORD err = GetLastError();
        if(err == ERROR_ENVVAR_NOT_FOUND) {
            cerr << "GetFirmwareEnvironmentVariable failed because the variable was not found." << endl;
        } else {
            cerr << "GetFirmwareEnvironmentVariable failed with error code: " << err << endl;
        }
    }
    return length;
}

string optionNameFromId(LoadOptionId i) {
    stringstream s;
    s << "Boot" << hex << setw(4) << setfill('0') << uppercase << i;
    return move(s.str());
}

int conmain() {
    LoadOptionId BootOrder[MAX_LOAD_OPTIONS];
    uint8_t LoadOptionBuffer[1024];
    DWORD BootOrderLength;
    DWORD err;

    if (!EnablePrivilege()) {
        err = GetLastError();
        // Technically, this error means "The data area passed to a system call is too small"
        // but no amount of buffer space helps.
        // Only running with administrator privileges allows this call to succeed.
        // I don't know why.
        if (err == ERROR_INSUFFICIENT_BUFFER) {
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
    BootOrderLength = GetUEFIVar("BootOrder", BootOrder);
    if (BootOrderLength == 0) {
        return 2;
    }

    cout << "BootOrder:\n";
    for(auto e: BootOrder | std::views::take(BootOrderLength / sizeof(BootOrder[0]))) {
        const char *optionName = optionNameFromId(e).c_str();
        cout << optionName << endl;
        auto len = GetUEFIVar(optionName, LoadOptionBuffer);
        if (len == 0) {
            return 3;
        }
        wcout << ((LoadOption*)LoadOptionBuffer)->description << endl;
    }

    return 0;
}

int main() {
    int r = conmain();
    system("pause");
    return r;
}
