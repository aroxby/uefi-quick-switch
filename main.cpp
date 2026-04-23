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

struct LoadOptionParseResult {
    bool success;
    LoadOptionId value;

    LoadOptionParseResult(const char *str) {
        char *end;
        auto ivalue = strtoul(str, &end, 16);
        if (*end != '\0') {
            cerr << "Invalid load option ID (provide hex value): " << str << endl;
            success = false;
            return;
        }
        if (ivalue > MAX_LOAD_OPTIONS) {
            cerr << "Load option ID out of range (uint16_t): " << str << endl;
            success = false;
            return;
        }
        value = static_cast<LoadOptionId>(ivalue);
        success = true;
    }

    operator bool() const { return success; }

    operator LoadOptionId() const { return value; }
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

DWORD getUEFIVar(const char *varName, void *buffer, size_t bufferLength, bool required = true) {
    DWORD length = GetFirmwareEnvironmentVariableA(varName, EFI_GLOBAL_VARIABLE_GUID, buffer, bufferLength);
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

bool setUEFIVar(const char *varName, void *buffer, size_t bufferLength, bool required = false) {
    if (!SetFirmwareEnvironmentVariableA(varName, EFI_GLOBAL_VARIABLE_GUID, buffer, bufferLength)) {
        DWORD err = GetLastError();
        if (err == ERROR_ENVVAR_NOT_FOUND) {
            if (required) {
                cerr << "SetFirmwareEnvironmentVariable failed because the variable was not found." << endl;
                return false;
            }
        } else {
            cerr << "SetFirmwareEnvironmentVariable failed with error code: " << err << endl;
            return false;
        }
    }
    return true;
}

string optionNameFromId(LoadOptionId i) {
    stringstream s;
    s << "Boot" << hex << setw(4) << setfill('0') << uppercase << i;
    return s.str();
}

void dumpBootNext() {
    LoadOptionId bootNextId;
    DWORD bootNextLength = getUEFIVar("BootNext", &bootNextId, sizeof(bootNextId), false);
    string bootNextOption = bootNextLength == sizeof(bootNextId) ? optionNameFromId(bootNextId) : "(not set)";
    cout << "BootNext: " << bootNextOption << endl;
}

int dumpBootOrder() {
    LoadOptionId bootOrder[MAX_LOAD_OPTIONS];
    uint8_t loadOptionBuffer[1024];

    DWORD bootOrderLength = getUEFIVar("BootOrder", bootOrder, sizeof(bootOrder));
    if (bootOrderLength == 0) {
        return 12;
    }

    cout << "BootOrder:\n";
    for (auto e : bootOrder | views::take(bootOrderLength / sizeof(bootOrder[0]))) {
        string optionName = optionNameFromId(e);
        DWORD len = getUEFIVar(optionName.c_str(), loadOptionBuffer, sizeof(loadOptionBuffer));
        if (len == 0) {
            return 13;
        }
        LoadOption *option = (LoadOption *)loadOptionBuffer;
        cout << optionName << ": ";
        wcout << option->description << endl;
    }

    dumpBootNext();
    return 0;
}

int clearBootNext() {
    bool rc = setUEFIVar("BootNext", nullptr, 0);
    return rc ? 0 : 21;
}

int setBootNext(LoadOptionId id) {
    bool rc = setUEFIVar("BootNext", &id, sizeof(id), true);
    return rc ? 0 : 31;
}

bool checkArgCount(const char *operation, int argc, int min, int max) {
    if (argc > max) {
        cerr << "Too many arguments to '" << operation << "' operation." << endl;
        return false;
    } else if (argc < min) {
        cerr << "Not enough arguments to '" << operation << "' operation." << endl;
        return false;
    }
    return true;
}

int mainNoPause(int argc, char *argv[]) {
    if (!enablePrivilege()) {
        DWORD err = GetLastError();
        // When run without admin privileges the required system privilege doesn't exist but no error code is set.
        if (err == ERROR_SUCCESS) {
            cerr << "This program must be run with administrator privileges." << endl;
        } else {
            cerr << "Failed to enable privilege with error code: " << err << endl;
        }
        return 1;
    }

    const char *operation = argc > 1 ? argv[1] : "list";
    if (!strcmp(operation, "list")) {
        checkArgCount(operation, argc, 0, 2);
        return dumpBootOrder();
    } else if (!strcmp(operation, "clear")) {
        checkArgCount(operation, argc, 0, 2);
        int rc = dumpBootOrder();
        if (rc != 0) {
            cerr << "Failed to read BootOrder, not clearing BootNext." << endl;
            return rc;
        }
        rc = clearBootNext();
        if (rc == ERROR_SUCCESS) {
            cout << "- Cleared BootNext -" << endl;
            dumpBootNext();
        }
        return rc;
    } else if (!strcmp(operation, "set")) {
        if (!checkArgCount(operation, argc, 3, 3)) {
            return 3;
        }
        cerr << "Will parse\n";
        LoadOptionParseResult parseResult(argv[2]);
        if (!parseResult) {
            return 4;
        }
        if (dumpBootOrder() != 0) {
            cerr << "Failed to read BootOrder, not setting BootNext." << endl;
            return 5;
        }
        int rc = setBootNext(parseResult);
        if (rc == ERROR_SUCCESS) {
            cout << "- Set BootNext to " << argv[2] << " -" << endl;
            dumpBootNext();
        }
        return rc;
    } else if (!strcmp(operation, "help")) {
        cout << "Usage: " << argv[0] << " [operation]\n\n"
             << "Operations:\n"
             << "  list                List current BootOrder and BootNext variables (default).\n"
             << "  clear               Clear BootNext variable.\n"
             << "  set <option_id>     Set BootNext to the specified load option ID (hex value, e.g. 0001).\n"
             << "  help                Show this help message." << endl;
        return 0;
    } else {
        cerr << "Unknown operation: " << operation << endl;
        return 10;
    }
}

int main(int argc, char *argv[]) {
    int r = mainNoPause(argc, argv);
    system("pause");
    return r;
}
