#include "windows.h"
#include "tchar.h"
#include <stdio.h>
#include<tlhelp32.h>
#include <conio.h>

#define REG_SUB_KEY L"injection"
#define MAX_SIZE 150

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) 
{
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    if( !OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
			              &hToken) )
    {
        _tprintf(L"OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if( !LookupPrivilegeValue(NULL,           // lookup privilege on local system
                              lpszPrivilege,  // privilege to lookup 
                              &luid) )        // receives LUID of privilege
    {
        _tprintf(L"LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if( bEnablePrivilege )
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if( !AdjustTokenPrivileges(hToken, 
                               FALSE, 
                               &tp, 
                               sizeof(TOKEN_PRIVILEGES), 
                               (PTOKEN_PRIVILEGES) NULL, 
                               (PDWORD) NULL) )
    { 
        _tprintf(L"AdjustTokenPrivileges error: %u\n", GetLastError() ); 
        return FALSE; 
    } 

    if( GetLastError() == ERROR_NOT_ALL_ASSIGNED )
    {
        _tprintf(L"The token does not have the specified privilege. \n");
        return FALSE;
    } 

    return TRUE;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	TCHAR szPath[_MAX_PATH] = { 0, };

	if (!GetModuleFileName(nullptr, szPath, MAX_PATH))
		return FALSE;

	TCHAR *p = _tcsrchr(szPath, '\\');
	if (!p)
		return FALSE;

	_tcscpy_s(p + 1, 50, szDllPath);
	_tprintf(L"%s\n", szPath);
	
    HANDLE hProcess = NULL, hThread = NULL;
    HMODULE hMod = NULL;
    LPVOID pRemoteBuf = NULL;
    DWORD dwBufSize = (DWORD)(_tcslen(szPath) + 1) * sizeof(TCHAR);
    LPTHREAD_START_ROUTINE pThreadProc;

    // #1. dwPID 를 이용하여 대상 프로세스(notepad.exe)의 HANDLE을 구한다.
    if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
    {
        _tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
        return FALSE;
    }

    // #2. 대상 프로세스(notepad.exe) 메모리에 szDllName 크기만큼 메모리를 할당한다.
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

    // #3. 할당 받은 메모리에 myhack.dll 경로("c:\\myhack.dll")를 쓴다.
    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szPath, dwBufSize, NULL);

    // #4. LoadLibraryA() API 주소를 구한다.
    hMod = GetModuleHandle(L"kernel32.dll");
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
	
    // #5. notepad.exe 프로세스에 스레드를 실행
    hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);	

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllName)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	LPTHREAD_START_ROUTINE pThreadProc;

	// dwPID = notepad 프로세스 ID
	// TH32CS_SNAPMODULE 파라미터를 이용해서 notepad 프로세스에 로딩된 DLL 이름을 얻음
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
	//	_tprintf(L"%s %s\n", me.szModule, me.szExePath);
		if (!_tcsicmp((LPCTSTR)me.szModule, szDllName) ||
			!_tcsicmp((LPCTSTR)me.szExePath, szDllName))
		{
			bFound = TRUE;
			break;
		}
	}

	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		return FALSE;
	}

	hModule = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		pThreadProc, me.modBaseAddr,
		0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}

int wstrcmp(LPCWSTR string1, LPCWSTR string2) {

	while (*string1 && *string2)
	{
		if(isascii(*string1) && isascii(*string2)){
			if (tolower((char)*string1) != tolower((char)*string2))
			return 1;
		}
		else {
			if (*string1 != *string2)
				return 1;
		}
		string1++;
		string2++;
	}

	return 0;

}

WORD FindProcessId(const wchar_t *processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

										  // Retrieve information about the first process,
										  // and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		OutputDebugString(L"!!! Failed to gather information on system processes! \n");
		return(NULL);
	}

	do
	{
		if (wcschr(processname,L'.') == NULL) {
			WCHAR * sc = wcschr(pe32.szExeFile, L'.');
			sc = '\0';
			if (0 == wstrcmp(processname, pe32.szExeFile))
			{
				result = pe32.th32ProcessID;
				break;
			}
		}
		else {
			//printf("Checking process %ls\n", pe32.szExeFile);
			if (0 == wstrcmp(processname, pe32.szExeFile))
			{
				result = pe32.th32ProcessID;
				break;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}

int SetRegStr(HKEY hKeyRoot, LPCWSTR SubKey, LPCWSTR ValueName, LPCWSTR ValueStr)
{
	int  Rslt;
	HKEY hKey;

	if ((Rslt = RegOpenKey(hKeyRoot, SubKey, &hKey)) != ERROR_SUCCESS)
		Rslt = RegCreateKey(hKeyRoot, SubKey, &hKey);

	if (Rslt == ERROR_SUCCESS)
	{
		RegSetValueEx(hKey, ValueName, 0, REG_SZ, (BYTE*)ValueStr, lstrlen(ValueStr) * 2);
		RegCloseKey(hKey);
	}
	return Rslt == ERROR_SUCCESS;
}

int GetRegStr(HKEY hKeyRoot, LPCWSTR SubKey, LPCWSTR ValueName, LPWSTR Buff, DWORD BuffSize)
{
	BOOL  Rslt = FALSE;
	HKEY  hKey;

	if (RegOpenKey(hKeyRoot, SubKey, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hKey, ValueName, NULL, NULL, (LPBYTE)Buff, &BuffSize) == ERROR_SUCCESS)
			Rslt = TRUE;
		RegCloseKey(hKey);
	}
	return Rslt;
}

int _tmain(int argc, TCHAR *argv[])
{
	TCHAR fPath[MAX_SIZE];

	if (argc != 7)
	{
		_tprintf(L"%s <processname> <dllFile> <message> <autosave> <unicode/mulitbyte> <messagekey>", wcsrchr(argv[0], L'\\') + 1);
		getchar();
		return -1;
	}

	if (wstrcmp(argv[5], L"unicode") && wstrcmp(argv[5], L"mulitbyte")) {
		_tprintf(L"%s <processname> <dllFile> <message> <autosave> <unicode/mulitbyte> <messagekey>", wcsrchr(argv[0], L'\\') + 1);
		getchar();
		return -1;
	}

	if (lstrlenW(argv[3]) > MAX_SIZE) {
		_tprintf(L"Error : Out of range [message is max %d]",MAX_SIZE);
		getchar();
		return -1;
	}

	int pid = FindProcessId(argv[1]);

	_tprintf(L"Process : %s \nPid : %d\nInjection dll : %s\n", argv[1], pid, argv[2]);

	SetRegStr(HKEY_CURRENT_USER, REG_SUB_KEY, L"processname", argv[1]);
	SetRegStr(HKEY_CURRENT_USER, REG_SUB_KEY, L"message", argv[3]);
	SetRegStr(HKEY_CURRENT_USER, REG_SUB_KEY, L"autosave", argv[4]);
	SetRegStr(HKEY_CURRENT_USER, REG_SUB_KEY, L"lang", argv[5]);
	SetRegStr(HKEY_CURRENT_USER, REG_SUB_KEY, L"messagekey", argv[6]);
	SetRegStr(HKEY_CURRENT_USER, REG_SUB_KEY, L"finish", L"false");

	if (!SetPrivilege(SE_DEBUG_NAME, TRUE)) return 1;

	if (InjectDll(pid, argv[2])) {
		_tprintf(L">> InjectDll success!!!\n");
		/*
		TODO : 현방식은 레지스트리 비교 -> 소켓통신으로 대체
		*/

		_tprintf(L">> Press any Key...");
		while (1) {
			getch();
			if (!SetPrivilege(SE_DEBUG_NAME, TRUE)) return 1;
			SetRegStr(HKEY_CURRENT_USER, REG_SUB_KEY, L"finish", L"true");

			TCHAR type[10];
			while (1) {
				GetRegStr(HKEY_CURRENT_USER, L"injection", L"finish", type, sizeof(type));

				if (wstrcmp(L"finish", type) == 0) {
					_tprintf(L"\n>>  \"%s\" ThreadProc is Finish!!!\n", argv[2]);
					break;
				}
			}
			// eject dll
			if (EjectDll(pid, argv[2]))
				_tprintf(L">> EjectDll(%d, \"%s\") success!!!\n", pid, argv[2]);
			else
				_tprintf(L">> EjectDll(%d, \"%s\") failed!!!\n", pid, argv[2]);
			break;

		}
	}
	else 
		_tprintf(L">> InjectDll failed!!!\n");

	


	_tprintf(L">> Press any Key...");
	getch();
	
    return 0;
}