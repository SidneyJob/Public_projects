#include <Windows.h>
#include <UserEnv.h>
#include <Wtsapi32.h>
#include <sddl.h>
#include <psapi.h>
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#include <atlstr.h>
#include <vector>
#include <stdio.h>

#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Wtsapi32.lib")

bool InitializeWrapper();

typedef struct
{
	DWORD origSessionID;
	HANDLE hUser;
	bool bPreped;
}CleanupInteractive;

bool EnablePrivilege(LPCWSTR privilegeStr, HANDLE hToken = NULL)
{
	TOKEN_PRIVILEGES  tp;         // token privileges
	LUID              luid;
	bool				bCloseToken = false;

	if (NULL == hToken)
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			return false;
		}
		bCloseToken = true;
	}

	if (!LookupPrivilegeValue(NULL, privilegeStr, &luid))
	{
		if (bCloseToken)
			CloseHandle(hToken);
		return false;
	}

	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Adjust Token privileges
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		DWORD gle = GetLastError();
		if (bCloseToken)
			CloseHandle(hToken);
		return false;
	}
	if (bCloseToken)
		CloseHandle(hToken);

	return true;
}

void Duplicate(HANDLE& h)
{
	HANDLE hDupe = NULL;
	if (DuplicateTokenEx(h, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupe))
	{
		CloseHandle(h);
		h = hDupe;
	}
}

DWORD GetInteractiveSessionID()
{
	// Get the active session ID.
	DWORD   SessionId = 0;
	PWTS_SESSION_INFO pSessionInfo;
	DWORD   Count = 0;

	if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &Count))
	{
		for (DWORD i = 0; i < Count; i++)
		{
			if (pSessionInfo[i].State == WTSActive){ // Here is
				SessionId = pSessionInfo[i].SessionId;
			}
		}
		WTSFreeMemory(pSessionInfo);
	}

	if (SessionId == 0)
		return WTSGetActiveConsoleSessionId();
	return SessionId;
}

BOOL PrepForInteractiveProcess(HANDLE& hUser, CleanupInteractive* pCI)
{
	pCI->bPreped = true;
	Duplicate(hUser);
	pCI->hUser = hUser;
	DWORD targetSessionID = GetInteractiveSessionID();

	DWORD returnedLen = 0;
	GetTokenInformation(hUser, TokenSessionId, &pCI->origSessionID, sizeof(pCI->origSessionID), &returnedLen);
	EnablePrivilege(SE_TCB_NAME, hUser);
	SetTokenInformation(hUser, TokenSessionId, &targetSessionID, sizeof(targetSessionID));
	return TRUE;
}

bool ElevateUserToken(HANDLE& hEnvUser)
{
	TOKEN_ELEVATION_TYPE tet;
	DWORD needed = 0;
	DWORD gle = 0;

	if (GetTokenInformation(hEnvUser, TokenElevationType, (LPVOID)&tet, sizeof(tet), &needed))
	{
		if (tet == TokenElevationTypeLimited)
		{
			//get the associated token, which is the full-admin token
			TOKEN_LINKED_TOKEN tlt = { 0 };
			if (GetTokenInformation(hEnvUser, TokenLinkedToken, (LPVOID)&tlt, sizeof(tlt), &needed))
			{
				Duplicate(tlt.LinkedToken);
				hEnvUser = tlt.LinkedToken;
				return true;
			}
			else
			{
				gle = GetLastError();
				return false;
			}
		}
		else
			return true;
	}
	else
	{
		//can't tell if it's elevated or not -- continue anyway

		gle = GetLastError();
		switch (gle)
		{
		case ERROR_INVALID_PARAMETER: //expected on 32-bit XP
		case ERROR_INVALID_FUNCTION: //expected on 64-bit XP
			break;
		default:
			break;
		}

		return true;
	}
}

CString GetTokenUserSID(HANDLE hToken)
{
	DWORD tmp = 0;
	CString userName;
	DWORD sidNameSize = 64;
	std::vector<WCHAR> sidName;
	sidName.resize(sidNameSize);

	DWORD sidDomainSize = 64;
	std::vector<WCHAR> sidDomain;
	sidDomain.resize(sidNameSize);

	DWORD userTokenSize = 1024;
	std::vector<WCHAR> tokenUserBuf;
	tokenUserBuf.resize(userTokenSize);

	TOKEN_USER* userToken = (TOKEN_USER*)&tokenUserBuf.front();

	if (GetTokenInformation(hToken, TokenUser, userToken, userTokenSize, &tmp))
	{
		WCHAR* pSidString = NULL;
		if (ConvertSidToStringSid(userToken->User.Sid, &pSidString))
			userName = pSidString;
		if (NULL != pSidString)
			LocalFree(pSidString);
	}
	else
		_ASSERT(0);

	return userName;
}
HANDLE GetLocalSystemProcessToken()
{
	DWORD pids[1024 * 10] = { 0 }, cbNeeded = 0, cProcesses = 0;

	if (!EnumProcesses(pids, sizeof(pids), &cbNeeded)){
		return NULL;
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);
	for (DWORD i = 0; i < cProcesses; ++i)
	{
		DWORD gle = 0;
		DWORD dwPid = pids[i];
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
		if (hProcess)
		{
			HANDLE hToken = 0;
			if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_EXECUTE, &hToken))
			{
				try
				{
					CString name = GetTokenUserSID(hToken);

					//const wchar_t arg[] = L"NT AUTHORITY\\";
					//if(0 == _wcsnicmp(name, arg, sizeof(arg)/sizeof(arg[0])-1))

					if (name == L"S-1-5-18") //Well known SID for Local System
					{
						CloseHandle(hProcess);
						return hToken;
					}
				}
				catch (...)
				{
					return NULL;
				}
			}
			else
				gle = GetLastError();
			CloseHandle(hToken);
		}
		else
			gle = GetLastError();
		CloseHandle(hProcess);
	}
	return NULL;
}
bool StartProcess(LPWSTR proc, LPWSTR startingDir)
{
	EnablePrivilege(SE_DEBUG_NAME);
	HANDLE hUser = GetLocalSystemProcessToken();

	Duplicate(hUser);

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	DWORD launchGLE = 0;

	CleanupInteractive ci = { 0 };
	PrepForInteractiveProcess(hUser, &ci);
	si.lpDesktop = (LPWSTR)L"WinSta0\\Default";

	DWORD dwFlags = CREATE_NEW_CONSOLE;

	LPVOID pEnvironment = NULL;
	SetLastError(0);
	BOOL b = CreateEnvironmentBlock(&pEnvironment, hUser, TRUE);
	if (NULL != pEnvironment)
		dwFlags |= CREATE_UNICODE_ENVIRONMENT;

	EnablePrivilege(SE_IMPERSONATE_NAME);
	ImpersonateLoggedOnUser(hUser);

	EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
	EnablePrivilege(SE_INCREASE_QUOTA_NAME);
	DWORD l = (wcslen(proc) + 1) * sizeof(WCHAR);
	PWCHAR ch_proc = (PWCHAR)malloc(l);
	memcpy(ch_proc, proc, l);

	CreateProcessAsUser(hUser, NULL, ch_proc, NULL, NULL, TRUE, dwFlags, pEnvironment, startingDir, &si, &pi);

	if (ci.bPreped)
		SetTokenInformation(ci.hUser, TokenSessionId, &ci.origSessionID, sizeof(ci.origSessionID));
	if (NULL != pEnvironment)
		DestroyEnvironmentBlock(pEnvironment);
	pEnvironment = NULL;
	if (hUser)
	{
		CloseHandle(hUser);
		hUser = NULL;
	}

	return true;
}
int main() {
	StartProcess((LPWSTR)L"C:\\Windows\\System32\\cmd.exe", NULL);
	return 0;
}