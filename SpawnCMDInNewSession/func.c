#include "headers.h"

void Duplicate(HANDLE *h){
	HANDLE hDupe = NULL;
	if (DuplicateTokenEx(h, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupe))
	{
		CloseHandle(h);
		h = hDupe;
		hDupe = NULL;
	}
}

DWORD GetInteractiveSessionID(){
	// Get the active session ID.
	DWORD   SessionId = 0;
	PWTS_SESSION_INFO pSessionInfo;
	DWORD   Count = 0;

	if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &Count))
	{
		for (DWORD i = 0; i < Count; i++)
		{
			if (pSessionInfo[i].State == WTSActive)	//Here is
			{
				SessionId = pSessionInfo[i].SessionId;
			}
		}
		WTSFreeMemory(pSessionInfo);
	}

	if (SessionId == 0)
		return WTSGetActiveConsoleSessionId();
	return SessionId;
}

