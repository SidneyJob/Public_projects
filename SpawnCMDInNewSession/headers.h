#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <UserEnv.h>
#include <Wtsapi32.h>
#include <sddl.h>
#include <psapi.h>

#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Wtsapi32.lib")


typedef struct
{
	DWORD origSessionID;
	HANDLE hUser;
	bool bPreped;
}CleanupInteractive;


void Duplicate(HANDLE *h);
DWORD GetInteractiveSessionID();


