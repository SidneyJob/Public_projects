#include "headers.h"

bool LaunchProcess(const char *process_path){
	LUID seCreateSymbolicLinkPrivilege;
	
	PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
	CleanupInteractive ci = { 0 };
	TOKEN_MANDATORY_LABEL til = { 0 };
	CHAR lowIntegrityLevelSid[20] = "S-1-16-4096";
	PSID integritySid = NULL;
	
	HANDLE token = NULL;
	HANDLE newtoken = NULL;
	
	HANDLE hProcess = GetCurrentProcess();
	OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &token);
	DuplicateTokenEx(token,0,NULL,SecurityImpersonation, TokenPrimary, &newtoken);
	
	printf("[+] Token of process: %d\n",token);
	printf("[+] Primary token is %d\n",newtoken);
	

	ConvertStringSidToSid(lowIntegrityLevelSid, &integritySid);
    til.Label.Attributes = SE_GROUP_INTEGRITY;
    til.Label.Sid = integritySid;
	
	SetTokenInformation(newtoken, TokenIntegrityLevel, &til, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(integritySid));
	CreateProcessAsUser(newtoken, NULL, (LPSTR)process_path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	
	
	
	
	
    if (LookupPrivilegeValue(NULL, SE_CREATE_SYMBOLIC_LINK_NAME, &seCreateSymbolicLinkPrivilege)){
		DWORD length;
		printf("[+] SeCreateSymbolicLinkPrivilege = %ld, %ld\n", seCreateSymbolicLinkPrivilege.HighPart, seCreateSymbolicLinkPrivilege.LowPart);
	    if (!GetTokenInformation(token, TokenPrivileges, NULL, 0, &length)){
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER){
				TOKEN_PRIVILEGES* privileges = (TOKEN_PRIVILEGES*)malloc(length);
				if (GetTokenInformation(token, TokenPrivileges, privileges, length, &length)){
					BOOL found = FALSE;
					DWORD count = privileges->PrivilegeCount;
					printf("[+] User has %ld privileges\n", count);	
	}}}}

}
int main(void){
	int sessionid;
	
	
	sessionid = GetInteractiveSessionID();
	printf("\n[+] IneractiveSessionID:  %d\n",sessionid);
	//printf("[*]Calling process...\n");
	LaunchProcess("cmd.exe");
	//printf("[+]Proccess was called!\n");
	
	
	
	printf("\n"); return 0;
}