#pragma once

#include "structs.hpp"
#include <ntstatus.h>
//#define DEBUG_PRINT

#ifdef DEBUG_PRINT

#define dprintf(...) wprintf(__VA_ARGS__)

#else

#define dprintf(...) do{}while(0);

#endif // DEBUG_PRINT


typedef _Null_terminated_ wchar_t* NTSTRSAFE_PWSTR;

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess() NtCurrentProcess()
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread() NtCurrentThread()
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define ZwCurrentSession() NtCurrentSession()
#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#define RtlProcessHeap() (NtCurrentPeb()->ProcessHeap)

// Windows 8 and above
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5) // NtOpenThreadToken(NtCurrentThread())
#define NtCurrentThreadEffectiveToken() ((HANDLE)(LONG_PTR)-6) // NtOpenThreadToken(NtCurrentThread()) + NtOpenProcessToken(NtCurrentProcess())


ULONGLONG RandomNumber();
void GenRandomString(wchar_t* s, const int len);
BOOL IsTokenElevatedLimited(HANDLE hToken);
BOOL IsTokenImpersonatePrivilege(HANDLE hToken);
BOOL IsTokenServiceAccount(HANDLE hToken);
BOOL ImpersonatePrivilegeBack();


#define KI_USER_SHARED_DATA 0x7FFE0000
#define SharedUserData  ((KUSER_SHARED_DATA * const) KI_USER_SHARED_DATA)
//#define GetCurrentTickCount() ((DWORD)((SharedUserData->TickCountMultiplier * (ULONGLONG)SharedUserData->TickCount.LowPart) >> 24))


typedef VOID(NTAPI* RtlInitUnicodeString_)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(WINAPI* RtlDefaultNpAcl_)(OUT PACL* pACL);