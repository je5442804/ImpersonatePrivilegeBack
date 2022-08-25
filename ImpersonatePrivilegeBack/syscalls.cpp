#define UMDF_USING_NTSTATUS
#include "syscalls.hpp"
#include "structs.hpp"
#include <stdio.h>

#define JUMPER

SW3_SYSCALL_LIST SW3_SyscallList;

PVOID BaseStaticServerData;
ULONG KernelBaseGlobalData;
USHORT OSBuildNumber;


PVOID Ntdll;
PVOID Kernel32;
PVOID KernelBase;

DWORD SW3_HashSyscall(PCSTR FunctionName)
{
	DWORD i = 0;
	DWORD Hash = SW3_SEED;

	while (FunctionName[i])
	{
		WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
		Hash ^= PartialName + SW3_ROR8(Hash);
	}

	return Hash;
}

PVOID SC(PVOID NtApiAddress)
{
	DWORD searchLimit = 512;
	PVOID SyscallAddress;
	BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
	ULONG distance_to_syscall = 0x12;
	if (OSBuildNumber != 0 && OSBuildNumber < 10586) //Beta 10525
	{
		distance_to_syscall = 0x08;
	}
	// we don't really care if there is a 'jmp' between
	// NtApiAddress and the 'syscall; ret' instructions
	SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

	if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
	{
		// we can use the original code for this system call :)
		return SyscallAddress;
	}
	// the 'syscall; ret' intructions have not been found,
	// we will try to use one near it, similarly to HalosGate
	for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
	{
		// let's try with an Nt* API below our syscall
		SyscallAddress = SW3_RVA2VA(
			PVOID,
			NtApiAddress,
			distance_to_syscall + num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
			return SyscallAddress;
		}

		// let's try with an Nt* API above our syscall
		SyscallAddress = SW3_RVA2VA(
			PVOID,
			NtApiAddress,
			distance_to_syscall - num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
			return SyscallAddress;
		}
	}
	return NULL;
}

BOOL SW3_PopulateSyscallList()
{
	// Return early if the list is already populated.
	if (SW3_SyscallList.Count) return TRUE;
	PPEB Peb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA Ldr = Peb->Ldr;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectoryNtdll = NULL;
	PVOID DllBase = NULL;
	//PVOID ntdll = 0;
	// Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
	// in the list, so it's safer to loop through the full list and find it.
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	DWORD SizeOfNtdll = 0;
	//PVOID Kernel32 = 0;
	DWORD SizeofKernel32 = 0;
	//PVOID KernelBase = 0;
	DWORD SizeofKernelBase = 0;
	for (LdrEntry = (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink; LdrEntry->DllBase != NULL; LdrEntry = (PLDR_DATA_TABLE_ENTRY)LdrEntry->InLoadOrderLinks.Flink)
	{
		DllBase = LdrEntry->DllBase;
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
		PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
		PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;

		DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (VirtualAddress == 0) continue;

		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
		// If this is NTDLL.dll, exit loop.
		PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

		if ((*(ULONG*)DllName | 0x20202020) == 'nrek')
		{
			if ((*(ULONG*)(DllName + 4) | 0x20202020) == '23le')
			{
				//wprintf(L"OK Kernel32: %p\n", DllBase);
				Kernel32 = DllBase;
				SizeofKernel32 = NtHeaders->OptionalHeader.SizeOfImage;
			}
			if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'able')
			{
				//wprintf(L"OK KernelBase: %p\n", DllBase);
				KernelBase = DllBase;
				SizeofKernelBase = NtHeaders->OptionalHeader.SizeOfImage;
			}
		}
		if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
		if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c)
		{
			//wprintf(L"OK Ntdll: %p\n", DllBase);
			Ntdll = DllBase;
			SizeOfNtdll = NtHeaders->OptionalHeader.SizeOfImage;
			ExportDirectoryNtdll = ExportDirectory;
		}
	}
	DllBase = 0;
	ExportDirectory = ExportDirectoryNtdll;
	if (!ExportDirectory)
		return FALSE;
	OSBuildNumber = Peb->OSBuildNumber;

	//GetGloablVariable(Ntdll, SizeOfNtdll, Kernel32, SizeofKernel32, KernelBase, SizeofKernelBase);
	//GetUnexportFunction(KernelBase, SizeofKernelBase);
	DWORD NumberOfNames = ExportDirectory->NumberOfNames;
	PDWORD Functions = SW3_RVA2VA(PDWORD, Ntdll, ExportDirectory->AddressOfFunctions);
	PDWORD Names = SW3_RVA2VA(PDWORD, Ntdll, ExportDirectory->AddressOfNames);
	PWORD Ordinals = SW3_RVA2VA(PWORD, Ntdll, ExportDirectory->AddressOfNameOrdinals);

	// Populate SW3_SyscallList with unsorted Zw* entries.
	DWORD i = 0;
	PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;

	do
	{
		PCHAR FunctionName = SW3_RVA2VA(PCHAR, Ntdll, Names[NumberOfNames - 1]);

		// Is this a system call?
		if (*(USHORT*)FunctionName == 0x775a)
		{
			Entries[i].Hash = SW3_HashSyscall(FunctionName);
			Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
			Entries[i].SyscallAddress = SC(SW3_RVA2VA(PVOID, Ntdll, Entries[i].Address));

			i++;
			if (i == SW3_MAX_ENTRIES) break;
		}
	} while (--NumberOfNames);

	// Save total number of system calls found.
	SW3_SyscallList.Count = i;

	// Sort the list by address in ascending order.
	for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
	{
		for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
		{
			if (Entries[j].Address > Entries[j + 1].Address)
			{
				// Swap entries.
				SW3_SYSCALL_ENTRY TempEntry;

				TempEntry.Hash = Entries[j].Hash;
				TempEntry.Address = Entries[j].Address;
				TempEntry.SyscallAddress = Entries[j].SyscallAddress;

				Entries[j].Hash = Entries[j + 1].Hash;
				Entries[j].Address = Entries[j + 1].Address;
				Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

				Entries[j + 1].Hash = TempEntry.Hash;
				Entries[j + 1].Address = TempEntry.Address;
				Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
			}
		}
	}

	return TRUE;
}
EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
	// Ensure SW3_SyscallList is populated.
	if (!SW3_PopulateSyscallList()) return -1;

	for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
	{
		if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
		{
			return i;
		}
	}

	return -1;
}
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
	// Ensure SW3_SyscallList is populated.
	if (!SW3_PopulateSyscallList()) return NULL;

	for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
	{
		if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
		{
			return SW3_SyscallList.Entries[i].SyscallAddress;
		}
	}

	return NULL;
}
EXTERN_C PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash)
{
	// Ensure SW3_SyscallList is populated.
	if (!SW3_PopulateSyscallList()) return NULL;

	DWORD index = ((DWORD)rand()) % SW3_SyscallList.Count;

	while (FunctionHash == SW3_SyscallList.Entries[index].Hash) {
		// Spoofing the syscall return address
		index = ((DWORD)rand()) % SW3_SyscallList.Count;
	}
	return SW3_SyscallList.Entries[index].SyscallAddress;
}
