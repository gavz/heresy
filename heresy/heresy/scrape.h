#pragma once

#include "section.h"

typedef NTSTATUS(NTAPI * ZW_QUERY_SECTION)(HANDLE, SECTION_INFORMATION_CLASS, PVOID, ULONG, PULONG);

NTSTATUS NTAPI GetNtdllBaseAddressFromKnownDlls(
	_In_ ZW_QUERY_SECTION __ZwQuerySection,
	_Out_ PVOID *OutAddress
);

NTSTATUS NTAPI FindSyscallOpcodeFromNtdll(
	_In_ PVOID NtDllBaseAddress,
	_In_ PCCH SyscallName,
	_Out_ PUINT32 OutOpcode
);

NTSTATUS NTAPI CreateSyscallStub(
	_In_ PUCHAR StartAddress,
	_In_ DWORD32 SyscallOpcode,
	_In_ ULONG PoolTag,
	_Out_ PVOID *OutPtr
);

#define OPCODE_NOT_FOUND 0xFFFFFFFF

static inline
UINT32 GetHeresyNtdllOpcode(
	PCCH NtDllFunctionName
)
{
	static UNICODE_STRING ZwQuerySectionName = RTL_CONSTANT_STRING(L"ZwQuerySection");
	static ZW_QUERY_SECTION __ZwQuerySection = NULL;
	
	static PVOID NtdllBase = NULL;

	NTSTATUS Status = STATUS_SUCCESS;

	if (__ZwQuerySection == NULL)
	{
		__ZwQuerySection = (ZW_QUERY_SECTION)MmGetSystemRoutineAddress(&ZwQuerySectionName);

		if (__ZwQuerySection == NULL)
		{
			return OPCODE_NOT_FOUND;
		}
	}


	if (NtdllBase == NULL)
	{
		Status = GetNtdllBaseAddressFromKnownDlls(__ZwQuerySection, &NtdllBase);

		if (!NT_SUCCESS(Status) || NtdllBase == NULL)
		{
			return OPCODE_NOT_FOUND;
		}
	}

	ULONG32 OpCode;

	Status = FindSyscallOpcodeFromNtdll(NtdllBase, NtDllFunctionName, &OpCode);

	if (!NT_SUCCESS(Status))
	{
		return OPCODE_NOT_FOUND;
	}

	return OpCode;
}

static inline
PVOID NTAPI MakeHeresyZwStubFromNtdllExport(
	PUCHAR RealZwAddress,
	PCCH NtDllFunctionName,
	UINT32 PoolTag
)
{
	PVOID Func = NULL;

	UINT32 Opcode = GetHeresyNtdllOpcode(NtDllFunctionName);

	if (Opcode == OPCODE_NOT_FOUND)
	{
		return NULL;
	}

	NTSTATUS Status = CreateSyscallStub(RealZwAddress, Opcode, PoolTag, &Func);

	if (!NT_SUCCESS(Status))
	{
		return NULL;
	}

	return Func;
}
