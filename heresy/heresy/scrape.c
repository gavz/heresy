#include <ntddk.h>

#include "scrape.h"
#include "bytescan.h"
#include "getproc.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text( PAGE, FindSyscallOpcodeFromNtdll )
#pragma alloc_text( PAGE, GetNtdllBaseAddressFromKnownDlls )
#pragma alloc_text( PAGE, CreateSyscallStub )
#endif

NTSTATUS NTAPI FindSyscallOpcodeFromNtdll(
	_In_ PVOID NtDllBaseAddress,
	_In_ PCCH SyscallName,
	_Out_ PUINT32 OutOpcode
)
{
	FARPROC SyscallAddress = KernelGetProcAddress(NtDllBaseAddress, SyscallName);

	if (SyscallAddress == NULL)
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	CHAR WildCardByte = '\xff';

	//  b8 ?? ?? 00 00		mov eax, 0x0000????
	UCHAR ScanMask[] = "\xb8\xff\xff\x00\x00";	

	SIZE_T ScanMaskSize = sizeof(ScanMask) - 1;
	SIZE_T ScanSize = 20;

	PUCHAR EndAddress = NULL;

	NTSTATUS Status = ByteScanMask(
		SyscallAddress,
		ScanSize,
		ScanMask,
		ScanMaskSize,
		WildCardByte,
		&EndAddress
	);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	*OutOpcode = *(PUINT32)((PUCHAR)EndAddress - 4);

	return Status;
}

NTSTATUS NTAPI GetNtdllBaseAddressFromKnownDlls(
	_In_ ZW_QUERY_SECTION __ZwQuerySection,
	_Out_ PVOID *OutAddress
)
{
	static UNICODE_STRING KnownDllsNtdllName = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");

	NTSTATUS Status = STATUS_SUCCESS;

	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(
		&ObjectAttributes, 
		&KnownDllsNtdllName, 
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
		0, 
		NULL
	);

	HANDLE SectionHandle = NULL;

	Status = ZwOpenSection(&SectionHandle, SECTION_QUERY, &ObjectAttributes);

	if (NT_SUCCESS(Status))
	{
		// +0x1000 because kernel only checks min size
		UCHAR SectionInfo[sizeof(SECTION_IMAGE_INFORMATION) + 0x1000]; 

		Status = __ZwQuerySection(
			SectionHandle,
			SectionImageInformation,
			&SectionInfo, 
			sizeof(SectionInfo), 
			0
		);

		if (NT_SUCCESS(Status))
		{
			*OutAddress = ((SECTION_IMAGE_INFORMATION*)&SectionInfo)->TransferAddress;
		}

		ZwClose(SectionHandle);
	}

	return Status;
}

static inline NTSTATUS ScanForKiServiceLinkage(
	_In_ PUCHAR StartAddress,
	_In_ SIZE_T ScanSize,
	_Out_ PUCHAR* EndAddress,
	_Out_ PUCHAR* EndCopyAddress,
	_Out_ PUCHAR* Relative32Address
)
{
	UCHAR ScanMask[] =
		"\x50"							//	50						push    rax
		"\x9c"							//	9c						pushfq
		"\x6a\x10"						//	6a 10					push    10h
		"\x48\x8d\x05\x00\x00\x00\x00";	//  48 8d 05 ?? ?? ?? ??	lea     rax, [nt!KiServiceLinkage]

	SIZE_T ScanMaskSize = sizeof(ScanMask) - 1;
	CHAR WildCardByte = '\x00';

	NTSTATUS Status = ByteScanMask(
		StartAddress,
		ScanSize,
		ScanMask,
		ScanMaskSize,
		WildCardByte,
		EndAddress
	);

	*(UINT64*)EndCopyAddress = (UINT64)(*EndAddress - 7);
	*(UINT64*)Relative32Address = (UINT64)(*EndAddress - 4);

	return Status;
}

static inline NTSTATUS ScanForKiServiceInternal(
	_In_ PUCHAR StartAddress,
	_In_ SIZE_T ScanSize,
	_Out_ PUCHAR* EndAddress,
	_Out_ PUCHAR* EndCopyAddress,
	_Out_ PUCHAR* Relative32Address,
	_Out_ PUCHAR* OpcodeAddress
)
{
	UCHAR ScanMask[] =
		"\x50" 					    // 50                  push    rax
		"\xb8\x00\x00\x00\x00" 		// b8 ?? ?? ?? ??      mov     eax, ??
		"\xe9\x00\x00\x00\x00";		// e9 ?? ?? ?? ??      jmp     nt!KiServiceInternal

	SIZE_T ScanMaskSize = sizeof(ScanMask) - 1;
	CHAR WildCardByte = '\x00';

	NTSTATUS Status = ByteScanMask(
		StartAddress,
		ScanSize,
		ScanMask,
		ScanMaskSize,
		WildCardByte,
		EndAddress
	);


	*(UINT64*)EndCopyAddress = (UINT64)(*EndAddress - 5);
	*(UINT64*)Relative32Address = (UINT64)(*EndAddress - 4);
	*(UINT64*)OpcodeAddress = (UINT64)(*EndAddress - 9);

	return Status;
}

static inline
PVOID ConvertRelative32AddressToAbsoluteAddress(
	_In_reads_(4) PUINT32 Relative32StartAddress
)
{
	UINT32 Offset = *Relative32StartAddress;
	PUCHAR InstructionEndAddress = (PUCHAR)Relative32StartAddress + 4;

	return InstructionEndAddress + Offset;
}

NTSTATUS NTAPI CreateSyscallStub(
	_In_ PUCHAR KnownSyscall,
	_In_ UINT32 SyscallOpcode,
	_In_ ULONG PoolTag,
	_Out_ PVOID * OutPtr
)
{
	SIZE_T ScanSize = 0x100;

	PUCHAR LinkageEndAddress = NULL;
	PUCHAR LinkageCopyAddress = NULL;
	PUCHAR LinkageRelative32Address = NULL;

	PUCHAR StartAddress = KnownSyscall;

	NTSTATUS Status = ScanForKiServiceLinkage(
		StartAddress,
		ScanSize,
		&LinkageEndAddress,
		&LinkageCopyAddress,
		&LinkageRelative32Address
	);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	PUCHAR InternalEndAddress = NULL;
	PUCHAR InternalCopyAddress = NULL;
	PUCHAR InternalRelative32Address = NULL;
	PUCHAR InternalOpcodeAddress = NULL;

	Status = ScanForKiServiceInternal(
		LinkageEndAddress,
		ScanSize,
		&InternalEndAddress,
		&InternalCopyAddress,
		&InternalRelative32Address,
		&InternalOpcodeAddress
	);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	// We have to translate the addresses because we are not in +/-2GB signed distance
	// 48 b8 ff ff ff ff ff ff f8 ff    movabs rax, 0xfff8ffffffffffff
	static const SIZE_T MOVABS_RAX_LEN = 10;

	// ff 25 00 00 00 00			jmp    QWORD PTR [rip+0x0] 
	// ff ff ff ff ff ff ff ff		dq	   TargetAddress
	static const SIZE_T JMP_REL_RIP0_LEN = 14;

	SIZE_T LinkageCopySize = (SIZE_T)(LinkageCopyAddress - StartAddress);
	SIZE_T InternalCopySize = (SIZE_T)(InternalCopyAddress - LinkageEndAddress);

	SIZE_T StubMovAbsOffset = LinkageCopySize;
	SIZE_T StubInternalCopyOffset = LinkageCopySize + MOVABS_RAX_LEN;
	SIZE_T StubJmpOffset = StubInternalCopyOffset + InternalCopySize;
	SIZE_T StubOpcodeOffset = StubInternalCopyOffset + (InternalCopyAddress - InternalOpcodeAddress) - 2; 	// b8 ?? ?? ?? ??      mov     eax, ??
	SIZE_T SystemInternalCopyOffset = (SIZE_T)(LinkageEndAddress - StartAddress);

	SIZE_T StubSize = StubJmpOffset + JMP_REL_RIP0_LEN + 1; // add a c3 for fun

	PUCHAR Stub = ExAllocatePoolWithTag(NonPagedPool, StubSize, PoolTag);

	if (Stub == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(Stub, StartAddress, LinkageCopySize);

	UINT64 MovAbsTargetAddr = (UINT64)ConvertRelative32AddressToAbsoluteAddress((PUINT32)LinkageRelative32Address);

	*(UINT16*)(Stub + StubMovAbsOffset) = 0xb848;	// 48 b8	movabs rax, ...
	*(UINT64*)(Stub + StubMovAbsOffset + 2) = MovAbsTargetAddr;

	RtlCopyMemory(Stub + StubInternalCopyOffset, StartAddress + SystemInternalCopyOffset, InternalCopySize);

	UINT64 JmpTargetAddr = (UINT64)ConvertRelative32AddressToAbsoluteAddress((PUINT32)InternalRelative32Address);

	*(UINT64*)(Stub + StubJmpOffset) = 0x00000000000025ff;	// ff 25 00 00 00 00 .. .. jmp [$ + 0]
	*(UINT64*)(Stub + StubJmpOffset + 6) = JmpTargetAddr;

	Stub[StubSize - 1] = (UCHAR)'\xc3';

	*(UINT32*)(Stub + StubOpcodeOffset) = SyscallOpcode;

	*OutPtr = Stub;

	return STATUS_SUCCESS;
}