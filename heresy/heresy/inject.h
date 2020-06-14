#pragma once

#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020

#define WORKER_FACTORY_ALL_ACCESS ( \
    STANDARD_RIGHTS_REQUIRED | \
    WORKER_FACTORY_RELEASE_WORKER | \
    WORKER_FACTORY_WAIT | \
    WORKER_FACTORY_SET_INFORMATION | \
    WORKER_FACTORY_QUERY_INFORMATION | \
    WORKER_FACTORY_READY_WORKER | \
    WORKER_FACTORY_SHUTDOWN \
    )

typedef enum _WORKER_FACTORY_INFORMATION_CLASS {
	WorkerFactoryMinimumThreadInformation = 4
} WORKER_FACTORY_INFORMATION_CLASS, *PWORKER_FACTORY_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI * ZW_CREATE_WORKER_FACTORY)(
	_Out_ PHANDLE WorkerFactoryHandleReturn,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE CompletionPortHandle,
	_In_ HANDLE WorkerProcessHandle,
	_In_ PVOID StartRoutine,
	_In_ PVOID StartParameter,
	_In_ ULONG MaxThreadCount,
	_In_ SIZE_T StackReserve,
	_In_ SIZE_T StackCommit
	);

typedef NTSTATUS(NTAPI * ZW_SET_INFORMATION_WORKER_FACTORY)(
	_In_ HANDLE WorkerFactoryHandle,
	_In_ WORKER_FACTORY_INFORMATION_CLASS WorkerFactoryInformationClass,
	_In_ PVOID WorkerFactoryInformation,
	_In_ SIZE_T WorkerFactoryInformationLength
	);


typedef PCHAR(NTAPI *PS_GET_PROCESS_IMAGE_FILE_NAME)(PEPROCESS);

typedef NTSTATUS(NTAPI *ZW_CREATE_IO_COMPLETION)(
	PHANDLE, 
	ACCESS_MASK, 
	POBJECT_ATTRIBUTES, 
	ULONG);

typedef struct INJECT_WORK_FACTORY_FUNCTIONS {
	// find with heresy
	ZW_CREATE_WORKER_FACTORY __ZwCreateWorkerFactory;
	ZW_SET_INFORMATION_WORKER_FACTORY __ZwSetInformationWorkerFactory;

	// exported:
	PS_GET_PROCESS_IMAGE_FILE_NAME __PsGetProcessImageFileName;
	ZW_CREATE_IO_COMPLETION __ZwCreateIoCompletion;

} INJECT_WORK_FACTORY_FUNCTIONS, *PINJECT_WORK_FACTORY_FUNCTIONS;

NTSTATUS NTAPI InjectWorkFactory(
	_In_ PCHAR ProcessInsensitiveName,
	_In_ PUCHAR UserModePayload,
	_In_ SIZE_T UserModePayloadSize,
	_In_ ULONG PoolTag,
	_In_ PINJECT_WORK_FACTORY_FUNCTIONS Functions
);