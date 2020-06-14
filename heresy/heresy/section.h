#pragma once

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID TransferAddress;
	ULONG ZeroBits;
	ULONG MaximumStackSize;
	ULONG CommittedStackSize;
	ULONG SubSystemType;
	union 
	{
		struct
		{
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		} s1;
		ULONG SubSystemVersion;
	} u1;
	ULONG GpValue;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	UCHAR ImageContainsCode;
	UCHAR ImageFlags;
	INT32 ComPlusNativeReady : 1;
	INT32 ComPlusILOnly : 1;
	INT32 ImageDynamicallyRelocated : 1;
	INT32 Reserved : 5;
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation = 0,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

