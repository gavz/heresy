#pragma once

static inline
NTSTATUS NTAPI ByteScanMatch(
	_In_ PUCHAR TargetAddress,
	_In_ PUCHAR MaskBytes,
	_In_ SIZE_T MaskBytesLength,
	_In_ UCHAR WildCardByte
)
{
	for (SIZE_T MaskOffset = 0; MaskOffset < MaskBytesLength; ++MaskOffset)
	{
		if (MaskBytes[MaskOffset] == WildCardByte)
		{
			continue;
		}

		if (TargetAddress[MaskOffset] != MaskBytes[MaskOffset])
		{
			return STATUS_NOT_FOUND;
		}
	}

	return STATUS_SUCCESS;
}

static inline
NTSTATUS NTAPI ByteScanMask(
	_In_ PUCHAR StartAddress,
	_In_ SIZE_T MaxScanLength,
	_In_ PUCHAR MaskBytes,
	_In_ SIZE_T MaskBytesLength,
	_In_ UCHAR WildCardByte,
	_Out_ PUCHAR *EndAddress
)
{
	for (SIZE_T Offset = 0; Offset <= MaxScanLength; ++Offset)
	{
		if (Offset + MaskBytesLength >= MaxScanLength)
		{
			break;
		}

		PUCHAR TargetAddress = StartAddress + Offset;

		if (NT_SUCCESS(ByteScanMatch(TargetAddress, MaskBytes, MaskBytesLength, WildCardByte)))
		{
			*EndAddress = StartAddress + Offset + MaskBytesLength;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}