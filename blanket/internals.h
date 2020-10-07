#pragma once
#include "struct.h"

EXTERN_C NTSYSAPI
NTSTATUS NTAPI ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

EXTERN_C NTSYSAPI
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
	PVOID   ModuleAddress
);