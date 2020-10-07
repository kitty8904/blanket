#include "includes.h"

namespace memory
{
	PVOID kernelBase = NULL;

	NTSTATUS writeToReadOnly(PVOID address, PVOID buffer, SIZE_T size, BOOLEAN reset = false)
	{
		auto mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);
		if (!mdl)
		{
			log("IoAllocateMdl failed");
			return STATUS_UNSUCCESSFUL;
		}

		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);

		auto mmMap = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		RtlCopyMemory(mmMap, buffer, size);

		if (reset)
		{
			log("Restoring page to READONLY");
			MmProtectMdlSystemAddress(mdl, PAGE_READONLY);
		}

		MmUnmapLockedPages(mmMap, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		return STATUS_SUCCESS;
	}

	PVOID getSystemModuleBase(PCCHAR module_name)
	{
		ULONG bytes = 0;
		PVOID moduleBase = NULL;
		PRTL_PROCESS_MODULES modules = NULL;

		// First fetch to retrieve the size
		ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
		if (bytes == 0)
			return moduleBase;

		// Allocate the size
		modules = (PRTL_PROCESS_MODULES)ExAllocatePoolZero(NonPagedPool, bytes, 'KEKE');
		if (modules == NULL)
			return moduleBase;

		// Fetch real data
		if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes)))
		{
			// Walk loaded modules
			PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
			for (ULONG i(0); i < modules->NumberOfModules; i++)
			{
				if (strstr((PCHAR)module[i].FullPathName, module_name) != NULL)
				{
					moduleBase = module[i].ImageBase;
					break;
				}
			}
		}

		if (modules)
			ExFreePoolWithTag(modules, 'KEKE');

		return moduleBase;
	}

	PVOID getKernelBase()
	{
		if (kernelBase == NULL)
			return (kernelBase = getSystemModuleBase("ntoskrnl"));
		return kernelBase;
	}
}