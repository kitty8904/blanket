#include "includes.h"
#include "log.h"
#include "blanket.h"

PVOID gStartAddress = NULL;


void NTAPI main_loop()
{
	auto currentThreadId = PsGetCurrentThreadId();
	auto thisThread = (PMYTHREAD)PsGetCurrentThread();
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = RELATIVE(SECONDS(1));

	// Restore the original address
	blanket::restoreStartAddress(gStartAddress);
	
	// Hide the thread from common API calls
	if (!NT_SUCCESS(blanket::hideThread(thisThread)))
	{
		log("Could not hide properly thread, exiting...");
		return;
	}

	// Main loop. Exiting the loop will result in a BSOD
	while (1)
	{
		log("Thread id %u running", currentThreadId);
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
	}
}

EXTERN_C NTSTATUS DriverEntry(
	PDRIVER_OBJECT  driverObject,
	PUNICODE_STRING registryPath
)
{
	UNREFERENCED_PARAMETER(driverObject);
	UNREFERENCED_PARAMETER(registryPath);

	// Find a decent start address for the thread, and write a jmp there
	if (!NT_SUCCESS(blanket::setupStartAddress(main_loop, gStartAddress)))
	{
		log("Failed to find a start address for the thread, exiting...");
		return STATUS_UNSUCCESSFUL;
	}

	// Create the thread at this address, which should be cleared at the beginning of the thread
	HANDLE threadHandle = NULL;
	const auto status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, 0, 0, 0, (PKSTART_ROUTINE)gStartAddress, 0);

	if (!NT_SUCCESS(status))
	{
		log("Failed to create thread. Code: %X", status);
		ZwClose(threadHandle);
		return STATUS_UNSUCCESSFUL;
	}

	ZwClose(threadHandle);
	return STATUS_SUCCESS;
}