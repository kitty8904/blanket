#pragma once
#include "log.h"
#include "scan.h"
#include "struct.h"
#include "mem.h"
#include "includes.h"

UCHAR codeCave[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
UCHAR sExMapHandleToPointer[] = "\x40\x53\x48\x83\xEC\x20\x4C\x8B\xC9\xF7\xC2\xFC\x03\x00\x00\x74";
UCHAR sExDestroyHandle[] = "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\x48\x83\x79\x60\x00\x49\x8B\xE8\x48\x8B\xF2\x48";

typedef struct _HANDLE_TABLE* PHANDLE_TABLE;

typedef struct HANDLE_TABLE_ENTRY* PHANDLE_TABLE_ENTRY;

typedef NTKERNELAPI PHANDLE_TABLE_ENTRY(*PEX_MAP_HANDLE_TO_POINTER)(
	__in  PHANDLE_TABLE HandleTable,
	__in  HANDLE Handle
	);

typedef NTKERNELAPI BOOLEAN(*PEX_DESTROY_HANDLE)(
	__inout		PHANDLE_TABLE HandleTable,
	__in		HANDLE Handle,
	__inout_opt PHANDLE_TABLE_ENTRY HandleTableEntry
);

namespace blanket
{
	PEX_MAP_HANDLE_TO_POINTER pExMapHandleToPointer;
	PEX_DESTROY_HANDLE pExDestroyHandle;
	PHANDLE_TABLE PspCidTable;

	NTSTATUS unlinkThread(PMYTHREAD thread)
	{
		PMYPROCESS thisProcess = (PMYPROCESS)PsGetCurrentProcess();
		auto threadId = PsGetThreadId((PETHREAD)thread);

		LIST_ENTRY threadListHead = thisProcess->ThreadListHead;
		for (PLIST_ENTRY list(threadListHead.Flink); list != &threadListHead; list = list->Flink) {
			PMYTHREAD pEntry = CONTAINING_RECORD(list, MYTHREAD, ThreadListEntry);
			QWORD currentThreadId = (QWORD)PsGetThreadId((PETHREAD)pEntry);
			if (currentThreadId == (QWORD)threadId)
			{
				PMYTHREAD pPreviousEntry = CONTAINING_RECORD(list->Blink, MYTHREAD, ThreadListEntry);
				PMYTHREAD pNextEntry = CONTAINING_RECORD(list->Flink, MYTHREAD, ThreadListEntry);
				pPreviousEntry->ThreadListEntry.Flink = list->Flink;
				pNextEntry->ThreadListEntry.Blink = list->Blink;
				return STATUS_SUCCESS;
			}
		}
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS changeFlags(PMYTHREAD thread)
	{
		// Not a system thread anymore
		thread->MiscFlags &= ~(1UL << 10);
		// Dont queue APC on me
		thread->MiscFlags &= ~(1UL << 4);

		// Testing
		if (PsIsSystemThread((PETHREAD)thread))
			return STATUS_UNSUCCESSFUL;

		return STATUS_SUCCESS;
	}

	NTSTATUS removePspCidTableHandle(HANDLE handle)
	{
		if (pExMapHandleToPointer == NULL)
			pExMapHandleToPointer = (PEX_MAP_HANDLE_TO_POINTER)scan::signatureScanBySection(
				memory::getKernelBase(), "PAGE", sExMapHandleToPointer, 0, sizeof(sExMapHandleToPointer) - 1
			);

		if (pExMapHandleToPointer == NULL)
		{
			log("Unable to find ExMapHandleToPointer function, exiting...");
			return STATUS_UNSUCCESSFUL;
		}

		if (pExDestroyHandle == NULL)
			pExDestroyHandle = (PEX_DESTROY_HANDLE)scan::signatureScanBySection(
				memory::getKernelBase(), "PAGE", sExDestroyHandle, 0, sizeof(sExDestroyHandle) - 1
			);

		if (pExDestroyHandle == NULL)
		{
			log("Unable to find ExDestroyHandle function, exiting...");
			return STATUS_UNSUCCESSFUL;
		}

		if (PspCidTable == NULL)
			RtlCopyMemory(&PspCidTable, (PVOID)((UINT64)memory::getKernelBase() + 0x572538), 8);  // TODO sigscan this

		// Find handle in PspCidTable
		PHANDLE_TABLE_ENTRY ptr = pExMapHandleToPointer(PspCidTable, handle);
		if (ptr == NULL)
		{
			log("ExMapHandleToPointer returned NULL, exiting...");
			return STATUS_UNSUCCESSFUL;
		}

		// Remove it
		pExDestroyHandle(PspCidTable, handle, ptr);
		return STATUS_SUCCESS;
	}

	NTSTATUS clearPspCidTable(PMYTHREAD thread)
	{
		PETHREAD tempThread = NULL;
		auto threadId = PsGetThreadId((PETHREAD)thread);

		if (!NT_SUCCESS(PsLookupThreadByThreadId(threadId, &tempThread)))
		{
			log("Thread id %u was not found using PsLookupThreadByThreadId", threadId);
			return STATUS_SUCCESS;
		}

		blanket::removePspCidTableHandle(thread->Cid.UniqueThread);

		if (NT_SUCCESS(PsLookupThreadByThreadId(threadId, &tempThread)))
		{
			log("Thread id %u was found using PsLookupThreadByThreadId, exiting...", threadId);
			return STATUS_UNSUCCESSFUL;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS clearPspCidTable(PMYPROCESS process)
	{
		PEPROCESS tempProcess = NULL;
		auto processId = PsGetProcessId((PEPROCESS)process);

		if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &tempProcess)))
		{
			log("Process id %u was not found using PsLookupProcessByProcessId", processId);
			return STATUS_SUCCESS;
		}

		blanket::removePspCidTableHandle(processId);

		if (NT_SUCCESS(PsLookupProcessByProcessId(processId, &tempProcess)))
		{
			log("Process id %u was found using PsLookupProcessByProcessId, exiting...", processId);
			return STATUS_UNSUCCESSFUL;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS setupStartAddress(PVOID routine, PVOID& outCodeCave)
	{
		// movabs rax jmp rax
		BYTE trampoline[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0xCC};
		memcpy((PVOID)((ULONG_PTR)trampoline + 2), &routine, sizeof(PVOID));

		// Find code cave in ntoskrnl
		PVOID codeCaveStart = scan::signatureScanBySection(
			memory::getKernelBase(), ".text", codeCave, 0, sizeof(codeCave) - 1
		);

		if (codeCaveStart == NULL)
		{
			log("Unable to find code cave in ntoskrnl, exiting...");
			return STATUS_UNSUCCESSFUL;
		}

		// Write a jmp
		if (!NT_SUCCESS(memory::writeToReadOnly(codeCaveStart, &trampoline, sizeof(trampoline))))
		{
			log("Unable to setup a jmp, exiting...");
			return STATUS_UNSUCCESSFUL;
		}

		outCodeCave = codeCaveStart;
		return STATUS_SUCCESS;
	}

	NTSTATUS restoreStartAddress(PVOID codeCaveStart)
	{
		BYTE zeros[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		if (!NT_SUCCESS(memory::writeToReadOnly(codeCaveStart, &zeros, sizeof(zeros), true)))
		{
			log("Could not restore start address, exiting...");
			return STATUS_UNSUCCESSFUL;
		}
		return STATUS_SUCCESS;
	}

	NTSTATUS hideThread(PMYTHREAD thread)
	{
		// Unlink thread
		if (!NT_SUCCESS(blanket::unlinkThread(thread)))
		{
			log("Could not properly unlink thread, exiting...");
			return STATUS_UNSUCCESSFUL;
		}
		log("Succesfully unlinked thread");	

		// Change flags
		if (!NT_SUCCESS(blanket::changeFlags(thread)))
		{
			log("Could not properly change thread flags, exiting...");
			return STATUS_UNSUCCESSFUL;
		}
		log("Succesfully changed flags");

		// Clear PspCidTable
		if (!NT_SUCCESS(blanket::clearPspCidTable(thread)))
		{
			log("Could not properly clear PspCidTable, exiting...");
			return STATUS_UNSUCCESSFUL;
		}
		log("Succesfully cleared PspCidTable");

		return STATUS_SUCCESS;
	}
}