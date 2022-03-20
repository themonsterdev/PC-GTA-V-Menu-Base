#include "pch.h"

static uint8_t resetInstruction[RESET_SIZE];

LPVOID AllocatePageNearAddress(LPVOID targetAddr)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

	uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); // round down to nearest page boundary
	uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

	uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

	uint64_t pageOffset = 1;
	while (true)
	{
		uint64_t byteOffset = pageOffset * PAGE_SIZE;
		uint64_t highAddr = startPage + byteOffset;
		uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

		bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

		if (highAddr < maxAddr)
		{
			void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr != nullptr)
				return outAddr;
		}

		pageOffset++;

		if (needsExit)
		{
			break;
		}
	}

	return nullptr;
}

VOID WriteAbsoluteJump64(LPVOID absJumpMemory, LPVOID addrToJumpTo)
{
	uint8_t absJumpInstructions[] = {
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
		0x41, 0xFF, 0xE2                                            // jmp r10
	};

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof addrToJumpTo64);
	memcpy(absJumpMemory, absJumpInstructions, sizeof absJumpInstructions);
}

VOID InstallHook(LPVOID pTarget, LPVOID pRetour, LPVOID* ppOriginal)
{
	memcpy(resetInstruction, pTarget, RESET_SIZE);

	DWORD oldProtect;
	VirtualProtect(pTarget, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

	LPVOID hookMemory = AllocatePageNearAddress(pTarget);
	uint32_t trampolineSize = BuildTrampoline(pTarget, hookMemory);
	*ppOriginal = hookMemory;

	// create the relay function
	LPVOID relayFuncMemory = (DWORD*)hookMemory + trampolineSize;
	WriteAbsoluteJump64(relayFuncMemory, pRetour); //write relay func instructions

	// install the hook
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	size_t jmpSize = sizeof jmpInstruction;

	DWORD relativeAddress = (DWORD)relayFuncMemory - ((DWORD)pTarget + (DWORD)jmpSize);
	memcpy(jmpInstruction + 1, &relativeAddress, 4);

	// E9 BF E8 FD FF                   jmp     near ptr 7FF766FB0054h
	// 90 90 90                         align 8
	memcpy(pTarget, jmpInstruction, jmpSize);
}

VOID UninstallHook(LPVOID pTarget)
{
	DWORD oldProtect;
	VirtualProtect(pTarget, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

	// uninstall the hook
	memcpy(pTarget, resetInstruction, RESET_SIZE);
}
