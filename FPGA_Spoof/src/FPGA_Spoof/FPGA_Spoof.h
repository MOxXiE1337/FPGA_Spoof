#pragma once

#include <print>
#include <MemProcFS/vmmdll.h>

#define NTOSKRNL_PID 0x4

namespace FPGA_Spoof
{
	inline VMM_HANDLE gVMMHandle = NULL;
	bool InitFPGA();
	bool SetupFPGA();
	bool SpoofFPGA();

	ULONG64 GetModuleBaseViaVMM(const char* szModuleName, DWORD dwPid);
	ULONG64 GetProcAddressViaVMM(const char* szProcName, DWORD dwPid, const char* szModuleName);
	bool ReadMemory(ULONG64 vaAddress, void* pBuffer, size_t cSize, DWORD dwPid);
	bool WriteMemory(ULONG64 vaAddress, void* buffer, size_t cSize, DWORD dwPid);
}
