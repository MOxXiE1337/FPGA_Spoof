#include "FPGA_Spoof.h"


bool FPGA_Spoof::InitFPGA()
{
    LPCSTR szArgv[] = { "", "-device","fpga","-norefresh" };
    ULONG64 ulFPGAId, ulDeviceId = 0;

    gVMMHandle = VMMDLL_Initialize(4, szArgv);

    if (gVMMHandle)
    {
        VMMDLL_ConfigGet(gVMMHandle, LC_OPT_FPGA_FPGA_ID, &ulFPGAId);
        VMMDLL_ConfigGet(gVMMHandle, LC_OPT_FPGA_DEVICE_ID, &ulDeviceId);
        
        std::println("[+] FPGA Id: {:X}", ulFPGAId);
        std::println("[+] Device Id: {:X}", ulDeviceId);

        if (SetupFPGA())
        {
            std::println("[+] FPGA has been set up successfully");
            return true;
        }

        std::println("[-] Failed to set up FPGA");
        VMMDLL_Close(gVMMHandle);
        return false;
    }

    std::println("[-] Failed to initialize VMMDLL");
    return false;
}

bool FPGA_Spoof::SetupFPGA()
{
    ULONG64 ulFPGAId;
    ULONG64 ulFPGAMajorVersion;
    ULONG64 ulFPGAMinorVersion;

    if (VMMDLL_ConfigGet(gVMMHandle, LC_OPT_FPGA_FPGA_ID, &ulFPGAId) &&
        VMMDLL_ConfigGet(gVMMHandle, LC_OPT_FPGA_VERSION_MAJOR, &ulFPGAMajorVersion) &&
        VMMDLL_ConfigGet(gVMMHandle, LC_OPT_FPGA_VERSION_MINOR, &ulFPGAMinorVersion))
    {
        std::println("[+] VMMDLL_ConfigGet: ID = {:X} VERSION = {:X}.{:X}", ulFPGAId, ulFPGAMajorVersion, ulFPGAMinorVersion);
        if ((ulFPGAMajorVersion >= 4) && (ulFPGAMajorVersion >= 5 || ulFPGAMinorVersion >= 7))
        {
            HANDLE hLC;
            LC_CONFIG LcConfig =
            {
                .dwVersion = LC_CONFIG_VERSION,
                .szDevice = "existing"
            };

            hLC = LcCreate(&LcConfig);
            if (hLC)
            {
                BYTE Data[4] = {0x10,0x00,0x10,0x00};
                LcCommand(hLC, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x002, 4, Data, NULL, NULL);
                std::println("[+] Register auto cleared");
                LcClose(hLC);
            }
        }
        return true;
    }

    std::println("[-] Failed to look up FPGA device");
    return false;
}

bool FPGA_Spoof::SpoofFPGA()
{
    ULONG vaNtoskrnlBase = GetModuleBaseViaVMM("ntoskrnl.exe", NTOSKRNL_PID);

    std::println("[+] ntoskrnl: {:X}", vaNtoskrnlBase);

    ULONG64 vaHalPrivateDispatchTable = GetProcAddressViaVMM("HalPrivateDispatchTable", NTOSKRNL_PID, "ntoskrnl.exe");
    if (vaHalPrivateDispatchTable == 0)
    {
        std::println("[-] Failed to get ntoskrnl.HalPrivateDispatchTable");
        return false;
    }

    std::println("[+] ntoskrnl.HalPrivateDispatchTable: {:X}", vaHalPrivateDispatchTable);

    ULONG64 vaAddressOfHalpKdReadPCIConfig = vaHalPrivateDispatchTable + 0xA0;
    ULONG64 vaHalpKdReadPCIConfig = 0;
    if (!ReadMemory(vaAddressOfHalpKdReadPCIConfig, &vaHalpKdReadPCIConfig, sizeof(ULONG64), NTOSKRNL_PID))
        return false;

    std::println("[+] ntoskrnl.HalpKdReadPCIConfig: {:X}", vaHalpKdReadPCIConfig);

    ULONG64 vaCallOfHaliPciInterfaceReadConfig = vaHalpKdReadPCIConfig + 0x1B;
    ULONG32 offHaliPciInterfaceReadConfig = 0;

    if (!ReadMemory(vaCallOfHaliPciInterfaceReadConfig + 1, &offHaliPciInterfaceReadConfig, sizeof(ULONG32), NTOSKRNL_PID))
        return false;

    ULONG64 vaHaliPciInterfaceReadConfig = vaCallOfHaliPciInterfaceReadConfig + offHaliPciInterfaceReadConfig + 5;

    std::println("[+] ntoskrnl.HaliPciInterfaceReadConfig: {:X}", vaHaliPciInterfaceReadConfig);

    ULONG64 vaCallOfHalpPciAccessMmConfigSpace = vaHaliPciInterfaceReadConfig;
    ULONG32 offHalpPciAccessMmConfigSpace = 0;

    // serach call HalpPciAccessMmConfigSpace
    while(true)
    {
        ULONG64 bOpcodes = 0;
        if (!ReadMemory(vaCallOfHalpPciAccessMmConfigSpace, &bOpcodes, sizeof(ULONG64), NTOSKRNL_PID))
            return false;

        std::println("DEBUG: {:X}: {:X}", bOpcodes);

        if ((BYTE)bOpcodes == 0xE8 && *(WORD*)((char*)(&bOpcodes) + 0x5) == 0xC084)
            break;

        ++vaCallOfHalpPciAccessMmConfigSpace;
    }

    if (!ReadMemory(vaCallOfHalpPciAccessMmConfigSpace + 1, &offHalpPciAccessMmConfigSpace, sizeof(ULONG32), NTOSKRNL_PID))
        return false;

    ULONG64 vaHalpPciAccessMmConfigSpace = vaCallOfHalpPciAccessMmConfigSpace + offHalpPciAccessMmConfigSpace + 0x5;

    std::println("[+] ntoskrnl.HalpPciAccessMmConfigSpace: {:X}", vaHalpPciAccessMmConfigSpace);

    // search mov     r9, cs:HalpPciMcfgTable 
    ULONG64 vaMovOfHalpPciMcfgTable = vaHalpPciAccessMmConfigSpace;
    for (;; vaMovOfHalpPciMcfgTable++)
    {
        ULONG32 bOpcodes = 0;
        if (!ReadMemory(vaMovOfHalpPciMcfgTable, &bOpcodes, sizeof(ULONG32), NTOSKRNL_PID))
            return false;

        if ((BYTE)bOpcodes == 0x4C && *(WORD*)((char*)(&bOpcodes) + 0x1) == 0x0D8B)
            break;
    }

    // i dont know wtf is it doing now, just C&V
    ULONG32 offHalpPciMcfgTable = 0;
    if (!ReadMemory(vaMovOfHalpPciMcfgTable + 3, &offHalpPciMcfgTable, sizeof(ULONG32), NTOSKRNL_PID))
        return false;
    ULONG64 vaHalpPciMcfgTable = vaMovOfHalpPciMcfgTable + offHalpPciMcfgTable + 7;
    ULONG64 vaHalpPciMcfgTableCount = vaHalpPciMcfgTable - 24;

    std::println("[+] ntoskrnl.HalpPciMcfgTable: {:X}", vaHalpPciMcfgTable);
    std::println("[+] ntoskrnl.HalpPciMcfgTableCount: {:X}", vaHalpPciMcfgTableCount);

    if (vaHalpPciMcfgTable == 0 || vaHalpPciMcfgTableCount == 24)
    {
        std::println("[-] Maybe the system is not supported");
        return false;
    }
    else
    {
        ULONG64 bPatch = 0;
        if (!WriteMemory(vaHalpPciMcfgTable, &bPatch, sizeof(ULONG64), NTOSKRNL_PID)) // HalpPciMcfgTable
            return false;
        if (!WriteMemory(vaHalpPciMcfgTableCount, &bPatch, sizeof(ULONG64), NTOSKRNL_PID)) // HalpPciMcfgTableCount
            return false;

        std::println("[+] Spoof has been applied successfully");
    }
    return true;
}

ULONG64 FPGA_Spoof::GetModuleBaseViaVMM(const char* szModuleName, DWORD dwPid)
{
    PVMMDLL_MAP_MODULEENTRY pModuleEntry = NULL;
    if (VMMDLL_Map_GetModuleFromNameU(gVMMHandle, dwPid, szModuleName, &pModuleEntry, 0) == TRUE)
    {
        return pModuleEntry->vaBase;
    }
    else
    {
        VMMDLL_MemFree(pModuleEntry);
    }

    return 0;
}

ULONG64 FPGA_Spoof::GetProcAddressViaVMM(const char* szProcName, DWORD dwPid, const char* szModuleName)
{
    PVMMDLL_MAP_EAT pEatMap = NULL;
    PVMMDLL_MAP_EATENTRY pEatMapEntry = NULL;   
    ULONG64 vaFunction = 0;

    if (VMMDLL_Map_GetEATU(gVMMHandle, dwPid, szModuleName, &pEatMap) == TRUE)
    {
        if (pEatMap->dwVersion == VMMDLL_MAP_EAT_VERSION)
        {
            for (size_t i = 0; i < pEatMap->cMap; i++)
            {
                pEatMapEntry = pEatMap->pMap + i;
                std::println("DEBUG: {}", pEatMapEntry->uszFunction);
                if (strcmp(pEatMapEntry->uszFunction, szProcName) == 0)
                {
                    vaFunction = pEatMapEntry->vaFunction;
                    break;
                }
            }
            
            VMMDLL_MemFree(pEatMap);
            pEatMap = NULL;
            return vaFunction;
        }
        else
        {
            VMMDLL_MemFree(pEatMap);
            pEatMap = NULL;
            std::println("[-] Invalid VMM Map version");
            return 0;
        }
    }

    return 0;
}

bool FPGA_Spoof::ReadMemory(ULONG64 vaAddress, void* pBuffer, size_t cSize, DWORD dwPid)
{
    if (VMMDLL_MemReadEx(gVMMHandle, dwPid, vaAddress, (PBYTE)pBuffer, cSize, NULL, 0x21) == TRUE)
        return true;
    std::println("[-] Failed to read memory at {:X}", vaAddress);
    return false;
}

bool FPGA_Spoof::WriteMemory(ULONG64 vaAddress, void* pBuffer, size_t cSize, DWORD dwPid)
{
    if (VMMDLL_MemWrite(gVMMHandle, dwPid, vaAddress, (PBYTE)pBuffer, cSize))
        return true;
    std::println("[-] Failed to write memory at {:X}", vaAddress);
    return false;
}
