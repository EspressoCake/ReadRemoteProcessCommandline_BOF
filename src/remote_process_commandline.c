#include <windows.h>
#include <winternl.h>
#include <ntdef.h>
#include <processthreadsapi.h>
#include "beacon.h"

DECLSPEC_IMPORT NTSTATUS    NTAPI   NTDLL$NtClose(HANDLE ProcessHandle);
DECLSPEC_IMPORT NTSTATUS    NTAPI   NTDLL$NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
DECLSPEC_IMPORT NTSTATUS    NTAPI   NTDLL$NtQueryInformationProcess(HANDLE ProcessHandle,PROCESSINFOCLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength,PULONG ReturnLength);
DECLSPEC_IMPORT NTSTATUS    NTAPI   NTDLL$NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG Size, PULONG TotalBytesRead);
DECLSPEC_IMPORT LPVOID      WINAPI  KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT HANDLE      WINAPI  KERNEL32$GetProcessHeap (VOID);
DECLSPEC_IMPORT WINBOOL     WINAPI  KERNEL32$HeapFree (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);


VOID dumpFormatAllocation(formatp* formatAllocationData, LPVOID heapaddr)
{
    char*   outputString = NULL;
    int     sizeOfObject = 0;

    outputString = BeaconFormatToString(formatAllocationData, &sizeOfObject);
    BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);

    if (heapaddr != NULL)
    {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, heapaddr);
    }

    BeaconFormatFree(formatAllocationData);

    return;
}


HANDLE GetProcessHandle(DWORD dwPid)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    CLIENT_ID uPid = { 0 };

    uPid.UniqueProcess = (PVOID)dwPid;
    uPid.UniqueThread = 0;

    status = NTDLL$NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
    if (hProcess == NULL) {
        return NULL;
    }

    return hProcess;
}


WCHAR* returnData(HANDLE hProcessHandle, formatp* fpObject)
{
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    RTL_USER_PROCESS_PARAMETERS rtlPP = { 0 };

    NTSTATUS ntResult = NTDLL$NtQueryInformationProcess(hProcessHandle, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

    if (NT_SUCCESS(ntResult))
    {
        BeaconFormatPrintf(fpObject, "%-20s 0x%p\n", "Remote PEB:", pbi.PebBaseAddress);

        PEB pebData = { 0 };
        ULONG pebSize = 0;

        NTDLL$NtReadVirtualMemory(hProcessHandle, pbi.PebBaseAddress, &pebData, sizeof(PEB), &pebSize);

        if (pebSize == (ULONG)sizeof(PEB))
        {
            ULONG ulRtlParameters = 0;
            NTDLL$NtReadVirtualMemory(hProcessHandle, pebData.ProcessParameters, &rtlPP, sizeof(RTL_USER_PROCESS_PARAMETERS), &ulRtlParameters);

            if (ulRtlParameters == sizeof(RTL_USER_PROCESS_PARAMETERS))
            {
                WCHAR* wcCommandLineBuffer = (WCHAR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, rtlPP.CommandLine.Length * sizeof(WCHAR));

                if (wcCommandLineBuffer != NULL)
                {
                    ULONG ulReadCommandline = 0;
                    BeaconFormatPrintf(fpObject, "%-20s 0x%p\n", "Command Addr:", wcCommandLineBuffer);
                    BeaconFormatPrintf(fpObject, "%-20s %hu\n", "Size:", rtlPP.CommandLine.Length), 

                    NTDLL$NtReadVirtualMemory(hProcessHandle, rtlPP.CommandLine.Buffer, wcCommandLineBuffer, rtlPP.CommandLine.Length, &ulReadCommandline);
                    BeaconFormatPrintf(fpObject, "%-20s %S\n", "Commandline:", (wchar_t*)wcCommandLineBuffer);

                    return wcCommandLineBuffer;
                }
            }
            else
            {
                return NULL;
            }

        }
        else
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }
}


void go(char* args, int len)
{
    datap parser;
    formatp fpObject;

    BeaconDataParse(&parser, args, len);
    BeaconFormatAlloc(&fpObject, 64 * 1024);

    DWORD dwProcessID = (DWORD)BeaconDataInt(&parser);

    BeaconFormatPrintf(&fpObject, "%-20s %lu\n", "Process ID:", dwProcessID);

    HANDLE hProcess = GetProcessHandle(dwProcessID);

    if (hProcess)
    {
        WCHAR* heapAllocatedData = returnData(hProcess, &fpObject);
        dumpFormatAllocation(&fpObject, heapAllocatedData);
    }
    else
    {
        BeaconFormatPrintf(&fpObject, "%-20s %s\n", "Error:", "Unable to obtain process handle.");

    }

    NTDLL$NtClose(hProcess);
}