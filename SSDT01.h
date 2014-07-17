#ifndef __SSDT_01_H__
#define __SSDT_01_H__

#ifndef _WIN32_WINNT				// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501			// Change this to the appropriate value to target other versions of Windows.
#endif						

#ifdef __cplusplus
extern "C" 
{
#endif


#include "VisualDDKHelpers.h"
#include <ntddk.h>


#ifdef __cplusplus
}
#endif


#include <stdlib.h>
#include "SSDTHook.h"


#define DEVICE_NAME_PROCESS				L"\\Device\\SSDT01ByZachary"
#define SYMBOLINK_NAME_PROCESS			L"\\??\\SSDT01ByZachary"

#define MAX_PROCESS_ARRARY_LENGTH		1024

#define	SSDT01_DEVICE_TYPE				FILE_DEVICE_UNKNOWN

//定义用于应用程序和驱动程序通信的宏，这里使用的是缓冲区读写方式
#define	IO_INSERT_HIDE_PROCESS			(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IO_REMOVE_HIDE_PROCESS			(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IO_INSERT_PROTECT_PROCESS		(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IO_REMOVE_PROTECT_PROCESS		(ULONG) CTL_CODE(SSDT01_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct _SYSTEM_THREAD_INFORMATION 
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;

} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION 
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;

} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef enum _SYSTEM_INFORMATION_CLASS 
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass

} SYSTEM_INFORMATION_CLASS;


NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation (
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS (* NTQUERYSYSTEMINFORMATION)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

NTSTATUS HookNtQuerySystemInformation (
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

NTQUERYSYSTEMINFORMATION pOldNtQuerySystemInformation;


typedef NTSTATUS (* NTTERMINATEPROCESS)(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
	);

NTSTATUS HookNtTerminateProcess(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
	);

NTTERMINATEPROCESS pOldNtTerminateProcess;


PUCHAR PsGetProcessImageFileName(__in PEPROCESS Process);


ULONG g_PIDHideArray[MAX_PROCESS_ARRARY_LENGTH];
ULONG g_PIDProtectArray[MAX_PROCESS_ARRARY_LENGTH];

ULONG g_currHideArrayLen = 0;
ULONG g_currProtectArrayLen = 0;


//验证 uPID 所代表的进程是否存在于隐藏进程列表中，即判断 uPID 这个进程是否需要隐藏
ULONG ValidateProcessNeedHide(ULONG uPID);

//验证 uPID 所代表的进程是否存在于保护进程列表中，即判断 uPID 这个进程是否需要保护
ULONG ValidateProcessNeedProtect(ULONG uPID);

//往隐藏进程列表中插入 uPID
ULONG InsertHideProcess(ULONG uPID);

//从隐藏进程列表中移除 uPID
ULONG RemoveHideProcess(ULONG uPID);

//往保护进程列表中插入 uPID
ULONG InsertProtectProcess(ULONG uPID);

//从隐藏进程列表中移除 uPID
ULONG RemoveProtectProcess(ULONG uPID);


void SSDT01DriverUnload(IN PDRIVER_OBJECT pDriverObject);

NTSTATUS SSDT01CreateDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01CloseDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01GeneralDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01ReadDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01WriteDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS SSDT01DeviceIoControlDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);


#ifdef __cplusplus
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING  pRegistryPath);
#endif


#endif