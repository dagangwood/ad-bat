//////////////////////////////////////////////////////////////////////////
//补充Windows未文档化的结构体定义
//////////////////////////////////////////////////////////////////////////
#include <ntddk.h>
/*#include <ntifs.h>*/
#include <ntdef.h>
#include <ntimage.h>
#include <stdio.h>
#include <ntstrsafe.h>

typedef unsigned char BYTE ;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef int      BOOL      ;
typedef unsigned short WORD;
#define SEC_IMAGE         0x1000000  

//用于 CreateThread()
typedef struct _USER_STACK {
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,					// 0 Y N
	SystemProcessorInformation,				// 1 Y N
	SystemPerformanceInformation,			// 2 Y N
	SystemTimeOfDayInformation,				// 3 Y N
	SystemNotImplemented1,					// 4 Y N
	SystemProcessesAndThreadsInformation,	// 5 Y N
	SystemCallCounts,						// 6 Y N
	SystemConfigurationInformation,			// 7 Y N
	SystemProcessorTimes,					// 8 Y N
	SystemGlobalFlag,						// 9 Y Y
	SystemNotImplemented2,					// 10 Y N
	SystemModuleInformation,				// 11 Y N
	SystemLockInformation,					// 12 Y N
	SystemNotImplemented3,					// 13 Y N
	SystemNotImplemented4,					// 14 Y N
	SystemNotImplemented5,					// 15 Y N
	SystemHandleInformation,				// 16 Y N
	SystemObjectInformation,				// 17 Y N
	SystemPagefileInformation,				// 18 Y N
	SystemInstructionEmulationCounts,		// 19 Y N
	SystemInvalidInfoClass1,				// 20
	SystemCacheInformation,					// 21 Y Y
	SystemPoolTagInformation,				// 22 Y N
	SystemProcessorStatistics,				// 23 Y N
	SystemDpcInformation,					// 24 Y Y
	SystemNotImplemented6,					// 25 Y N
	SystemLoadImage,						// 26 N Y
	SystemUnloadImage,						// 27 N Y
	SystemTimeAdjustment,					// 28 Y Y
	SystemNotImplemented7,					// 29 Y N
	SystemNotImplemented8,					// 30 Y N
	SystemNotImplemented9,					// 31 Y N
	SystemCrashDumpInformation,				// 32 Y N
	SystemExceptionInformation,				// 33 Y N
	SystemCrashDumpStateInformation,		// 34 Y Y/N
	SystemKernelDebuggerInformation,		// 35 Y N
	SystemContextSwitchInformation,			// 36 Y N
	SystemRegistryQuotaInformation,			// 37 Y Y
	SystemLoadAndCallImage,					// 38 N Y
	SystemPrioritySeparation,				// 39 N Y
	SystemNotImplemented10,					// 40 Y N
	SystemNotImplemented11,					// 41 Y N
	SystemInvalidInfoClass2,				// 42
	SystemInvalidInfoClass3,				// 43
	SystemTimeZoneInformation,				// 44 Y N
	SystemLookasideInformation,				// 45 Y N
	SystemSetTimeSlipEvent,					// 46 N Y
	SystemCreateSession,					// 47 N Y
	SystemDeleteSession,					// 48 N Y
	SystemInvalidInfoClass4,				// 49
	SystemRangeStartInformation,			// 50 Y N
	SystemVerifierInformation,				// 51 Y Y
	SystemAddVerifier,						// 52 N Y
	SystemSessionProcessesInformation		// 53 Y N
} SYSTEM_INFORMATION_CLASS;

typedef struct _SECTION_IMAGE_INFORMATION { // Information Class 1
	PVOID EntryPoint;
	ULONG Unknown1;
	ULONG StackReserve;
	ULONG StackCommit;
	ULONG Subsystem;
	USHORT MinorSubsystemVersion;
	USHORT MajorSubsystemVersion;
	ULONG Unknown2;
	ULONG Characteristics;
	USHORT ImageNumber;
	BOOLEAN Executable;
	UCHAR Unknown3;
	ULONG Unknown4[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

//
//EXTER NTSYSAPI NTSTATUS NTAPI ZwCreateProcess(__out PHANDLE ProcessHandle,
//						  __in ACCESS_MASK DesiredAccess,
//						  __in POBJECT_ATTRIBUTES ObjectAttributes,
//						  __in HANDLE InheritFromProcessHandle,
//						  __in BOOLEAN InheritHandles,
//						  __in HANDLE SectionHandle OPTIONAL,
//						  __in HANDLE DebugPort OPTIONAL,
//						  __in HANDLE ExceptionPort OPTIONAL);
//
// 
//extern NTSYSAPI NTSTATUS NTAPI ZwCreateProcessEx(__out PHANDLE ProcessHandle,
//							__in ACCESS_MASK DesiredAccess,
//							__in POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
//							__in HANDLE ParentProcess,
//							__in BOOLEAN InheritObjectTable,
//							__in HANDLE SectionHandle OPTIONAL,
//							__in HANDLE DebugPort OPTIONAL,
//							__in HANDLE ExceptionPort OPTIONAL,
//							__in HANDLE Unknown);
//
//
//NTSYSAPI NTSTATUS NTAPI ZwCreateThread(__out PHANDLE ThreadHandle,
//						 __in ACCESS_MASK DesiredAccess,
//						 __in POBJECT_ATTRIBUTES ObjectAttributes,
//						 __in HANDLE ProcessHandle,
//						 __out PCLIENT_ID ClientId,
//						 __in PCONTEXT ThreadContext,
//						 __in PUSER_STACK UserStack,
//						 __in BOOLEAN CreateSuspended);
//
//
//NTSYSAPI NTSTATUS NTAPI ZwTerminateThread(__in HANDLE ThreadHandle OPTIONAL,
//							__in NTSTATUS ExitStatus);
//
//
//
//NTSYSAPI NTSTATUS NTAPI ZwQueueApcThread(__in HANDLE ThreadHandle,
//						   __in PKNORMAL_ROUTINE ApcRoutine,
//						   __in PVOID ApcContext OPTIONAL,
//						   __in PVOID Argument1 OPTIONAL,
//						   __in PVOID Argument2 OPTIONAL);
//
//
//NTSYSAPI NTSTATUS NTAPI ZwWriteVirtualMemory(__in HANDLE ProcessHandle,
//							   __in PVOID BaseAddress,
//							   __in PVOID Buffer,
//							   __in ULONG BufferLength,
//							   __out PULONG ReturnLength OPTIONAL);
//
//
//NTSYSAPI NTSTATUS NTAPI ZwSetSystemInformation(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
//								 __in __out PVOID SystemInformation,
//								 __in ULONG SystemInformationLength);

typedef struct _THREAD_BASIC_INFORMATION { 
	NTSTATUS ExitStatus; 
	PVOID TebBaseAddress; 
	ULONG UniqueProcessId; 
	ULONG UniqueThreadId; 
	KAFFINITY AffinityMask; 
	KPRIORITY BasePriority; 
	ULONG DiffProcessPriority; 
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef enum {
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;


typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	THREAD_STATE State;
	KWAIT_REASON WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters; // Windows 2000 only
	SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

//	ZwQueryInformationThread
typedef NTSTATUS (*ZWQUERYINFORMATIONTHREAD) (__in HANDLE ThreadHandle, 
												  __in THREADINFOCLASS ThreadInformationClass, 
												  __out PVOID ThreadInformation, 
												  __in ULONG ThreadInformationLength, 
												  __out PULONG ReturnLength OPTIONAL );


// ZwQueryInformationProcess
typedef NTSTATUS (*ZWQUERYINFORMATIONPROCESS)(__in HANDLE ProcessHandle,
											  __in PROCESSINFOCLASS ProcessInformationClass,
											  __out PVOID ProcessInformation,
											  __in ULONG ProcessInformationLength,
											  __out PULONG ReturnLength OPTIONAL);

// ZwQuerySystemInformation
typedef NTSTATUS (*ZWQUERYSYSTEMINFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
											 IN OUT PVOID SystemInformation,
											 IN ULONG SystemInformationLength,
											 OUT PULONG ReturnLength OPTIONAL);

