#include "Structs.h"

//////////////////////////////////////////////////////////////////////////
//宏定义、全局变量声明部分
//////////////////////////////////////////////////////////////////////////


//Hook函数个数
#define HOOKNUMS	18

typedef struct Hook{
	ULONG	OrgFunc;	//原始函数地址 ZwXXXX
	ULONG	NewFunc;	//替换函数地址
	ULONG	NtFunc;		//保存原始函数地址
}Hook,*pHook;


//导出全局变量 SSDT 表
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int	*ServiceTableBase;
	unsigned int	*ServiceCounterTableBase;
	unsigned int	NumberOfServices;
	unsigned char	*ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()
__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;




//可写的SSDT表的首地址
PVOID* NewSystemCall;


//SSDT Hook 功能的三个宏定义
//ZwXXXX mov eax,(NtNums)
#define HOOK_INDEX(Zw2Nt)				*(PULONG)((PUCHAR)Zw2Nt+1)

#define HOOK(OrgFunc,NewFunc,NtFunc)	NtFunc = (PVOID)InterlockedExchange((PLONG)&NewSystemCall[HOOK_INDEX(OrgFunc)],(LONG)NewFunc)

#define UNHOOK(OrgFunc,NtFunc)			InterlockedExchange((PLONG)&NewSystemCall[HOOK_INDEX(OrgFunc)],(LONG)NtFunc)


//////////////////////////////////////////////////////////////////////////
//函数声明部分
//////////////////////////////////////////////////////////////////////////

//驱动卸载函数
VOID OnUnload(__in PDRIVER_OBJECT DriverObject);
//初始化SSDT HOOK
NTSTATUS InitSsdtHook();
//打开全部SSDT HOOK
NTSTATUS SsdtHook(pHook pInfo,BOOLEAN bFlag);
//获得SSDT的未导出API地址
NTSTATUS GetSsdtApi(PCHAR szApiName,PUNICODE_STRING szDll);








#define NtLoadDriver			0x00
#define	NtCreateKey				0x01
#define NtSetValueKey			0x02
#define NtDeleteKey				0x03
#define NtDeleteVauleKey		0x04
#define NtCreateFile			0x05
#define NtWriteFile				0x06
#define NtSetInformationFile	0x07
#define NtOpenProcess			0x08
#define NtCreateProcess			0x09
#define NtCreateProcessEx		0x0A
#define NtTerminateProcess		0x0B
#define NtCreateThread			0x0C
#define NtTerminateThread		0x0D
#define NtQueueApcThread		0x0E
#define NtWriteVirtualMemory	0x0F
#define NtSetSystemInformation	0x10
#define NtDuplicateObject		0x11




//	NtCreateKey()
typedef NTSTATUS (*NTCREATEKEY)(__out PHANDLE KeyHandle, 
					            __in ACCESS_MASK DesiredAccess, 
								__in POBJECT_ATTRIBUTES ObjectAttributes, 
								__reserved ULONG TitleIndex,
								__in_opt PUNICODE_STRING Class, 
								__in ULONG CreateOptions, 
								__out_opt PULONG Disposition);

NTSTATUS NewCreateKey(__out PHANDLE KeyHandle, 
					  __in ACCESS_MASK DesiredAccess, 
					  __in POBJECT_ATTRIBUTES ObjectAttributes, 
					  __reserved ULONG TitleIndex,
					  __in_opt PUNICODE_STRING Class, 
					  __in ULONG CreateOptions, 
					  __out_opt PULONG Disposition);

//	NtSetValueKey()
typedef NTSTATUS (*NTSETVALUEKEY)(__in HANDLE KeyHandle, 
								  __in PUNICODE_STRING ValueName, 
								  __in_opt ULONG TitleIndex, 
								  __in ULONG Type, 
								  __in PVOID Data,
								  __in ULONG DataSize);

NTSTATUS NewSetValueKey(__in HANDLE KeyHandle, 
					    __in PUNICODE_STRING ValueName, 
					    __in_opt ULONG TitleIndex, 
					    __in ULONG Type, 
						__in PVOID Data,
						__in ULONG DataSize);

//	NtDeleteKey()
typedef NTSTATUS (*NTDELETEKEY)(__in HANDLE KeyHandle);

NTSTATUS NewDeleteKey(__in HANDLE KeyHandle);

//	NtDeleteVauleKey()
typedef NTSTATUS (*NTDELETEVALUEKEY)(__in HANDLE KeyHandle, 
									 __in PUNICODE_STRING ValueName);

NTSTATUS NewDeleteValueKey(__in HANDLE KeyHandle, 
						   __in PUNICODE_STRING ValueName);

//	NtCreateFile()
typedef NTSTATUS (*NTCREATEFILE)(__out PHANDLE FileHandle, 
								 __in ACCESS_MASK DesiredAccess, 
								 __in POBJECT_ATTRIBUTES ObjectAttributes, 
								 __out PIO_STATUS_BLOCK IoStatusBlock, 
								 __in_opt PLARGE_INTEGER AllocationSize, 
								 __in ULONG FileAttributes, 
								 __in ULONG ShareAccess, 
								 __in ULONG CreateDisposition, 
								 __in ULONG CreateOptions, 
								 __in PVOID EaBuffer OPTIONAL,
								 __in ULONG EaLength);

NTSTATUS NewCreateFile(__out PHANDLE FileHandle, 
					   __in ACCESS_MASK DesiredAccess, 
					   __in POBJECT_ATTRIBUTES ObjectAttributes, 
					   __out PIO_STATUS_BLOCK IoStatusBlock, 
					   __in_opt PLARGE_INTEGER AllocationSize, 
					   __in ULONG FileAttributes, 
					   __in ULONG ShareAccess, 
					   __in ULONG CreateDisposition, 
					   __in ULONG CreateOptions, 
					   __in PVOID EaBuffer OPTIONAL,
					   __in ULONG EaLength);


//	NtWriteFile()
typedef NTSTATUS (*NTWRITEFILE)(__in HANDLE FileHandle, 
								__in_opt HANDLE Event, 
								__in_opt PIO_APC_ROUTINE ApcRoutine, 
								__in_opt PVOID ApcContext, 
								__out PIO_STATUS_BLOCK IoStatusBlock,
								__in PVOID Buffer,
								__in ULONG Length,
								__in PLARGE_INTEGER ByteOffset OPTIONAL,
								__in PULONG Key OPTIONAL);

NTSTATUS NewWriteFile(__in HANDLE FileHandle, 
					  __in_opt HANDLE Event, 
					  __in_opt PIO_APC_ROUTINE ApcRoutine, 
					  __in_opt PVOID ApcContext, 
					  __out PIO_STATUS_BLOCK IoStatusBlock,
					  __in PVOID Buffer,
					  __in ULONG Length,
					  __in PLARGE_INTEGER ByteOffset OPTIONAL,
					  __in PULONG Key OPTIONAL);

//	NtSetInformationFile()
typedef NTSTATUS (*NTSETINFORMATIONFILE)(__in HANDLE FileHandle, 
										 __out PIO_STATUS_BLOCK IoStatusBlock, 
										 __in PVOID FileInformation,
										 __in ULONG FileInformationLength,
										 __in FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS NewSetInformationFile(__in HANDLE FileHandle, 
							   __out PIO_STATUS_BLOCK IoStatusBlock, 
							   __in PVOID FileInformation,
							   __in ULONG FileInformationLength,
							   __in FILE_INFORMATION_CLASS FileInformationClass);

//	NtOpenProcess()
typedef NTSTATUS (*NTOPENPROCESS)(__out PHANDLE ProcessHandle, 
								  __in ACCESS_MASK DesiredAccess, 
								  __in POBJECT_ATTRIBUTES ObjectAttributes, 
								  __in_opt PCLIENT_ID ClientId);

NTSTATUS NewOpenProcess(__out PHANDLE ProcessHandle, 
					    __in ACCESS_MASK DesiredAccess, 
					    __in POBJECT_ATTRIBUTES ObjectAttributes, 
					    __in_opt PCLIENT_ID ClientId);

//	NtCreateProcess()
typedef NTSTATUS (*NTCREATEPROCESS)(__out PHANDLE ProcessHandle,
									__in ACCESS_MASK DesiredAccess,
									__in POBJECT_ATTRIBUTES ObjectAttributes,
									__in HANDLE InheritFromProcessHandle,
									__in BOOLEAN InheritHandles,
									__in HANDLE SectionHandle OPTIONAL,
									__in HANDLE DebugPort OPTIONAL,
									__in HANDLE ExceptionPort OPTIONAL);

NTCREATEPROCESS ZwCreateProces = NULL;

NTSTATUS NewCreateProcess(__out PHANDLE ProcessHandle,
						  __in ACCESS_MASK DesiredAccess,
						  __in POBJECT_ATTRIBUTES ObjectAttributes,
						  __in HANDLE InheritFromProcessHandle,
						  __in BOOLEAN InheritHandles,
						  __in HANDLE SectionHandle OPTIONAL,
						  __in HANDLE DebugPort OPTIONAL,
						  __in HANDLE ExceptionPort OPTIONAL);

//	NtCreateProcessEx()
typedef NTSTATUS (*NTCREATEPROCESSEX)(__out PHANDLE ProcessHandle,
									  __in ACCESS_MASK DesiredAccess,
									  __in POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
									  __in HANDLE ParentProcess,
									  __in BOOLEAN InheritObjectTable,
									  __in HANDLE SectionHandle OPTIONAL,
									  __in HANDLE DebugPort OPTIONAL,
									  __in HANDLE ExceptionPort OPTIONAL,
									  __in HANDLE Unknown);
NTCREATEPROCESSEX ZwCreateProcessEx = NULL;

NTSTATUS NewCreateProcessEx(__out PHANDLE ProcessHandle,
						    __in ACCESS_MASK DesiredAccess,
						    __in POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
						    __in HANDLE ParentProcess,
						    __in BOOLEAN InheritObjectTable,
						    __in HANDLE SectionHandle OPTIONAL,
						    __in HANDLE DebugPort OPTIONAL,
						    __in HANDLE ExceptionPort OPTIONAL,
						    __in HANDLE Unknown);

//	NtTerminateProcess()
typedef NTSTATUS (*NTTERMINATEPROCESS)(__in_opt HANDLE ProcessHandle, 
									   __in NTSTATUS ExitStatus);

NTSTATUS NewTerminateProcess(__in_opt HANDLE ProcessHandle, 
							 __in NTSTATUS ExitStatus);

//	NtCreateThread()
typedef NTSTATUS (*NTCREATETHREAD)(__out PHANDLE ThreadHandle,
								   __in ACCESS_MASK DesiredAccess,
								   __in POBJECT_ATTRIBUTES ObjectAttributes,
								   __in HANDLE ProcessHandle,
								   __out PCLIENT_ID ClientId,
								   __in PCONTEXT ThreadContext,
								   __in PUSER_STACK UserStack,
								   __in BOOLEAN CreateSuspended);
NTCREATETHREAD ZwCreateThread = NULL;

NTSTATUS NewCreateThread(__out PHANDLE ThreadHandle,
					     __in ACCESS_MASK DesiredAccess,
					     __in POBJECT_ATTRIBUTES ObjectAttributes,
					     __in HANDLE ProcessHandle,
					     __out PCLIENT_ID ClientId,
					     __in PCONTEXT ThreadContext,
					     __in PUSER_STACK UserStack,
					     __in BOOLEAN CreateSuspended);

//	NtTerminateThread()
typedef NTSTATUS (*NTTERMINATETHREAD)(__in HANDLE ThreadHandle OPTIONAL,
									  __in NTSTATUS ExitStatus);

NTTERMINATETHREAD ZwTerminateThread = NULL;


NTSTATUS NewTerminateThread(__in HANDLE ThreadHandle OPTIONAL,
						    __in NTSTATUS ExitStatus);



//	NtQueueApcThread()
typedef NTSTATUS (*NTQUEUEAPCTHREAD)(__in HANDLE ThreadHandle,
									 __in PKNORMAL_ROUTINE ApcRoutine,
									 __in PVOID ApcContext OPTIONAL,
									 __in PVOID Argument1 OPTIONAL,
									 __in PVOID Argument2 OPTIONAL);
NTQUEUEAPCTHREAD ZwQueueApcThread = NULL;

NTSTATUS NewQueueApcThread(__in HANDLE ThreadHandle,
						   __in PKNORMAL_ROUTINE ApcRoutine,
						   __in PVOID ApcContext OPTIONAL,
						   __in PVOID Argument1 OPTIONAL,
						   __in PVOID Argument2 OPTIONAL);


//	NtWriteVirtualMemory()
typedef NTSTATUS (*NTWRITEVIRTUALMEMORY)(__in HANDLE ProcessHandle,
										 __in PVOID BaseAddress,
										 __in PVOID Buffer,
										 __in ULONG BufferLength,
										 __out PULONG ReturnLength OPTIONAL);
NTWRITEVIRTUALMEMORY ZwWriteVirtualMemory = NULL;

NTSTATUS NewWriteVirtualMemory(__in HANDLE ProcessHandle,
							   __in PVOID BaseAddress,
						       __in PVOID Buffer,
							   __in ULONG BufferLength,
							   __out PULONG ReturnLength OPTIONAL);

//	NtLoadDriver()
typedef NTSTATUS (*NTLOADDRIVER)(__in PUNICODE_STRING DriverServiceName);

NTSTATUS NewLoadDriver(__in PUNICODE_STRING DriverServiceName);

//	NtSetSystemInformation()
typedef NTSTATUS (*NTSETSYSTEMINFORMATION)(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
										   __in __out PVOID SystemInformation,
										   __in ULONG SystemInformationLength);

NTSETSYSTEMINFORMATION ZwSetSystemInformation = NULL;

NTSTATUS NewSetSystemInformation(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
							     __in __out PVOID SystemInformation,
							     __in ULONG SystemInformationLength);

// NtDuplicateObject()
typedef NTSTATUS (*NTDUPLICATEOBJECT)(__in HANDLE SourceProcessHandle,
									  __in HANDLE SourceHandle,
									  __in HANDLE TargetProcessHandle,
									  __out PHANDLE TargetHandle OPTIONAL,
									  __in ACCESS_MASK DesiredAccess,
									  __in ULONG Attributes,
									  __in ULONG Options);

NTSTATUS NewDuplicateObject(__in HANDLE SourceProcessHandle,
						    __in HANDLE SourceHandle,
						    __in HANDLE TargetProcessHandle,
						    __out PHANDLE TargetHandle OPTIONAL,
						    __in ACCESS_MASK DesiredAccess,
						    __in ULONG Attributes,
						    __in ULONG Options);
