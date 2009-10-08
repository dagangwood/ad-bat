#include "Sys.h"


//////////////////////////////////////////////////////////////////////////
//全局变量部分
//////////////////////////////////////////////////////////////////////////

PDRIVER_OBJECT pGlobalDvrObj;

Hook HookFunc[HOOKNUMS];

//设备名、符号链接名字符串
UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\AdBAT");
UNICODE_STRING symb_link = RTL_CONSTANT_STRING(L"\\DosDevices\\AdBAT");


//a event handle and object got from user mode 
HANDLE hIoEvent = NULL;
PVOID IoEventObject = NULL;
PVOID IoBuff = NULL;

//Happen when got a hook
HANDLE hJudgeEvent = NULL;
PVOID JudgeEventObject = NULL;
PVOID JudgeBuff = NULL;

//管理共享内存的互斥量
KMUTEX IoJudgeMutex;

//自身进程句柄及PID
ULONG	hGlobalSelfProcHandle = NULL;
ULONG	dwGlobalSelfPid		  = NULL;


//文件、注册表规则库头指针
LIST_ENTRY	FileListHdr;
LIST_ENTRY	RegListHdr;
NPAGED_LOOKASIDE_LIST	nPagedList;

NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriverObject,

					 __in PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;
	PDEVICE_OBJECT device;
	//int i = 0;

	//DbgPrint("DriverEntry() Function...\n");

	pGlobalDvrObj = pDriverObject;
	//生成设备对象
	status = IoCreateDevice(pDriverObject,
							NULL,
							&device_name,
							FILE_DEVICE_UNKNOWN,
							FILE_DEVICE_SECURE_OPEN,
							FALSE,
							&device);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//生成符号链接
	status = IoCreateSymbolicLink(&symb_link,&device_name);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device);
		return status;
	}

	//设备生成之后，打开初始化完成标记
	//device->Flags &= ~DO_DEVICE_INITIALIZING;





	//Display(&FileListHdr);

	//初始化SSDT Hook 操作
	status = InitSsdtHook();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//开始SSDT Hook
	//for (i=0;i<HOOKNUMS;i++)
	//{
	//	SsdtHook(&HookFunc[i],TRUE);
	//}

	// 驱动卸载函数 
	pDriverObject->DriverUnload = OnUnload;
	//打开、关闭设备函数
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]  = CreateClose;
	// IOCTL分发函数
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;


	return status;
}


//驱动卸载函数
VOID OnUnload(__in PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT pdoNextDeviceObj = pGlobalDvrObj->DeviceObject;
	//循环用
	int i = 0;
	
	//DbgPrint("OnUnload() Function...\n");

	IoDeleteSymbolicLink(&symb_link);


	for (i=0;i<HOOKNUMS;i++)
	{
		SsdtHook(&HookFunc[i],FALSE);
	}

	Display(&FileListHdr);
	Display(&RegListHdr);

	// 删除所有驱动设备句柄
	while(pdoNextDeviceObj)
	{
		PDEVICE_OBJECT pdoThisDeviceObj = pdoNextDeviceObj;
		pdoNextDeviceObj = pdoThisDeviceObj->NextDevice;
		IoDeleteDevice(pdoThisDeviceObj);
	}
}


//初始化SSDT HOOK
NTSTATUS InitSsdtHook()
{
	//循环用
	int i = 0;
	UNICODE_STRING	szName;
	UNICODE_STRING szDll;
	PMDL pMdl;
	RtlInitUnicodeString(&szDll, L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntdll.dll");
	RtlInitUnicodeString(&szName,L"ZwSetSystemInformation");



	//DbgPrint("InitSsdtHoot() Function...");

	//先清零
	for (i=0;i<HOOKNUMS;i++)
	{
		HookFunc[i].NewFunc = 0x00;
		HookFunc[i].NtFunc = 0x00;
		HookFunc[i].ZwIndex = 0x00;
	}


	//注册Hook信息
	//NtLoadDriver()
	HookFunc[NtLoadDriver].ZwIndex = HOOK_INDEX(ZwLoadDriver);
	HookFunc[NtLoadDriver].NewFunc = NewLoadDriver;
	//NtCreateKey()
	HookFunc[NtCreateKey].ZwIndex = HOOK_INDEX(ZwCreateKey);
	HookFunc[NtCreateKey].NewFunc = NewCreateKey;
	//NtSetValueKey()
	HookFunc[NtSetValueKey].ZwIndex = HOOK_INDEX(ZwSetValueKey);
	HookFunc[NtSetValueKey].NewFunc = NewSetValueKey;
	//NtDeleteKey()
	HookFunc[NtDeleteKey].ZwIndex = HOOK_INDEX(ZwDeleteKey);
	HookFunc[NtDeleteKey].NewFunc = NewDeleteKey;
	//NtDeleteVauleKey()
	HookFunc[NtDeleteVauleKey].ZwIndex = HOOK_INDEX(ZwDeleteValueKey);
	HookFunc[NtDeleteVauleKey].NewFunc = NewDeleteValueKey;
	//NtCreateFile()
	HookFunc[NtCreateFile].ZwIndex = HOOK_INDEX(ZwCreateFile);
	HookFunc[NtCreateFile].NewFunc = NewCreateFile;
	//NtWriteFile()
	HookFunc[NtWriteFile].ZwIndex = HOOK_INDEX(ZwWriteFile);
	HookFunc[NtWriteFile].NewFunc = NewWriteFile;
	//NtSetInformationFile()
	HookFunc[NtSetInformationFile].ZwIndex = HOOK_INDEX(ZwSetInformationFile);
	HookFunc[NtSetInformationFile].NewFunc = NewSetInformationFile;
	//NtOpenProcess()
	HookFunc[NtOpenProcess].ZwIndex = HOOK_INDEX(ZwOpenProcess);
	HookFunc[NtOpenProcess].NewFunc = NewOpenProcess;
	//NtCreateProcess()
	HookFunc[NtCreateProcess].ZwIndex = HOOK_INDEX(GetSsdtApi("ZwCreateProcess",&szDll));
	HookFunc[NtCreateProcess].NewFunc = NewCreateProcess;
	//NtCreateProcessEx()
	HookFunc[NtCreateProcessEx].ZwIndex = HOOK_INDEX(GetSsdtApi("ZwCreateProcessEx",&szDll));
	HookFunc[NtCreateProcessEx].NewFunc = NewCreateProcessEx;
	//NtTerminateProcess()
	HookFunc[NtTerminateProcess].ZwIndex = HOOK_INDEX(ZwTerminateProcess);
	HookFunc[NtTerminateProcess].NewFunc = NewTerminateProcess;
	//NtCreateThread()
	HookFunc[NtCreateThread].ZwIndex = HOOK_INDEX(GetSsdtApi("ZwCreateThread",&szDll));
	HookFunc[NtCreateThread].NewFunc = NewCreateThread;
	//NtTerminateThread()
	HookFunc[NtTerminateThread].ZwIndex = HOOK_INDEX(GetSsdtApi("ZwTerminateThread",&szDll));
	HookFunc[NtTerminateThread].NewFunc = NewTerminateThread;
	//NtQueueApcThread()
	HookFunc[NtQueueApcThread].ZwIndex = HOOK_INDEX(GetSsdtApi("ZwQueueApcThread",&szDll));
	HookFunc[NtQueueApcThread].NewFunc = NewQueueApcThread;
	//NtWriteVirtualMemory()
	HookFunc[NtWriteVirtualMemory].ZwIndex = HOOK_INDEX(GetSsdtApi("ZwWriteVirtualMemory",&szDll));
	HookFunc[NtWriteVirtualMemory].NewFunc = NewWriteVirtualMemory;
	//NtSetSystemInformation()
	HookFunc[NtSetSystemInformation].ZwIndex = HOOK_INDEX(MmGetSystemRoutineAddress(&szName));
	HookFunc[NtSetSystemInformation].NewFunc = NewSetSystemInformation;
	//NtDuplicateObject()
	HookFunc[NtDuplicateObject].ZwIndex = HOOK_INDEX(ZwDuplicateObject);
	HookFunc[NtDuplicateObject].NewFunc = NewDuplicateObject;

	//使SSDT表可写,并保存可写的首地址
	pMdl = MmCreateMdl(NULL,KeServiceDescriptorTable.ServiceTableBase,KeServiceDescriptorTable.NumberOfServices*4);

	//DbgPrint("SsdtHook() Function...\n");

	if (!pMdl)
	{
		return STATUS_UNSUCCESSFUL;
	}

	MmBuildMdlForNonPagedPool(pMdl);

	pMdl->MdlFlags = pMdl->MdlFlags|MDL_MAPPED_TO_SYSTEM_VA;
	NewSystemCall = (PVOID*)MmMapLockedPages(pMdl,KernelMode);

	if (!NewSystemCall)
	{
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


//SSDT Hook or UnHook
NTSTATUS SsdtHook(pHook pInfo,BOOLEAN bFlag)
{
	if (bFlag == TRUE)
	{
		//HOOK(pInfo->ZwIndex,pInfo->NewFunc,pInfo->NtFunc);
		pInfo->NtFunc = InterlockedExchange((PLONG)&NewSystemCall[pInfo->ZwIndex],(LONG)pInfo->NewFunc);
	}
	else
	{
		//UNHOOK(pInfo->ZwIndex,pInfo->NtFunc);
		InterlockedExchange((PLONG)&NewSystemCall[pInfo->ZwIndex],(LONG)pInfo->NtFunc);
	}

	return STATUS_SUCCESS;
}






//////////////////////////////////////////////////////////////////////////
//Hook 函数部分
//////////////////////////////////////////////////////////////////////////

NTSTATUS NewLoadDriver(__in PUNICODE_STRING DriverServiceName)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTLOADDRIVER OldNtFunc;
	
	//DbgPrint("NewLoadDriver() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_INFO;
	pEvent->Behavior	= NtLoadDriver;
	String2Target(pEvent,DriverServiceName);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	OldNtFunc= HookFunc[NtLoadDriver].NtFunc;

	status = OldNtFunc(DriverServiceName);

	return status;
}


NTSTATUS NewCreateKey(__out PHANDLE KeyHandle, 
					  __in ACCESS_MASK DesiredAccess, 
					  __in POBJECT_ATTRIBUTES ObjectAttributes, 
					  __reserved ULONG TitleIndex, 
					  __in_opt PUNICODE_STRING Class,
					  __in ULONG CreateOptions, 
					  __out_opt PULONG Disposition)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTCREATEKEY OldNtFunc = HookFunc[NtCreateKey].NtFunc;

	//DbgPrint("NewCreateKey() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_REG;
	pEvent->Behavior	= NtCreateKey;
	if (ObjectAttributes!=NULL)
	{
		String2Target(pEvent,ObjectAttributes->ObjectName);
	}
	//Handle2Target(pGlobalEvent,KeyHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(KeyHandle,
					   DesiredAccess,
					   ObjectAttributes,
					   TitleIndex,
					   Class,
					   CreateOptions,
					   Disposition);

	return status;
}


NTSTATUS NewSetValueKey(__in HANDLE KeyHandle, 
						__in PUNICODE_STRING ValueName, 
						__in_opt ULONG TitleIndex, 
						__in ULONG Type, 
						__in PVOID Data,
						__in ULONG DataSize)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTSETVALUEKEY OldNtFunc = HookFunc[NtSetValueKey].NtFunc;

	//DbgPrint("NewSetValueKey() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_REG;
	pEvent->Behavior	= NtSetValueKey;
	Handle2Target(pEvent,KeyHandle);
	String2Target(pEvent,ValueName);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(KeyHandle,
					   ValueName,
					   TitleIndex,
					   Type,
					   Data,
					   DataSize);


	return status;
}


NTSTATUS NewDeleteKey(__in HANDLE KeyHandle)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTDELETEKEY OldNtFunc = HookFunc[NtDeleteKey].NtFunc;

	//DbgPrint("NewDeleteKey() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_REG;
	pEvent->Behavior	= NtDeleteKey;
	Handle2Target(pEvent,KeyHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(KeyHandle);

	return status;
}

NTSTATUS NewDeleteValueKey(__in HANDLE KeyHandle, 
						   __in PUNICODE_STRING ValueName)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTDELETEVALUEKEY OldNtFunc = HookFunc[NtDeleteVauleKey].NtFunc;

	//DbgPrint("NewDeleteValueKey() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_REG;
	pEvent->Behavior	= NtDeleteVauleKey;
	Handle2Target(pEvent,KeyHandle);
	String2Target(pEvent,ValueName);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(KeyHandle,
					   ValueName);

	return status;
}

//	NtCreateFile()
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
					   __in ULONG EaLength)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTCREATEFILE OldNtFunc = HookFunc[NtCreateFile].NtFunc;

	//DbgPrint("NewCreateFile() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_FILE;
	pEvent->Behavior	= NtCreateFile;
	if (ObjectAttributes!=NULL)
	{
		String2Target(pEvent,ObjectAttributes->ObjectName);
	}

	
	//Handle2Target(pGlobalEvent,FileHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(FileHandle,
					   DesiredAccess,
					   ObjectAttributes,
					   IoStatusBlock,
					   AllocationSize,
					   FileAttributes,
					   ShareAccess,
					   CreateDisposition,
					   CreateOptions,
					   EaBuffer,
					   EaLength);

	return status;
}


//	NtWriteFile()
NTSTATUS NewWriteFile(__in HANDLE FileHandle, 
					  __in_opt HANDLE hEvent, 
					  __in_opt PIO_APC_ROUTINE ApcRoutine, 
					  __in_opt PVOID ApcContext, 
					  __out PIO_STATUS_BLOCK IoStatusBlock,
					  __in PVOID Buffer,
					  __in ULONG Length,
					  __in PLARGE_INTEGER ByteOffset OPTIONAL,
					  __in PULONG Key OPTIONAL)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTWRITEFILE OldNtFunc = HookFunc[NtWriteFile].NtFunc;

	//DbgPrint("NewWriteFile() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_FILE;
	pEvent->Behavior	= NtWriteFile;
	Handle2Target(pEvent,FileHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	//if (JudgeByUser(pEvent))
	//{
	//	goto _label;
	//}
	//else
	//{
	//	//TODO.. 善后工作
	//}

_label:
	status = OldNtFunc(FileHandle,
					   hEvent,
					   ApcRoutine,
					   ApcContext,
					   IoStatusBlock,
					   Buffer,
					   Length,
					   ByteOffset,
					   Key);

	return status;
}

//	NtSetInformationFile()
NTSTATUS NewSetInformationFile(__in HANDLE FileHandle, 
							   __out PIO_STATUS_BLOCK IoStatusBlock, 
							   __in PVOID FileInformation,
							   __in ULONG FileInformationLength,
							   __in FILE_INFORMATION_CLASS FileInformationClass)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTSETINFORMATIONFILE OldNtFunc = HookFunc[NtSetInformationFile].NtFunc;

	//DbgPrint("NewSetInformationFile() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_FILE;
	pEvent->Behavior	= NtSetInformationFile;
	Handle2Target(pEvent,FileHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(FileHandle,
					   IoStatusBlock,
					   FileInformation,
					   FileInformationLength,
					   FileInformationClass);

	return status;
}

//	NtOpenProcess()
NTSTATUS NewOpenProcess(__out PHANDLE ProcessHandle, 
						__in ACCESS_MASK DesiredAccess, 
						__in POBJECT_ATTRIBUTES ObjectAttributes, 
						__in_opt PCLIENT_ID ClientId)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;

	NTOPENPROCESS OldNtFunc = HookFunc[NtOpenProcess].NtFunc;

	//DbgPrint("NewOpenProcess() Function...\n");

	//填充行为记录结构体
	//RtlZeroMemory(pGlobalEvent,sizeof(Event));
	//pGlobalEvent->Type		= EVENT_TPYE_PROC;
	//pGlobalEvent->Behavior	= NtOpenProcess;
	//String2Target(pGlobalEvent,ObjectAttributes->ObjectName);

	//不填充行为记录结构体，只判断是否对Ad-BAT自身有危害

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否对Ad-BAT不利？
	if (ClientId->UniqueProcess == pEvent->Pid)
	{
		goto _label_evil;
	}
	////是否在白名单中？
	//if (IsInWhiteList(pGlobalEvent))
	//{
	//	goto _label;
	//}
	////用户层判断结果？
	//if (JudgeByUser(pGlobalEvent))
	//{
	//	goto _label;
	//}
_label_evil:
	//TODO.. 善后工作

_label:
	status = OldNtFunc(ProcessHandle,
					   DesiredAccess,
					   ObjectAttributes,
					   ClientId);

	return status;
}

//	NtCreateProcess()
NTSTATUS NewCreateProcess(__out PHANDLE ProcessHandle,
						  __in ACCESS_MASK DesiredAccess,
						  __in POBJECT_ATTRIBUTES ObjectAttributes,
						  __in HANDLE InheritFromProcessHandle,
						  __in BOOLEAN InheritHandles,
						  __in HANDLE SectionHandle OPTIONAL,
						  __in HANDLE DebugPort OPTIONAL,
						  __in HANDLE ExceptionPort OPTIONAL)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTCREATEPROCESS OldNtFunc = HookFunc[NtCreateProcess].NtFunc;

	//DbgPrint("NewCreateProcess() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_PROC;
	pEvent->Behavior	= NtCreateProcess;
	Handle2Target(pEvent,SectionHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(ProcessHandle,
					   DesiredAccess,
					   ObjectAttributes,
					   InheritFromProcessHandle,
					   InheritHandles,
					   SectionHandle,
					   DebugPort,
					   ExceptionPort);

	return status;
}

//	NtCreateProcessEx()
NTSTATUS NewCreateProcessEx(__out PHANDLE ProcessHandle,
							__in ACCESS_MASK DesiredAccess,
							__in POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
							__in HANDLE ParentProcess,
							__in BOOLEAN InheritObjectTable,
							__in HANDLE SectionHandle OPTIONAL,
							__in HANDLE DebugPort OPTIONAL,
							__in HANDLE ExceptionPort OPTIONAL,
							__in HANDLE Unknown)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTCREATEPROCESSEX OldNtFunc = HookFunc[NtCreateProcessEx].NtFunc;

	//DbgPrint("NewCreateProcessEx() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_PROC;
	pEvent->Behavior	= NtCreateProcessEx;
	Handle2Target(pEvent,SectionHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(ProcessHandle,
					   DesiredAccess,
					   ObjectAttributes,
					   ParentProcess,
					   InheritObjectTable,
					   SectionHandle,
					   DebugPort,
					   ExceptionPort,
					   Unknown);

	return status;
}

//	NtTerminateProcess()
NTSTATUS NewTerminateProcess(__in_opt HANDLE ProcessHandle, 
							 __in NTSTATUS ExitStatus)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTTERMINATEPROCESS OldNtFunc = HookFunc[NtTerminateProcess].NtFunc;

	//DbgPrint("NewTerminateProcess() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_PROC;
	pEvent->Behavior	= NtTerminateProcess;
	Handle2Target(pEvent,ProcessHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(ProcessHandle,
					   ExitStatus);

	return status;
}

//	NtCreateThread()
NTSTATUS NewCreateThread(__out PHANDLE ThreadHandle,
						 __in ACCESS_MASK DesiredAccess,
						 __in POBJECT_ATTRIBUTES ObjectAttributes,
						 __in HANDLE ProcessHandle,
						 __out PCLIENT_ID ClientId,
						 __in PCONTEXT ThreadContext,
						 __in PUSER_STACK UserStack,
						 __in BOOLEAN CreateSuspended)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;

	NTCREATETHREAD OldNtFunc = HookFunc[NtCreateThread].NtFunc;

	//DbgPrint("NewCreateThread() Function...\n");

	//填充行为记录结构体
	//RtlZeroMemory(pGlobalEvent,sizeof(Event));
	//pGlobalEvent->Type		= EVENT_TPYE_PROC;
	//pGlobalEvent->Behavior	= NtCreateThread;


	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否对Ad-BAT不利？
	if (ClientId->UniqueProcess == pEvent->Pid)
	{
		goto _label_evil;
	}
	////是否在白名单中？
	//if (IsInWhiteList(pGlobalEvent))
	//{
	//	goto _label;
	//}
	////用户层判断结果？
	//if (JudgeByUser(pGlobalEvent))
	//{
	//	goto _label;
	//}
	//else
	//{
	//	//TODO.. 善后工作
	//}
_label_evil:
	//TODO.. 善后工作

_label:
	status = OldNtFunc(ThreadHandle,
				   	   DesiredAccess,
					   ObjectAttributes,
					   ProcessHandle,
					   ClientId,
					   ThreadContext,
					   UserStack,
					   CreateSuspended);

	return status;
}

//	NtTerminateThread()
NTSTATUS NewTerminateThread(__in HANDLE ThreadHandle OPTIONAL,
							__in NTSTATUS ExitStatus)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTTERMINATETHREAD OldNtFunc = HookFunc[NtTerminateThread].NtFunc;

	//DbgPrint("NewTerminateThread() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_PROC;
	pEvent->Behavior	= NtTerminateThread;
	Handle2Target(pEvent,ThreadHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(ThreadHandle,
				       ExitStatus);

	return status;
}


//	NtQueueApcThread()
NTSTATUS NewQueueApcThread(__in HANDLE ThreadHandle,
						   __in PKNORMAL_ROUTINE ApcRoutine,
						   __in PVOID ApcContext OPTIONAL,
						   __in PVOID Argument1 OPTIONAL,
						   __in PVOID Argument2 OPTIONAL)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTQUEUEAPCTHREAD OldNtFunc = HookFunc[NtQueueApcThread].NtFunc;

	//DbgPrint("NewQueueApcThread() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_PROC;
	pEvent->Behavior	= NtQueueApcThread;
	Handle2Target(pEvent,ThreadHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(ThreadHandle,
					   ApcRoutine,
					   ApcContext,
					   Argument1,
					   Argument2);

	return status;
}


//	NtWriteVirtualMemory()
NTSTATUS NewWriteVirtualMemory(__in HANDLE ProcessHandle,
							   __in PVOID BaseAddress,
							   __in PVOID Buffer,
							   __in ULONG BufferLength,
							   __out PULONG ReturnLength OPTIONAL)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;
	NTWRITEVIRTUALMEMORY OldNtFunc = HookFunc[NtWriteVirtualMemory].NtFunc;

	//DbgPrint("NewWriteVirtualMemory() Function...\n");
	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_PROC;
	pEvent->Behavior	= NtWriteVirtualMemory;
	Handle2Target(pEvent,ProcessHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(ProcessHandle,
					   BaseAddress,
					   Buffer,
					   BufferLength,
					   ReturnLength);

	return status;
}

//	NtSetSystemInformation()
NTSTATUS NewSetSystemInformation(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
								 __in __out PVOID SystemInformation,
								 __in ULONG SystemInformationLength)
{
	Event	LocalEvent;
	Event*	pEvent = &LocalEvent;
	NTSTATUS status;

	NTSETSYSTEMINFORMATION OldNtFunc = HookFunc[NtSetSystemInformation].NtFunc;

	//是否加载驱动？
	if (SystemInformationClass !=  SystemLoadAndCallImage)
	{
		goto _label;
	}

	//DbgPrint("NewSetSystemInformation() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_INFO;
	pEvent->Behavior	= NtSetSystemInformation;
	String2Target(pEvent,SystemInformation);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
	else
	{
		//TODO.. 善后工作
	}

_label:
	status = OldNtFunc(SystemInformationClass,
					   SystemInformation,
					   SystemInformationLength);

	return status;
}

// NtDuplicateObject()
NTSTATUS NewDuplicateObject(__in HANDLE SourceProcessHandle,
							__in HANDLE SourceHandle,
							__in HANDLE TargetProcessHandle,
							__out PHANDLE TargetHandle OPTIONAL,
							__in ACCESS_MASK DesiredAccess,
							__in ULONG Attributes,
							__in ULONG Options)
{
	Event	LocalEvent;
	Event* pEvent = &LocalEvent;
	NTSTATUS status;

	NTDUPLICATEOBJECT OldNtFunc = HookFunc[NtDuplicateObject].NtFunc;

	//DbgPrint("NewDuplicateObject() Function...\n");

	//填充行为记录结构体
	RtlZeroMemory(pEvent,sizeof(Event));
	pEvent->Type		= EVENT_TPYE_INFO;
	pEvent->Behavior	= NtDuplicateObject;
	Handle2Target(pEvent,TargetProcessHandle);

	//是否自身行为？
	if (IsTrustedProcess(pEvent))
	{
		goto _label;
	}
	//是否对Ad-BAT不利？
	if (TargetProcessHandle == PsGetCurrentProcess())
	{
		goto _label_evil;
	}
	//是否在白名单中？
	if (IsInWhiteList(pEvent))
	{
		goto _label;
	}
	//用户层判断结果？
	if (JudgeByUser(pEvent))
	{
		goto _label;
	}
_label_evil:


_label:
	status = OldNtFunc(SourceProcessHandle,
					  SourceHandle,
					  TargetProcessHandle,
					  TargetHandle,
					  DesiredAccess,
					  Attributes,
					  Options);

	return status;
}


//获得SSDT的未导出API地址
NTSTATUS GetSsdtApi(PCHAR szApiName,PUNICODE_STRING szDll)
{
	HANDLE hThread, hSection, hFile, hMod;
	SECTION_IMAGE_INFORMATION sii;
	IMAGE_DOS_HEADER* dosheader;
	IMAGE_OPTIONAL_HEADER* opthdr;
	IMAGE_EXPORT_DIRECTORY* pExportTable;
	DWORD* arrayOfFunctionAddresses;
	DWORD* arrayOfFunctionNames;
	WORD* arrayOfFunctionOrdinals;
	DWORD functionOrdinal;
	DWORD Base, x, functionAddress;
	char* functionName;
	STRING ntFunctionName, ntFunctionNameSearch;
	PVOID BaseAddress = NULL;
	SIZE_T size=0;

	OBJECT_ATTRIBUTES oa = {sizeof oa, 0, szDll, OBJ_CASE_INSENSITIVE};

	IO_STATUS_BLOCK iosb;

	//_asm int 3;
	ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	oa.ObjectName = 0;

	ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0,PAGE_EXECUTE, SEC_IMAGE, hFile);

	ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE); 

	ZwClose(hFile);

	//BaseAddress = GetModlueBaseAdress("ntoskrnl.exe");

	hMod = BaseAddress;

	dosheader = (IMAGE_DOS_HEADER *)hMod;

	opthdr =(IMAGE_OPTIONAL_HEADER *) ((BYTE*)hMod+dosheader->e_lfanew+24);

	pExportTable =(IMAGE_EXPORT_DIRECTORY*)((BYTE*) hMod + opthdr->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress);

	// now we can get the exported functions, but note we convert from RVA to address
	arrayOfFunctionAddresses = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfFunctions);

	arrayOfFunctionNames = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfNames);

	arrayOfFunctionOrdinals = (WORD*)( (BYTE*)hMod + pExportTable->AddressOfNameOrdinals);

	Base = pExportTable->Base;

	RtlInitString(&ntFunctionNameSearch, szApiName);

	for(x = 0; x < pExportTable->NumberOfFunctions; x++)
	{
		functionName = (char*)( (BYTE*)hMod + arrayOfFunctionNames[x]);

		RtlInitString(&ntFunctionName, functionName);

		functionOrdinal = arrayOfFunctionOrdinals[x] + Base - 1; // always need to add base, -1 as array counts from 0
		// this is the funny bit.  you would expect the function pointer to simply be arrayOfFunctionAddresses[x]...
		// oh no... thats too simple.  it is actually arrayOfFunctionAddresses[functionOrdinal]!!
		functionAddress = (DWORD)( (BYTE*)hMod + arrayOfFunctionAddresses[functionOrdinal]);
		if (RtlCompareString(&ntFunctionName, &ntFunctionNameSearch, TRUE) == 0) 
		{
			//ZwClose(hSection);
			return functionAddress;
		}
	}

	//ZwClose(hSection);
	return 0;
}

//打开或者关闭设备
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject,PIRP irp)
{
	return STATUS_NOT_SUPPORTED;
}


//IOCONTROL 分发函数
NTSTATUS DeviceControl(PDEVICE_OBJECT pDeviceObject,PIRP pIrp)
{
	int i = 0;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);
	UNICODE_STRING	FileListName,RegListName;
	NTSTATUS Status;

	ULONG BuffPtr = NULL;

	ULONG Code = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	ULONG InputLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

	ULONG OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

	PVOID pIoBuff = pIrp->AssociatedIrp.SystemBuffer;

	//DbgPrint("DeviceIoControl() Function...\n");

	switch(Code)
	{
	case PROC_ON:
		{
			//DbgPrint("PROC_ON");

			SsdtHook(&HookFunc[NtOpenProcess],TRUE);
			SsdtHook(&HookFunc[NtCreateProcess],TRUE);
			SsdtHook(&HookFunc[NtCreateProcessEx],TRUE);
			SsdtHook(&HookFunc[NtTerminateProcess],TRUE);
			SsdtHook(&HookFunc[NtCreateThread],TRUE);
			SsdtHook(&HookFunc[NtTerminateThread],TRUE);
			SsdtHook(&HookFunc[NtQueueApcThread],TRUE);
			SsdtHook(&HookFunc[NtWriteVirtualMemory],TRUE);
		}
		break;
	case PROC_OFF:
		{
			//DbgPrint("PROC_OFF");

			SsdtHook(&HookFunc[NtOpenProcess],FALSE);
			SsdtHook(&HookFunc[NtCreateProcess],FALSE);
			SsdtHook(&HookFunc[NtCreateProcessEx],FALSE);
			SsdtHook(&HookFunc[NtTerminateProcess],FALSE);
			SsdtHook(&HookFunc[NtCreateThread],FALSE);
			SsdtHook(&HookFunc[NtTerminateThread],FALSE);
			SsdtHook(&HookFunc[NtQueueApcThread],FALSE);
			SsdtHook(&HookFunc[NtWriteVirtualMemory],FALSE);
		}
		break;
	case REG_ON:
		{
			//DbgPrint("REG_ON");

			SsdtHook(&HookFunc[NtCreateKey],TRUE);
			SsdtHook(&HookFunc[NtSetValueKey],TRUE);
			SsdtHook(&HookFunc[NtDeleteKey],TRUE);
			SsdtHook(&HookFunc[NtDeleteVauleKey],TRUE);
		}
		break;
	case REG_OFF:
		{
			//DbgPrint("REG_OFF");

			SsdtHook(&HookFunc[NtCreateKey],FALSE);
			SsdtHook(&HookFunc[NtSetValueKey],FALSE);
			SsdtHook(&HookFunc[NtDeleteKey],FALSE);
			SsdtHook(&HookFunc[NtDeleteVauleKey],FALSE);
		}
		break;
	case FILE_ON:
		{
			//DbgPrint("FILE_ON");

			SsdtHook(&HookFunc[NtCreateFile],TRUE);
			SsdtHook(&HookFunc[NtWriteFile],TRUE);
			SsdtHook(&HookFunc[NtSetInformationFile],TRUE);
		}
		break;
	case FILE_OFF:
		{
			//DbgPrint("FILE_OFF");

			SsdtHook(&HookFunc[NtCreateFile],FALSE);
			SsdtHook(&HookFunc[NtWriteFile],FALSE);
			SsdtHook(&HookFunc[NtSetInformationFile],FALSE);
		}
		break;
	case OTHER_ON:
		{
			//DbgPrint("OTHER_ON\n");

			SsdtHook(&HookFunc[NtLoadDriver],TRUE);
			SsdtHook(&HookFunc[NtSetSystemInformation],TRUE);
			SsdtHook(&HookFunc[NtDuplicateObject],TRUE);
		}
		break;
	case OTHER_OFF:
		{
			//DbgPrint("OTHER_OFF\n");

			SsdtHook(&HookFunc[NtLoadDriver],FALSE);
			SsdtHook(&HookFunc[NtSetSystemInformation],FALSE);
			SsdtHook(&HookFunc[NtDuplicateObject],FALSE);
		}
		break;
	case INFO_OUT:
		{
			DbgPrint("INFO_OUT  begin...");
		}
		break;
	case INFO_IN:
		{
			DbgPrint("INFO_IN");

		}
		break;
	case GET_PID_EVENT:
		{
			//DbgPrint("GET_PID_EVENT");

			//获得自身进程句柄及PID
			hGlobalSelfProcHandle = PsGetCurrentProcess();
			dwGlobalSelfPid		= PsGetCurrentProcessId();


			//读取规则库文件
			RtlInitUnicodeString(&FileListName,L"\\??\\C:\\File.rul");
			ReadRules(&FileListName,&FileListHdr);

			RtlInitUnicodeString(&RegListName,L"\\??\\C:\\Registry.rul");
			ReadRules(&RegListName,&RegListHdr);

			//Got event object from user mode
			if (InputLength!=sizeof(HANDLE)*4 || pIoBuff==NULL)
			{
				DbgPrint("Get event object failed...");
				break;
			}

			hIoEvent = *(HANDLE*)pIoBuff;
			ObReferenceObjectByHandle(hIoEvent,GENERIC_ALL,NULL,KernelMode,&IoEventObject,NULL);

			hJudgeEvent = *(HANDLE*)((ULONG)pIoBuff+sizeof(ULONG));
			ObReferenceObjectByHandle(hJudgeEvent,GENERIC_ALL,NULL,KernelMode,&JudgeEventObject,NULL);

			RtlCopyMemory(&BuffPtr,(ULONG)pIoBuff+sizeof(ULONG)*2,sizeof(ULONG));
			IoBuff = (PVOID)MmMapIoSpace(MmGetPhysicalAddress((PVOID)BuffPtr),sizeof(Event),0);

			RtlCopyMemory(&BuffPtr,(ULONG)pIoBuff+sizeof(ULONG)*3,sizeof(ULONG));
			JudgeBuff = (PVOID)MmMapIoSpace(MmGetPhysicalAddress((PVOID)BuffPtr),sizeof(BOOLEAN),0);

			KeInitializeMutex(&IoJudgeMutex,0);



			//开始SSDT Hook
			for (i=0;i<HOOKNUMS;i++)
			{
				SsdtHook(&HookFunc[i],TRUE);
			}
		}
		break;
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return pIrp->IoStatus.Status;
}


//////////////////////////////////////////////////////////////////////////
//内核判断逻辑函数
//////////////////////////////////////////////////////////////////////////
//是否为可信行为(尚未进行扩展)
BOOLEAN IsTrustedProcess(Event* pEvent)
{
	pEvent->Pid = PsGetCurrentProcessId();
	
	return hGlobalSelfProcHandle == PsGetCurrentProcess() ? TRUE : FALSE;
}
//是否在白名单中
BOOLEAN IsInWhiteList(Event* pEvent)
{
	//TODO.. 白名单判断，现在先用于行为dbgprint

	PLIST_ENTRY pListPtrNow;

	BOOLEAN JudgeRst = TRUE;

	BOOLEAN IsRstOut = FALSE;

	ULONG index = 0;

	PListItem pListItemTemp = NULL;

	HashsList HashsListTemp;



	HashsListTemp.pHashsF = GetHashsF(&HashsListTemp.HashslenF,pEvent->Target);

	HashsListTemp.pHashsB = GetHashsB(&HashsListTemp.HashslenB,pEvent->Target);


	switch (pEvent->Type)
	{
	case EVENT_TPYE_FILE:
		{
			//DbgPrint("EVENT_TYPE_FILE");
			DbgPrint("FILE LIST:\t%d\t%d\t%d\t%s\n",pEvent->Type,pEvent->Behavior,pEvent->Pid,pEvent->Target);
			JudgeRst = TRUE;
			pListPtrNow = FileListHdr.Flink;
			while(pListPtrNow!=&FileListHdr&&!IsRstOut)
			{
				pListItemTemp = (PListItem)CONTAINING_RECORD(pListPtrNow,ListItem,ListEntry);
				if (pListItemTemp->Length<=HashsListTemp.HashslenF)
				{
					switch(pListItemTemp->Type)
					{
					case '+':
						{
							if (HashsListTemp.pHashsF[pListItemTemp->Length-1]==pListItemTemp->Hash)
							{
								IsRstOut = TRUE;
								JudgeRst = TRUE;
								pEvent->RuleIndex = index;
							}
						}
						break;
					case '-':
						{
							if (HashsListTemp.pHashsF[pListItemTemp->Length-1]==pListItemTemp->Hash)
							{
								IsRstOut = TRUE;
								JudgeRst = FALSE;
								pEvent->RuleIndex = index;
							}

						}
						break;
					case '>':
						{
							if (HashsListTemp.pHashsB[pListItemTemp->Length-1]==pListItemTemp->Hash)
							{
								IsRstOut = TRUE;
								JudgeRst = TRUE;
								pEvent->RuleIndex = index;
							}
						}
						break;
					case '<':
						{
							if (HashsListTemp.pHashsB[pListItemTemp->Length-1]==pListItemTemp->Hash)
							{
								IsRstOut = TRUE;
								JudgeRst = FALSE;
								pEvent->RuleIndex = index;
							}
						}
						break;
					}
				}
				
				pListPtrNow = pListPtrNow->Flink;
				index++;
			}
		}
		break;
	case EVENT_TPYE_REG:
		{
			//DbgPrint("EVENT_TPYE_REG");
			DbgPrint("REG LIST:\t%d\t%d\t%d\t%s\n",pEvent->Type,pEvent->Behavior,pEvent->Pid,pEvent->Target);
			JudgeRst = TRUE;
			pListPtrNow = RegListHdr.Flink;
			while(pListPtrNow!=&RegListHdr&&!IsRstOut)
			{
				pListItemTemp = (PListItem)CONTAINING_RECORD(pListPtrNow,ListItem,ListEntry);
				if (pListItemTemp->Length<=HashsListTemp.HashslenF)
				{
					switch(pListItemTemp->Type)
					{
					case '+':
						{
							if (HashsListTemp.pHashsF[pListItemTemp->Length-1]==pListItemTemp->Hash)
							{
								IsRstOut = TRUE;
								JudgeRst = TRUE;
								pEvent->RuleIndex = index;
							}
						}
						break;
					case '-':
						{
							if (HashsListTemp.pHashsF[pListItemTemp->Length-1]==pListItemTemp->Hash)
							{
								IsRstOut = TRUE;
								JudgeRst = FALSE;
								pEvent->RuleIndex = index;
							}

						}
						break;
					case '>':
						{
							if (HashsListTemp.pHashsB[pListItemTemp->Length-1]==pListItemTemp->Hash)
							{
								IsRstOut = TRUE;
								JudgeRst = TRUE;
								pEvent->RuleIndex = index;
							}
						}
						break;
					case '<':
						{
							if (HashsListTemp.pHashsB[pListItemTemp->Length-1]==pListItemTemp->Hash)
							{
								IsRstOut = TRUE;
								JudgeRst = FALSE;
								pEvent->RuleIndex = index;
							}
						}
						break;
					}

				}
				
				pListPtrNow = pListPtrNow->Flink;
				index++;
			}
		}
		break;
	}


	ExFreePool(HashsListTemp.pHashsB);
	ExFreePool(HashsListTemp.pHashsF);

	return JudgeRst;
}

//用户层判断结果反馈
BOOLEAN JudgeByUser(Event* pEvent)
{
	//TODO.. 与用户层及分发函数进行交互，待定...

	BOOLEAN JudgeRst;

	KeWaitForSingleObject(&IoJudgeMutex,Executive,KernelMode,FALSE,NULL);
	RtlCopyMemory(IoBuff,pEvent,sizeof(Event));
	KeSetEvent((PKEVENT)IoEventObject,0,0);
	KeWaitForSingleObject((PKEVENT)JudgeEventObject,Executive,KernelMode,0,0);
	KeResetEvent((PKEVENT)JudgeEventObject);
	RtlCopyMemory(&JudgeRst,JudgeBuff,sizeof(BOOLEAN));
	KeReleaseMutex(&IoJudgeMutex,FALSE);

	return TRUE;
}



//////////////////////////////////////////////////////////////////////////
//Event->Target获得方式
//////////////////////////////////////////////////////////////////////////
//从字符串获得
NTSTATUS String2Target(Event* pEvent,PUNICODE_STRING pUnicodeString)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ANSI_STRING AnsiString;
	char* pStr = pEvent->Target;
	DWORD nSize = 0;
	while (*pStr != NULL)
	{
		pStr++;
		nSize++;
	}

	if (nSize)
	{
		pEvent->Target[nSize] = '\\';
	}
	
	AnsiString.Length = 0;
	AnsiString.MaximumLength = MAX_PATH-nSize;
	AnsiString.Buffer = --pStr;
	if (pUnicodeString == NULL)
	{
		return status;
	}

	status = RtlUnicodeStringToAnsiString(&AnsiString,pUnicodeString,FALSE);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	return STATUS_SUCCESS;
}

//从句柄获得
NTSTATUS Handle2Target(Event* pEvent,HANDLE Handle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pObject = NULL;
	PUNICODE_STRING pUnsiString;
	ZWQUERYINFORMATIONPROCESS	ZwQueryInformationProcess;
	ZWQUERYINFORMATIONTHREAD	ZwQueryInformationThread;
	THREAD_BASIC_INFORMATION	tbi;
	INT	nRet;

	if (Handle == NULL)
	{
		return status;
	}
	pUnsiString = ExAllocatePool(NonPagedPool,1028);
	if (pUnsiString == NULL)
	{
		return status;
	}

	//if (pEvent->Behavior==NtQueueApcThread || pEvent->Behavior==NtTerminateThread)
	//{
	//	RtlInitUnicodeString(pUnsiString,L"ZwQueryInformationThread");;

	//	ZwQueryInformationThread = MmGetSystemRoutineAddress(pUnsiString);
	//	if (ZwQueryInformationThread == NULL)
	//	{
	//		ExFreePool(pUnsiString);
	//		return status;
	//	}

	//	status = ZwQueryInformationThread(Handle,ThreadBasicInformation,&tbi,sizeof(THREAD_BASIC_INFORMATION),&nRet);
	//	if (!NT_SUCCESS(status))
	//	{
	//		return status;
	//	}	

	//}


	//进行各种类型判断
	switch (pEvent->Type)
	{
	case EVENT_TPYE_REG:
	case EVENT_TPYE_FILE:
		{
			status = ObReferenceObjectByHandle(Handle,NULL,NULL,KernelMode,&pObject,NULL);
			if (!NT_SUCCESS(status) || pObject==NULL)
			{
				return status;
			}
			status = ObQueryNameString(pObject,pUnsiString,512,&nRet);
			if (!NT_SUCCESS(status))
			{
				ObDereferenceObject(pObject);
				return status;
			}
		}
		break;
	case EVENT_TPYE_PROC:
	case EVENT_TPYE_INFO:
		{
			RtlInitUnicodeString(pUnsiString,L"ZwQueryInformationProcess");

			ZwQueryInformationProcess = MmGetSystemRoutineAddress(pUnsiString);
			if (ZwQueryInformationProcess == NULL)
			{
				ExFreePool(pUnsiString);
				return status;
			}

			status = ZwQueryInformationProcess(Handle,ProcessImageFileName,pUnsiString,1028,&nRet);
			if (!NT_SUCCESS(status))
			{
				return status;
			}	
		}
		break;
	}
	status = String2Target(pEvent,pUnsiString);
	ExFreePool(pUnsiString);

	return status;
}


//////////////////////////////////////////////////////////////////////////
//规则库读取用函数
//////////////////////////////////////////////////////////////////////////
//从指定文件读取规则库
NTSTATUS ReadRules(PUNICODE_STRING	pFileName,PLIST_ENTRY pListHdr)
{
	NTSTATUS	status;
	HANDLE	hFile;
	IO_STATUS_BLOCK	iostatus;
	OBJECT_ATTRIBUTES	ObjAttributes;
	FILE_STANDARD_INFORMATION	fsi;
	PCHAR	pBuffer;

	DbgPrint("%S",pFileName->Buffer);

	//初始化链表
	InitializeListHead(pListHdr);
	//初始化Lookaside
	ExInitializeNPagedLookasideList(&nPagedList,
		NULL,
		NULL,
		NULL,
		sizeof(ListItem),
		'0101',
		NULL);


	//初始化ObjectAttributes
	InitializeObjectAttributes(&ObjAttributes,
		pFileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	//打开文件
	status = ZwCreateFile(&hFile,
		GENERIC_READ,
		&ObjAttributes,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwCreateFile Error!");
		return status;
	}

	//读取文件长度
	status = ZwQueryInformationFile(hFile,
		&iostatus,
		&fsi,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwQueryInformationFile Error!");
		return status;
	}

	//为文件内容分配缓冲区
	pBuffer = (PCHAR)ExAllocatePool(NonPagedPool,(LONG)fsi.EndOfFile.QuadPart);
	if (pBuffer==NULL)
	{
		DbgPrint("ExAllocatePool Error!");
		return status;
	}

	//读取文件
	status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&iostatus,
		pBuffer,
		(LONG)fsi.EndOfFile.QuadPart,
		NULL,
		NULL);
	if (pBuffer==NULL)
	{
		DbgPrint("ZwReadFile Error!");
		return status;
	}

	//关闭文件句柄
	ZwClose(hFile);

	status = ParseRules(pBuffer,pListHdr);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ParseRules Error!");
		return status;
	}

	ExFreePool(pBuffer);
	return status;
}


//////////////////////////////////////////////////////////////////////////
//解析规则库
//////////////////////////////////////////////////////////////////////////
NTSTATUS	ParseRules(PCHAR pBuffer,PLIST_ENTRY pListHdr)
{
	ULONG	Hash = 0;
	PListItem pListItem;

	while (*pBuffer!='\0')
	{
		switch (*pBuffer)
		{
		case '+':
		case '-':
		case '<':
		case '>':
			{
				pListItem = (PListItem)ExAllocateFromNPagedLookasideList(&nPagedList);
				pListItem->Type = *pBuffer++;
				while (*pBuffer==' ' || *pBuffer=='\t')	pBuffer++;
				pListItem->Length = 0;
				while (*pBuffer!='\r')
				{
					pListItem->Length++;
					Hash += *pBuffer++;
					_asm{
						mov eax,Hash
							ror eax,25
							mov Hash,eax
					}
				}

				pListItem->Hash = Hash;
				InsertTailList(pListHdr,&pListItem->ListEntry);
			}
			break;
		case '\r':
			{
				pBuffer += 2;
			}
			break;
		default:
			{
				while (*pBuffer++!='\n');
			}
			break;
		}
	}

	return STATUS_SUCCESS;

}

//////////////////////////////////////////////////////////////////////////
//显示结果
//////////////////////////////////////////////////////////////////////////
VOID Display(PLIST_ENTRY pListHdr)
{
	PListItem pListItem;
	while (!IsListEmpty(pListHdr))
	{
		pListItem = (PListItem)RemoveHeadList(pListHdr);

		DbgPrint("%c\t%d\t%x\n",pListItem->Type,pListItem->Length,pListItem->Hash);

		ExFreeToNPagedLookasideList(&nPagedList,pListItem);
	}


	ExDeleteNPagedLookasideList(&nPagedList);
}

//////////////////////////////////////////////////////////////////////////
//正向、逆向计算Hash值
//////////////////////////////////////////////////////////////////////////
PULONG GetHashsF(PULONG pHashsLen,PCHAR pStr)
{
	PULONG pHashs = NULL;

	ULONG Hash = 0;

	CHAR HashTemp = 0x00;

	ULONG len = 0;

	ULONG index =0;


	RtlStringCbLengthA(pStr,MAX_PATH+1,(size_t*)&len);

	pHashs = (PULONG)ExAllocatePool(NonPagedPool,len*sizeof(ULONG));

	RtlZeroMemory(pHashs,len*4);

	for (index = 0;index<len;index++)
	{
		//大小写不敏感
		HashTemp = pStr[index];
		HashTemp = HashTemp|0x20;
		Hash+=(ULONG)HashTemp;
		//移位运算
		_asm
		{
				mov eax,Hash
				ror eax,25
				mov Hash,eax
		}
		pHashs[index] = Hash;
	}

	*pHashsLen = len;

	return pHashs;
}


PULONG GetHashsB(PULONG pHashsLen,PCHAR pStr)
{
	PULONG pHashs = NULL;

	ULONG Hash = 0;

	LONG len = 0;

	LONG index =0;

	CHAR HashTemp = 0x00;

	RtlStringCbLengthA(pStr,MAX_PATH+1,(size_t*)&len);

	pHashs = (PULONG)ExAllocatePool(NonPagedPool,len*sizeof(ULONG));

	RtlZeroMemory(pHashs,len*4);

	for (index = 0;index<len;index++)
	{
		//大小写不敏感
		HashTemp = pStr[index];
		HashTemp = HashTemp|0x20;
		Hash+=(ULONG)HashTemp;
		_asm
		{
			mov eax,Hash
				ror eax,25
				mov Hash,eax
		}
		pHashs[index] = Hash;
	}

	*pHashsLen = len;

	return pHashs;
}