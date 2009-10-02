#include "Sys.h"

PDRIVER_OBJECT pGlobalDvrObj;

Hook HookFunc[HOOKNUMS];

//设备名、符号链接名字符串
UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\AdBAT");
UNICODE_STRING symb_link = RTL_CONSTANT_STRING(L"\\DosDevices\\AdBAT");





NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriverObject,

					 __in PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;
	PDEVICE_OBJECT device;
	//循环用
	int i=0;

	DbgPrint("DriverEntry() Function...\n");

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

	//初始化SSDT Hook 操作
	status = InitSsdtHook();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//开始SSDT Hook
	for (i=0;i<HOOKNUMS;i++)
	{
		SsdtHook(&HookFunc[i],TRUE);
	}

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
	
	DbgPrint("OnUnload() Function...\n");

	IoDeleteSymbolicLink(&symb_link);


	for (i=0;i<HOOKNUMS;i++)
	{
		SsdtHook(&HookFunc[i],FALSE);
	}

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
	UNICODE_STRING szDll;
	PMDL pMdl;
	RtlInitUnicodeString(&szDll, L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntdll.dll");

	DbgPrint("InitSsdtHoot() Function...");

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
	HookFunc[NtSetSystemInformation].ZwIndex = HOOK_INDEX(GetSsdtApi("ZwSetSystemInformation",&szDll));
	HookFunc[NtSetSystemInformation].NewFunc = NewSetSystemInformation;
	//NtDuplicateObject()
	HookFunc[NtDuplicateObject].ZwIndex = HOOK_INDEX(ZwDuplicateObject);
	HookFunc[NtDuplicateObject].NewFunc = NewDuplicateObject;

	//使SSDT表可写,并保存可写的首地址
	pMdl = MmCreateMdl(NULL,KeServiceDescriptorTable.ServiceTableBase,KeServiceDescriptorTable.NumberOfServices*4);

	DbgPrint("SsdtHook() Function...\n");

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
	NTSTATUS status;
	NTLOADDRIVER OldNtFunc;
	
	DbgPrint("NewLoadDriver() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtCreateKey].NtFunc;

	DbgPrint("NewCreateKey() Function...\n");
	
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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtSetValueKey].NtFunc;

	DbgPrint("NewSetValueKey() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtDeleteKey].NtFunc;

	DbgPrint("NewDeleteKey() Function...\n");

	status = OldNtFunc(KeyHandle);

	return status;
}

NTSTATUS NewDeleteValueKey(__in HANDLE KeyHandle, 
						   __in PUNICODE_STRING ValueName)
{

	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtDeleteVauleKey].NtFunc;

	DbgPrint("NewDeleteValueKey() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtCreateFile].NtFunc;

	DbgPrint("NewCreateFile() Function...\n");
	
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
					  __in_opt HANDLE Event, 
					  __in_opt PIO_APC_ROUTINE ApcRoutine, 
					  __in_opt PVOID ApcContext, 
					  __out PIO_STATUS_BLOCK IoStatusBlock,
					  __in PVOID Buffer,
					  __in ULONG Length,
					  __in PLARGE_INTEGER ByteOffset OPTIONAL,
					  __in PULONG Key OPTIONAL)
{
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtWriteFile].NtFunc;

	DbgPrint("NewWriteFile() Function...\n");

	status = OldNtFunc(FileHandle,
					   Event,
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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtSetInformationFile].NtFunc;

	DbgPrint("NewSetInformationFile() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtOpenProcess].NtFunc;

	DbgPrint("NewOpenProcess() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtCreateProcess].NtFunc;

	DbgPrint("NewCreateProcess() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtCreateProcessEx].NtFunc;

	DbgPrint("NewCreateProcessEx() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtTerminateProcess].NtFunc;

	DbgPrint("NewTerminateProcess() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtCreateThread].NtFunc;

	DbgPrint("NewCreateThread() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtTerminateThread].NtFunc;

	DbgPrint("NewTerminateThread() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtQueueApcThread].NtFunc;

	DbgPrint("NewQueueApcThread() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtWriteVirtualMemory].NtFunc;

	DbgPrint("NewWriteVirtualMemory() Function...\n");

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
	NTSTATUS status;

	NTSETSYSTEMINFORMATION OldNtFunc = HookFunc[NtSetSystemInformation].NtFunc;

	DbgPrint("NewSetSystemInformation() Function...\n");

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
	NTSTATUS status;

	NTLOADDRIVER OldNtFunc = HookFunc[NtDuplicateObject].NtFunc;

	DbgPrint("NewDuplicateObject() Function...\n");

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
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(pIrp);

	NTSTATUS Status;

	ULONG Code = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	ULONG InputLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

	ULONG OutputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

	PVOID pIoBuff = pIrp->AssociatedIrp.SystemBuffer;

	DbgPrint("DeviceIoControl() Function...\n");

	switch(Code)
	{
	case PROC_ON:
		{
			DbgPrint("PROC_ON");

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
			DbgPrint("PROC_OFF");

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
			DbgPrint("REG_ON");

			SsdtHook(&HookFunc[NtCreateKey],TRUE);
			SsdtHook(&HookFunc[NtSetValueKey],TRUE);
			SsdtHook(&HookFunc[NtDeleteKey],TRUE);
			SsdtHook(&HookFunc[NtDeleteVauleKey],TRUE);
		}
		break;
	case REG_OFF:
		{
			DbgPrint("REG_OFF");

			SsdtHook(&HookFunc[NtCreateKey],FALSE);
			SsdtHook(&HookFunc[NtSetValueKey],FALSE);
			SsdtHook(&HookFunc[NtDeleteKey],FALSE);
			SsdtHook(&HookFunc[NtDeleteVauleKey],FALSE);
		}
		break;
	case FILE_ON:
		{
			DbgPrint("FILE_ON");

			SsdtHook(&HookFunc[NtCreateFile],TRUE);
			SsdtHook(&HookFunc[NtWriteFile],TRUE);
			SsdtHook(&HookFunc[NtSetInformationFile],TRUE);
		}
		break;
	case FILE_OFF:
		{
			DbgPrint("FILE_OFF");

			SsdtHook(&HookFunc[NtCreateFile],FALSE);
			SsdtHook(&HookFunc[NtWriteFile],FALSE);
			SsdtHook(&HookFunc[NtSetInformationFile],FALSE);
		}
		break;
	case OTHER_ON:
		{
			DbgPrint("OTHER_ON\n");

			SsdtHook(&HookFunc[NtLoadDriver],TRUE);
			SsdtHook(&HookFunc[NtSetSystemInformation],TRUE);
			SsdtHook(&HookFunc[NtDuplicateObject],TRUE);
		}
		break;
	case OTHER_OFF:
		{
			DbgPrint("OTHER_OFF\n");

			SsdtHook(&HookFunc[NtLoadDriver],FALSE);
			SsdtHook(&HookFunc[NtSetSystemInformation],FALSE);
			SsdtHook(&HookFunc[NtDuplicateObject],FALSE);
		}
		break;
	case INFO_OUT:
		{
			DbgPrint("INFO_OUT");
		}
		break;
	case INFO_IN:
		{
			DbgPrint("INFO_IN");
		}
		break;
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return pIrp->IoStatus.Status;
}