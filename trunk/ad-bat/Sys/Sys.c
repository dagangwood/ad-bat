#include "Sys.h"
#include <ntddk.h>


PDRIVER_OBJECT pGlobalDvrObj;

Hook HookFunc[HOOKNUMS];

//设备名、符号链接名字符串
UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\Ad-BAT");
UNICODE_STRING symb_link = RTL_CONSTANT_STRING(L"\\Device\\AdBATSL");


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,

					 IN PUNICODE_STRING pRegistryPath)
{
	DbgPrint("DriverEntry() Function...\n");

	pGlobalDvrObj = pDriverObject;
	NTSTATUS status;
	PDEVICE_OBJECT device;

	//生成设备对象
	status = IoCreateDevice(pDriverObject,
							NULL,
							device_name,
							FILE_DEVICE_UNKNOWN,
							NULL,
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
	device->Flags &= ~DO_DEVICE_INITIALIZING;

	//初始化SSDT Hook 操作
	InitSsdtHook();

	//开始SSDT Hook
	for (int i=0;i<HOOKNUMS;i++)
	{
		NT_SUCCESS status = SsdtHook(&HookFunc[i],TRUE);
		if (!NT_SUCCESS(status))
		{
			return status;
		}
	}

	// 驱动卸载函数 
	pDriverObject->DriverUnload = OnUnload;

	// IOCTL分发函数 (等苗的代码)
	//pDriverObject->MajorFunction[IRP_MY_DEVICE_CONTROL] = ;


	return status;
}


//驱动卸载函数
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	DbgPrint("OnUnload() Function...\n");


	PDEVICE_OBJECT pdoNextDeviceObj = pGlobalDvrObj->DeviceObject;
	IoDeleteSymbolicLink(&symb_link);


	for (int i=0;i<HOOKNUMS;i++)
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
	DbgPrint("InitSsdtHoot() Function...");

	//先清零
	for (int i=0;i<HOOKNUMS;i++)
	{
		HookFunc[i].NewFunc = 0x00;
		HookFunc[i].NtFunc = 0x00;
		HookFunc[i].OrgFunc = 0x00;
	}

	//注册Hook信息
	//NtLoadDriver()
	HookFunc[NtLoadDriver].OrgFunc = ZwLoadDriver;
	HookFunc[NtLoadDriver].NewFunc = NewLoadDriver;
	//NtCreateKey()
	HookFunc[NtCreateKey].OrgFunc = ZwCreateKey;
	HookFunc[NtCreateKey].NewFunc = NewCreateKey;
	//NtSetValueKey()
	HookFunc[NtSetValueKey].OrgFunc = ZwSetValueKey;
	HookFunc[NtSetValueKey].NewFunc = NewSetValueKey;
	//NtDeleteKey()
	HookFunc[NtDeleteKey].OrgFunc = ZwDeleteKey;
	HookFunc[NtDeleteKey].NewFunc = NewDeleteKey;
	//NtDeleteVauleKey()
	HookFunc[NtDeleteVauleKey].OrgFunc = ZwDeleteValueKey;
	HookFunc[NtDeleteVauleKey].NewFunc = NewDeleteValueKey;
	//NtCreateFile()
	HookFunc[NtCreateFile].OrgFunc = ZwCreateFile;
	HookFunc[NtCreateFile].NewFunc = NewCreateFile;
	//NtWriteFile()
	HookFunc[NtWriteFile].OrgFunc = ZwWriteFile;
	HookFunc[NtWriteFile].NewFunc = NewWriteFile;
	//NtSetInformationFile()
	HookFunc[NtSetInformationFile].OrgFunc = ZwSetInformationFile;
	HookFunc[NtSetInformationFile].NewFunc = NewSetInformationFile;
	//NtOpenProcess()
	HookFunc[NtOpenProcess].OrgFunc = ZwOpenProcess;
	HookFunc[NtOpenProcess].NewFunc = NewOpenProcess;
	//NtCreateProcess()
	HookFunc[NtCreateProcess].OrgFunc = ZwCreateProcess;
	HookFunc[NtCreateProcess].NewFunc = NewCreateProcess;
	//NtCreateProcessEx()
	HookFunc[NtCreateProcessEx].OrgFunc = ZwCreateProcessEx;
	HookFunc[NtCreateProcessEx].NewFunc = NewCreateProcessEx;
	//NtTerminateProcess()
	HookFunc[NtTerminateProcess].OrgFunc = ZwTerminateProcess;
	HookFunc[NtTerminateProcess].NewFunc = NewTerminateProcess;
	//NtCreateThread()
	HookFunc[NtCreateThread].OrgFunc = ZwCreateThread;
	HookFunc[NtCreateThread].NewFunc = NewCreateThread;
	//NtTerminateThread()
	HookFunc[NtTerminateThread].OrgFunc = ZwTerminateThread;
	HookFunc[NtTerminateThread].NewFunc = NewTerminateThread;
	//NtQueueApcThread()
	HookFunc[NtQueueApcThread].OrgFunc = ZwQueueApcThread;
	HookFunc[NtQueueApcThread].NewFunc = NewQueueApcThread;
	//NtWriteVirtualMemory()
	HookFunc[NtWriteVirtualMemory].OrgFunc = ZwWriteVirtualMemory;
	HookFunc[NtWriteVirtualMemory].NewFunc = NewWriteVirtualMemory;
	//NtSetSystemInformation()
	HookFunc[NtSetSystemInformation].OrgFunc = ZwSetSystemInformation;
	HookFunc[NtSetSystemInformation].NewFunc = NewSetSystemInformation;
	//NtDuplicateObject()
	HookFunc[NtDuplicateObject].OrgFunc = ZwDuplicateObject;
	HookFunc[NtDuplicateObject].NewFunc = NewDuplicateObject;

	return STATUS_SUCCESS;
}


//打开全部SSDT HOOK
NTSTATUS SsdtHook(Hook* pInfo,BOOLEAN bFlag)
{
	DbgPrint("SsdtHook() Function...\n");



	PMDL pMdl = MmCreateMdl(NULL,KeServiceDescriptorTable.ServiceTableBase,KeServiceDescriptorTable.NumberOfServices*4);

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


	if (bFlag == TRUE)
	{
		HOOK(pInfo->OrgFunc,pInfo->NewFunc,pInfo->NtFunc);
	}
	else
	{
		UNHOOK(pInfo->OrgFunc,pInfo->NtFunc);
	}

	return STATUS_SUCCESS;
}