#include "Sys.h"
#include <ntddk.h>


PDRIVER_OBJECT pGlobalDvrObj;

Hook SsdtHook[HOOKNUMS];

//�豸���������������ַ���
UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\Ad-BAT");
UNICODE_STRING symb_link = RTL_CONSTANT_STRING(L"\\Device\\AdBATSL");


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,

					 IN PUNICODE_STRING pRegistryPath)
{
	DbgPrint("DriverEntry Function...\n");

	pGlobalDvrObj = pDriverObject;
	NTSTATUS status;
	PDEVICE_OBJECT device;

	//�����豸����
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

	//���ɷ�������
	status = IoCreateSymbolicLink(&symb_link,
								  &device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device);
		return status;
	}

	//�豸����֮�󣬴򿪳�ʼ����ɱ��
	device->Flags &= ~DO_DEVICE_INITIALIZING;


	


	// ����ж�غ��� 
	pDriverObject->DriverUnload = OnUnload;

	// IOCTL�ַ����� (����Ĵ���)
	pDriverObject->MajorFunction[IRP_MY_DEVICE_CONTROL] = ;


	return status;
}


//����ж�غ���
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	DbgPrint("OnUnload Function...\n");


	PDEVICE_OBJECT pdoNextDeviceObj = pGlobalDvrObj->DeviceObject;
	IoDeleteSymbolicLink(&symb_link);

	// Delete all the device objects
	while(pdoNextDeviceObj)
	{
		PDEVICE_OBJECT pdoThisDeviceObj = pdoNextDeviceObj;
		pdoNextDeviceObj = pdoThisDeviceObj->NextDevice;
		IoDeleteDevice(pdoThisDeviceObj);
	}
}


//��ʼ��SSDT HOOK
NTSTATUS InitSsdtHook()
{
	//������
	for (int i=0;i<HOOKNUMS;i++)
	{
		SsdtHook[i].NewFunc = 0x00;
		SsdtHook[i].NtFunc = 0x00;
		SsdtHook[i].OrgFunc = 0x00;
	}

	//ע��Hook��Ϣ
	//NtLoadDriver()
	SsdtHook[NtLoadDriver].OrgFunc = ZwLoadDriver;
	SsdtHook[NtLoadDriver].NewFunc = NewLoadDriver;
	//NtCreateKey()
	SsdtHook[NtCreateKey].OrgFunc = ZwCreateKey;
	SsdtHook[NtCreateKey].NewFunc = NewCreateKey;
	//NtSetValueKey()
	SsdtHook[NtSetValueKey].OrgFunc = ZwSetValueKey;
	SsdtHook[NtSetValueKey].NewFunc = NewSetValueKey;
	//NtDeleteKey()
	SsdtHook[NtDeleteKey].OrgFunc = ZwDeleteKey;
	SsdtHook[NtDeleteKey].NewFunc = NewDeleteKey;
	//NtDeleteVauleKey()
	SsdtHook[NtDeleteVauleKey].OrgFunc = ZwDeleteValueKey;
	SsdtHook[NtDeleteVauleKey].NewFunc = NewDeleteValueKey;
	//NtCreateFile()
	SsdtHook[NtCreateFile].OrgFunc = ZwCreateFile;
	SsdtHook[NtCreateFile].NewFunc = NewCreateFile;
	//NtWriteFile()
	SsdtHook[NtWriteFile].OrgFunc = ZwWriteFile;
	SsdtHook[NtWriteFile].NewFunc = NewWriteFile;
	//NtSetInformationFile()
	SsdtHook[NtSetInformationFile].OrgFunc = ZwSetInformationFile;
	SsdtHook[NtSetInformationFile].NewFunc = NewSetInformationFile;
	//NtOpenProcess()
	SsdtHook[NtOpenProcess].OrgFunc = ZwOpenProcess;
	SsdtHook[NtOpenProcess].NewFunc = NewOpenProcess;
	//NtCreateProcess()
	SsdtHook[NtCreateProcess].OrgFunc = ZwCreateProcess;
	SsdtHook[NtCreateProcess].NewFunc = NewCreateProcess;
	//NtCreateProcessEx()
	SsdtHook[NtCreateProcessEx].OrgFunc = ZwCreateProcessEx;
	SsdtHook[NtCreateProcessEx].NewFunc = NewCreateProcessEx;
	//NtTerminateProcess()
	SsdtHook[NtTerminateProcess].OrgFunc = ZwTerminateProcess;
	SsdtHook[NtTerminateProcess].NewFunc = NewTerminateProcess;
	//NtCreateThread()
	SsdtHook[NtCreateThread].OrgFunc = ZwCreateThread;
	SsdtHook[NtCreateThread].NewFunc = NewCreateThread;
	//NtTerminateThread()
	SsdtHook[NtTerminateThread].OrgFunc = ZwTerminateThread;
	SsdtHook[NtTerminateThread].NewFunc = NewTerminateThread;
	//NtQueueApcThread()
	SsdtHook[NtQueueApcThread].OrgFunc = ZwQueueApcThread;
	SsdtHook[NtQueueApcThread].NewFunc = NewQueueApcThread;
	//NtWriteVirtualMemory()
	SsdtHook[NtWriteVirtualMemory].OrgFunc = ZwWriteVirtualMemory;
	SsdtHook[NtWriteVirtualMemory].NewFunc = NewWriteVirtualMemory;
	//NtSetSystemInformation()
	SsdtHook[NtSetSystemInformation].OrgFunc = ZwSetSystemInformation;
	SsdtHook[NtSetSystemInformation].NewFunc = NewSetSystemInformation;


}