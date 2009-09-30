#include <ntddk.h>

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,

					 IN PUNICODE_STRING pRegistryPath)
{
	DbgPrint("DriverEntry Function...\n");

	NTSTATUS status;
	PDEVICE_OBJECT device;

	//�豸���������������ַ���
	UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\Ad-BAT");
	UNICODE_STRING symb_link = RTL_CONSTANT_STRING(L"\\Device\\AdBATSL");

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

	return status;
}