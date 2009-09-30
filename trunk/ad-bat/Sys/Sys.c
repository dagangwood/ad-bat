#include <ntddk.h>

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,

					 IN PUNICODE_STRING pRegistryPath)
{
	DbgPrint("DriverEntry Function...\n");

	NTSTATUS status;
	PDEVICE_OBJECT device;

	//设备名、符号链接名字符串
	UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\Ad-BAT");
	UNICODE_STRING symb_link = RTL_CONSTANT_STRING(L"\\Device\\AdBATSL");

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
	status = IoCreateSymbolicLink(&symb_link,
								  &device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device);
		return status;
	}

	//设备生成之后，打开初始化完成标记
	device->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}