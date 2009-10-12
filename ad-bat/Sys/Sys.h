#include "Structs.h"

//////////////////////////////////////////////////////////////////////////
//�궨�塢ȫ�ֱ�����������
//////////////////////////////////////////////////////////////////////////

#define MAX_PATH 260

//Hook��������
#define HOOKNUMS	18
//EXE Hash ����
#define HASHSIZE	4096

//////////////////////////////////////////////////////////////////////////
//Event.Behavior Define
//////////////////////////////////////////////////////////////////////////
#define NtLoadDriver			0x00
#define	NtCreateKey				0x01
#define NtSetValueKey			0x02
#define NtDeleteKey				0x03
#define NtDeleteVauleKey		0x04
#define NtCreateFile			0x05
#define NtWriteFile				0x06
#define NtSetInformationFile	0x07
#define NtOpenProcess			0x08	//Y
#define NtCreateProcess			0x09
#define NtCreateProcessEx		0x0A	//X
#define NtTerminateProcess		0x0B	//XY
#define NtCreateThread			0x0C	//Y
#define NtTerminateThread		0x0D	//Y
#define NtQueueApcThread		0x0E
#define NtWriteVirtualMemory	0x0F	//Y
#define NtSetSystemInformation	0x10
#define NtDuplicateObject		0x11	//Y

//Io������
//Io������
#define PROC_ON			CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define PROC_OFF		CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define REG_ON			CTL_CODE(FILE_DEVICE_UNKNOWN,0x821,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define REG_OFF			CTL_CODE(FILE_DEVICE_UNKNOWN,0x822,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FILE_ON			CTL_CODE(FILE_DEVICE_UNKNOWN,0x831,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FILE_OFF		CTL_CODE(FILE_DEVICE_UNKNOWN,0x832,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OTHER_ON		CTL_CODE(FILE_DEVICE_UNKNOWN,0x841,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OTHER_OFF		CTL_CODE(FILE_DEVICE_UNKNOWN,0x842,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define INFO_IN			CTL_CODE(FILE_DEVICE_UNKNOWN,0x851,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define INFO_OUT		CTL_CODE(FILE_DEVICE_UNKNOWN,0x852,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define GET_PID_EVENT	CTL_CODE(FILE_DEVICE_UNKNOWN,0x853,METHOD_BUFFERED,FILE_ANY_ACCESS)

//////////////////////////////////////////////////////////////////////////
//Event.type Define
//////////////////////////////////////////////////////////////////////////
#define EVENT_TPYE_PROC	1
#define EVENT_TPYE_REG	2
#define EVENT_TPYE_FILE	3
#define EVENT_TPYE_OTHER	4


//���ڴ洢Hook��Ϣ�Ľṹ��
typedef struct Hook{
	ULONG	ZwIndex;	//ԭʼ������ַ ZwXXXX
	ULONG	NewFunc;	//�滻������ַ
	ULONG	NtFunc;		//����ԭʼ������ַ
}Hook,*pHook;

//��Ϊ��¼�ṹ��
typedef struct Event{
	UINT	Type;
	UINT	Behavior;
	ULONG	Pid;
	ULONG	RuleIndex;
	CHAR	Target[MAX_PATH+1];
}Event;

//������ʽ
typedef struct ListItem{
	LIST_ENTRY	ListEntry;	//����
	ULONG		Hash;		//�ַ���Hash
	ULONG		Length;		//�ַ�������
	CHAR		Type;		//�ȶԷ�ʽ
}ListItem,*PListItem;

//���Ž��̹����ʽ
typedef struct ProcListItem{
	LIST_ENTRY	ListEntry;	//����
	ULONG		Hash;		//EXE�ļ�Hash
	ULONG		Pid;		//EXE����Pid
	CHAR		Type;		//�ȶԷ�ʽ
}ProcListItem,*PProcListItem;

//��ϣ��
typedef struct HashsList
{
	PULONG	pHashsF;
	PULONG	pHashsB;
	ULONG	HashslenF;
	ULONG	HashslenB;
}HashsList;


//����ȫ�ֱ��� SSDT ��
#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	UINT	*ServiceTableBase;
	UINT	*ServiceCounterTableBase;
	UINT	NumberOfServices;
	UCHAR	*ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()
__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;




//��д��SSDT����׵�ַ
PVOID* NewSystemCall;


//SSDT Hook ���ܵ������궨��
//ZwXXXX mov eax,(NtNums)
#define HOOK_INDEX(Zw2Nt)				*(PULONG)((PUCHAR)Zw2Nt+1)

#define HOOK(ZwIndex,NewFunc,NtFunc)	NtFunc = (PVOID)InterlockedExchange((PLONG)&NewSystemCall[HOOK_INDEX(ZwIndex)],(LONG)NewFunc)

#define UNHOOK(ZwIndex,NtFunc)			InterlockedExchange((PLONG)&NewSystemCall[HOOK_INDEX(ZwIndex)],(LONG)NtFunc)


//////////////////////////////////////////////////////////////////////////
//������������
//////////////////////////////////////////////////////////////////////////

//���ַ���ת��������
ULONG atoi(PCHAR pBuffer);

//����ж�غ���
VOID OnUnload(__in PDRIVER_OBJECT DriverObject);
//Io���ƺ���
NTSTATUS DeviceControl(PDEVICE_OBJECT pDeviceObject,PIRP pIrp);
//�򿪻��߹ر��豸
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject,PIRP irp);
//��ʼ��SSDT HOOK
NTSTATUS InitSsdtHook();
//��ȫ��SSDT HOOK
NTSTATUS SsdtHook(pHook pInfo,BOOLEAN bFlag);
//���SSDT��δ����API��ַ
NTSTATUS GetSsdtApi(PCHAR szApiName,PUNICODE_STRING szDll);


//�ں��ж��߼�����
//�Ƿ�Ϊ������Ϊ
BOOLEAN IsTrustedProcess();
//�Ƿ��ڰ�������
BOOLEAN IsInWhiteList(Event* pEvent);
//�û����жϽ������
BOOLEAN JudgeByUser(Event* pEvent);

//Event->Target��÷�ʽ
//·����ʽת��
NTSTATUS GetDosPath(PCHAR pString);
//���ַ������
NTSTATUS String2Target(Event* pEvent,PUNICODE_STRING pUnicodeString);
//�Ӿ�����
NTSTATUS Handle2Target(Event* pEvent,HANDLE Handle);
//�ӽ��̾����ý���PID
ULONG	ProcessHandle2Pid(HANDLE ProcessHanle);
//���߳̾���õ�����PID
ULONG	ThreadHandle2Pid(HANDLE ThreadHandle);
//����PID�õ����̾��
HANDLE  Pid2ProcessHandle(ULONG Pid);


//��ָ���ļ���ȡ�����
NTSTATUS ReadRules(PUNICODE_STRING pFileName,PLIST_ENTRY	pListHdr);
//���������
NTSTATUS ParseRules(PCHAR pBuffer,PLIST_ENTRY	pListHdr);
//��ȡ���������Ž��̹����
NTSTATUS ReadParseProcRules(PUNICODE_STRING pFileName,PLIST_ENTRY pListHdr);
PCHAR    ReadFile(PUNICODE_STRING pFileName,ULONG nSize);
ULONG	 GetHash(PCHAR pBuffer,ULONG nSize);
//��ʼ���ѿ��ŵĽ���
NTSTATUS InitTrustedProcess();

//��ʾ���
VOID Display(PLIST_ENTRY pListHdr);
VOID EventDisplay(Event* pEvent);


//�����������Hash
PULONG GetHashsF(PULONG pHashsLen,PCHAR pStr);
PULONG GetHashsB(PULONG pHashsLen,PCHAR pStr);




#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
ObQueryNameString(
				  __in PVOID Object,
				  __out_bcount_opt(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
				  __in ULONG Length,
				  __out PULONG ReturnLength
				  );
#endif







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
								__in_opt HANDLE hEvent, 
								__in_opt PIO_APC_ROUTINE ApcRoutine, 
								__in_opt PVOID ApcContext, 
								__out PIO_STATUS_BLOCK IoStatusBlock,
								__in PVOID Buffer,
								__in ULONG Length,
								__in PLARGE_INTEGER ByteOffset OPTIONAL,
								__in PULONG Key OPTIONAL);

NTSTATUS NewWriteFile(__in HANDLE FileHandle, 
					  __in_opt HANDLE hEvent, 
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

//	NtDuplicateObject
NTSYSAPI NTSTATUS NTAPI ZwDuplicateObject(__in HANDLE SourceProcessHandle,
										  __in HANDLE SourceHandle,
										  __in HANDLE TargetProcessHandle,
										  __out PHANDLE TargetHandle OPTIONAL,
										  __in ACCESS_MASK DesiredAccess,
										  __in ULONG Attributes,
										  __in ULONG Options);