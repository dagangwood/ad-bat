#include <ntddk.h>

//	NtCreateKey()
typedef NTSTATUS (*NTCREATEKEY)(__out PHANDLE KeyHandle, 
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
								  __in_bcount_opt);

//	NtDeleteKey()
typedef NTSTATUS (*NTDELETEKEY)(__in HANDLE KeyHandle);

//	NtDeleteVauleKey()
typedef NTSTATUS (*NTDELETEVALUEKEY)(__in HANDLE KeyHandle, 
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
								 __in_bcount_opt);

//	NtWriteFile()
typedef NTSTATUS (*NTWRITEFILE)(__in HANDLE FileHandle, 
								__in_opt HANDLE Event, 
								__in_opt PIO_APC_ROUTINE ApcRoutine, 
								__in_opt PVOID ApcContext, 
								__out PIO_STATUS_BLOCK IoStatusBlock,
								__in_bcount);

//	NtSetInformationFile()
typedef NTSTATUS (*NTSETINFORMATION)(__in HANDLE FileHandle, 
									 __out PIO_STATUS_BLOCK IoStatusBlock, 
									 __in_bcount);

//	NtOpenProcess()
typedef NTSTATUS (*NTOPENPROCESS)(__out PHANDLE ProcessHandle, 
								  __in ACCESS_MASK DesiredAccess, 
								  __in POBJECT_ATTRIBUTES ObjectAttributes, 
								  __in_opt PCLIENT_ID ClientId);

//	NtCreateProcess()
typedef NTSTATUS (*NTCREATEPROCESS)(OUT PHANDLE ProcessHandle,
									IN ACCESS_MASK DesiredAccess,
									IN POBJECT_ATTRIBUTES ObjectAttributes,
									IN HANDLE InheritFromProcessHandle,
									IN BOOLEAN InheritHandles,
									IN HANDLE SectionHandle OPTIONAL,
									IN HANDLE DebugPort OPTIONAL,
									IN HANDLE ExceptionPort OPTIONAL
									);

//	NtCreateProcessEx()
typedef NTSTATUS (*NTCREATEPROCESSEX)(OUT PHANDLE ProcessHandle,
									  IN ACCESS_MASK DesiredAccess,
									  IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
									  IN HANDLE ParentProcess,
									  IN BOOLEAN InheritObjectTable,
									  IN HANDLE SectionHandle OPTIONAL,
									  IN HANDLE DebugPort OPTIONAL,
									  IN HANDLE ExceptionPort OPTIONAL,
									  IN HANDLE Unknown );

//	NtTerminateProcess()
typedef NTSTATUS (*NTTERMINATEPROCESS)(__in_opt HANDLE ProcessHandle, 
									   __in NTSTATUS ExitStatus);

//	NtCreateThread()
typedef NTSTATUS (*NTCREATETHREAD)(OUT PHANDLE ThreadHandle,
								   IN ACCESS_MASK DesiredAccess,
								   IN POBJECT_ATTRIBUTES ObjectAttributes,
								   IN HANDLE ProcessHandle,
								   OUT PCLIENT_ID ClientId,
								   IN PCONTEXT ThreadContext,
								   IN PUSER_STACK UserStack,
								   IN BOOLEAN CreateSuspended);

//	NtTerminateThread()
typedef NTSTATUS (*NTTERMINATETHREAD)(IN HANDLE ThreadHandle OPTIONAL,
									  IN NTSTATUS ExitStatus);


//	NtQueueApcThread()
typedef NTSTATUS (*NTQUEUEAPCTHREAD)(IN HANDLE ThreadHandle,
									 IN PKNORMAL_ROUTINE ApcRoutine,
									 IN PVOID ApcContext OPTIONAL,
									 IN PVOID Argument1 OPTIONAL,
									 IN PVOID Argument2 OPTIONAL);


//	NtWriteVirtualMemory()
typedef NTSTATUS (*NTWRITEVIRTUALMEMORY)(IN HANDLE ProcessHandle,
										 IN PVOID BaseAddress,
										 IN PVOID Buffer,
										 IN ULONG BufferLength,
										 OUT PULONG ReturnLength OPTIONAL);

//	NtLoadDriver()
typedef NTSTATUS (*NTLOADDRIVER)(__in PUNICODE_STRING DriverServiceName);

//	NtSetSystemInformation()
typedef NTSTATUS (*NTSETSYSTEMINFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
										   IN OUT PVOID SystemInformation,
										   IN ULONG SystemInformationLength);

