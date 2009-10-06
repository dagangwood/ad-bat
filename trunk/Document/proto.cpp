//一些协议定义的思考




//行为记录的格式，暂定..
struct Event{
	int		type;//Process==1 Registry==2 File==3 Information==4
	int		behavior;//操作行为，例如进程具有创建、销毁；注册表具有读、写、创建、修改等
	unsigned long pid;//对应各种操作的进程PID
	UNICODE_STRING	target;//对应操作目标	
}


//////////////////////////////////////////////////////////////////////////
//Event.type Define
//////////////////////////////////////////////////////////////////////////
#define EVENT_TPYE_PROC	1000
#define EVENT_TPYE_REG	2000
#define EVENT_TPYE_FILE	3000
#define EVENT_TPYE_INFO	4000

//////////////////////////////////////////////////////////////////////////
//Event.behavior Define
//////////////////////////////////////////////////////////////////////////
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
#define NtTerminateThread		0x0E
#define NtQueueApcThread		0x0F
#define NtWriteVirtualMemory	0x10
#define NtSetSystemInformation	0x11
#define NtDuplicateObject		0x12


struct Reply{
	ULONG	cmd;	//cmd==1 pass cmd==2 deny
};

//////////////////////////////////////////////////////////////////////////
//Reply.cmd Define
//////////////////////////////////////////////////////////////////////////
#define REPLY_CMD_PASS 8000
#define REPLY_CMD_DENY 9000




//////////////////////////////////////////////////////////////////////////
//IO Protocol Define
//////////////////////////////////////////////////////////////////////////
#define PROC_ON		1001
#define PROC_OFF	1002

#define REG_ON		2001
#define REG_OFF		2002

#define FILE_ON		3001
#define FILE_OFF	3002

#define INFO_IN		4001
#define INFO_OUT	4002


switch(IOCTLCODE)
{
case PROC_ON:
	{

	}
	break;
case PROC_OFF:
	{

	}
	break;
case REG_ON:
	{

	}
	break;
case REG_OFF:
	{

	}
	break;
case FILE_ON:
	{

	}
	break;
case FILE_OFF:
	{

	}
	break;
case INFO_OUT:
	{

	}
	break;
case INFO_IN:
	{

	}
	break;
}
