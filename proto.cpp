//一些协议定义的思考

//行为记录的格式，暂定..
struct Event{
	int		type;//File==1 Process==2 Registry==3 Information==4
	int		behavior;//操作行为，例如进程具有创建、销毁；注册表具有读、写、创建、修改等
	unsigned long pid;//对应各种操作的进程PID
	UNICODE_STRING	target[];//对应操作目标	
}

struct Reply{
	ULONG	cmd;	//cmd==1 pass cmd==2 deny
};



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
