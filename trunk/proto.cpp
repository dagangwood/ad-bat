//һЩЭ�鶨���˼��

//��Ϊ��¼�ĸ�ʽ���ݶ�..
struct Event{
	int		type;//File==1 Process==2 Registry==3 Information==4
	int		behavior;//������Ϊ��������̾��д��������٣�ע�����ж���д���������޸ĵ�
	unsigned long pid;//��Ӧ���ֲ����Ľ���PID
	UNICODE_STRING	target[];//��Ӧ����Ŀ��	
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
