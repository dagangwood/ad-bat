#include "Header.h"

BOOL WINAPI DllMain(void * _HDllHandle,unsigned _Reason,void * _Reserved)
{

	return TRUE;
}



BOOL Initialize()
{

	//首先完成与UI交互的初始化工作  等  罗


	hDriver = CreateFile("\\\\.\\AdBAT",GENERIC_ALL,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

	if (hDriver==INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL,"Warning!!!","Open Failed...\n",MB_OK);
		return 0;
	}

	hIoEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
	hJudgeEvent = CreateEvent(NULL,FALSE,FALSE,NULL);

	DWORD len;

	CHAR Buff[16] = {0};

	memcpy(Buff,&hIoEvent,sizeof(HANDLE));
	memcpy(Buff+4,&hJudgeEvent,sizeof(HANDLE));
	*(PULONG)(Buff+8) = (ULONG)IoBuff;
	*(PULONG)(Buff+12) = (ULONG)JudgeBuff;


	DeviceIoControl(hDriver,GET_PID_EVENT,Buff,sizeof(HANDLE)*4,NULL,0,&len,NULL);

	DWORD ThreadID;

	CreateThread(NULL,NULL,LPTHREAD_START_ROUTINE(JudgeByUserThreadProc),NULL,NULL,&ThreadID);

	return 0;
}

VOID JudgeByUserThreadProc()
{

	while(TRUE)
	{
		BOOLEAN bRst = TRUE;
		WaitForSingleObject(hIoEvent,INFINITE);
		ResetEvent(hIoEvent);

		//Event* EventBuff = (Event *)IoBuff;

		//等 罗 与IO交互 完成用户判断


		//printf("%d\t",EventBuff->Type);
		//printf("%d\t",EventBuff->Behavior);
		//printf("%d\t",EventBuff->Pid);
		//printf("%s\t",EventBuff->Target);
		//printf("\n\n");


		//*(PBOOLEAN)JudgeBuff = TRUE;
		SetEvent(hJudgeEvent);

	}
}

Event GetIoBuff()
{
	Event Buff;
	memcpy(&Buff,IoBuff,sizeof(Event));
	return Buff;
}

BOOL SetJugheBuff(BOOLEAN Rst)
{
	*(PBOOLEAN)JudgeBuff = Rst;
	return TRUE;
}

BOOL SetOnOff(int Type,BOOL bOnOff)
{
	DWORD len;
	switch (Type)
	{
	case EVENT_TPYE_PROC:
		{
			if (bOnOff!=IsProcOn)
			{
				if (bOnOff)
				{
					DeviceIoControl(hDriver,PROC_ON,NULL,0,NULL,0,&len,NULL);
				}
				else
				{
					DeviceIoControl(hDriver,PROC_OFF,NULL,0,NULL,0,&len,NULL);
				}
			}
		}
		break;
	case EVENT_TPYE_REG:
		{
			if (bOnOff!=IsRegOn)
			{
				if (bOnOff)
				{
					DeviceIoControl(hDriver,REG_ON,NULL,0,NULL,0,&len,NULL);
				}
				else
				{
					DeviceIoControl(hDriver,REG_OFF,NULL,0,NULL,0,&len,NULL);
				}
			}
		}
		break;
	case EVENT_TPYE_FILE:
		{
			if (bOnOff!=IsFileOn)
			{
				if (bOnOff)
				{
					DeviceIoControl(hDriver,FILE_ON,NULL,0,NULL,0,&len,NULL);
				}
				else
				{
					DeviceIoControl(hDriver,FILE_OFF,NULL,0,NULL,0,&len,NULL);
				}
			}
		}
		break;
	case EVENT_TYPE_OTHER:
		{
			if (bOnOff!=IsOtherON)
			{
				if (bOnOff)
				{
					DeviceIoControl(hDriver,OTHER_ON,NULL,0,NULL,0,&len,NULL);
				}
				else
				{
					DeviceIoControl(hDriver,OTHER_OFF,NULL,0,NULL,0,&len,NULL);
				}
			}
		}
		break;
	}
	return TRUE;
}

BOOL SetLevel(int Level)
{
	if (Level!=gLevel)
	{
		//TODO.................
		gLevel = Level;
	}
	return TRUE;
}

BOOL ExecutExe(PCHAR Name,PCHAR Cmd)
{
	//TODO...........
	return TRUE;
}