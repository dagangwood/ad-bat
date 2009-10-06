#include <Windows.h>


typedef struct Event{
	UINT	Type;
	UINT	Behavior;
	ULONG	Pid;
	CHAR	Target[MAX_PATH+1];
}Event;



#define PROC_ON		CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define PROC_OFF	CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define REG_ON		CTL_CODE(FILE_DEVICE_UNKNOWN,0x821,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define REG_OFF		CTL_CODE(FILE_DEVICE_UNKNOWN,0x822,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FILE_ON		CTL_CODE(FILE_DEVICE_UNKNOWN,0x831,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FILE_OFF	CTL_CODE(FILE_DEVICE_UNKNOWN,0x832,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OTHER_ON	CTL_CODE(FILE_DEVICE_UNKNOWN,0x841,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define OTHER_OFF	CTL_CODE(FILE_DEVICE_UNKNOWN,0x842,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define INFO_IN		CTL_CODE(FILE_DEVICE_UNKNOWN,0x851,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define INFO_OUT	CTL_CODE(FILE_DEVICE_UNKNOWN,0x852,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define GET_PID_EVENT	CTL_CODE(FILE_DEVICE_UNKNOWN,0x853,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define TEST_MAKE_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN,0x999,METHOD_BUFFERED,FILE_ANY_ACCESS)


#define EVENT_TPYE_PROC		1
#define EVENT_TPYE_REG		2
#define EVENT_TPYE_FILE		3
#define EVENT_TYPE_OTHER	4

#define LEVEL_HIGH		3
#define LEVEL_NORMAL	2
#define LEVEL_LOW		1



BOOL IsProcOn = TRUE;
BOOL IsRegOn = TRUE;
BOOL IsFileOn = TRUE;
BOOL IsOtherON = TRUE;

int gLevel;


HANDLE hDriver;

HANDLE hIoEvent = NULL;
HANDLE hJudgeEvent = NULL;

CHAR IoBuff[4+4+4+MAX_PATH+1] = {0};
CHAR JudgeBuff[4] = {0};


VOID JudgeByUserThreadProc();

extern "C" _declspec(dllexport) Event GetIoBuff();  //可以使用c++的引用

extern "C" _declspec(dllexport) BOOL SetJugheBuff(BOOLEAN Rst); //设置判断结果

extern "C" _declspec(dllexport) BOOL Initialize(HWND hDialog);

extern "C" _declspec(dllexport) BOOL SetOnOff(int Type,BOOL bOnOff);

extern "C" _declspec(dllexport) BOOL SetLevel(int Level);

extern "C" _declspec(dllexport) BOOL ExecutExe(PCHAR Name,PCHAR Cmd);

extern "C" _declspec(dllexport) BOOL UpDate();

extern "C" _declspec(dllexport) BOOL TestFunc();

