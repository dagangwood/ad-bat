10.12

已修正：
DriverEntry()多了句话
IsTrustedProcess()死循环


存在一个蓝屏：
ReadFile()出问题，枚举出的部分进程路径有问题，最终导致ZwCreateFile()执行返回错误值，但是蓝在DbgPrint里，很诡异...

其它问题：
TrustedProcess不存在测试数据，需要在ring3下得到可信EXE的hash值


