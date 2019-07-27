#include <stdio.h>
#include <Windows.h>
#include <fltUser.h>
#include "FileEchoUK.h"


#define DEFAULT_THREAD_COUNT 2
#define DEFAULT_REQUEST_COUNT 5
#define MAX_THREAD_COUNT 64

#define RULE_PATH L"C:\\Users\\AT\\Desktop\\rule.txt"

#pragma comment(lib,"FltLib.lib")
#pragma comment(lib,"Advapi32.lib")

HANDLE g_hDevice = NULL;

#pragma pack(1)
typedef struct _FE_MESSAGE
{
	FILTER_MESSAGE_HEADER m_MessageHeader;
	FE_UK_DATA m_KernelData;
	OVERLAPPED m_Ovlp;
}FE_MESSAGE,*PFE_MESSAGEA;

typedef struct _FER3_REPLY_MESSAGE
{
	FILTER_REPLY_HEADER m_pReplyHeader;
	FE_REPLY_DATA m_ReplyData;
}FER3_REPLY_MESSAGE,*PFER3_REPLY_MESSAGE;

/** 线程传输数据 */
typedef struct _COMMUNICATION_THREAD_CONTEXT
{
	HANDLE m_Port;
	HANDLE m_Completion;
}COMMUNICATION_THREAD_CONTEXT,*PCOMMUNICATION_THREAD_CONTEXT;

HANDLE OpenDevice()
{
	HANDLE hDevice = NULL;
	SECURITY_ATTRIBUTES sAttr = {0x00};
	sAttr.bInheritHandle = TRUE;
	sAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	sAttr.lpSecurityDescriptor = NULL;

	hDevice = CreateFileW(L"\\\\.\\FileEchoDrv",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0x80,
		NULL
		);
	if(hDevice != INVALID_HANDLE_VALUE)
	{
		printf("Create Device Success!\n");
	}
	else
	{
		printf("Create Device Fail:%d!\n",GetLastError());
	}

	return hDevice;

}


BOOL InstallMiniFilter(void)
{
	//SCM管理器句柄
	SC_HANDLE hServicesMgr = NULL;
	//NT驱动程序的句柄
	SC_HANDLE hNt = NULL;
	TCHAR DriverFullPathNameBuffer[MAX_PATH] = {0x00};
	TCHAR FormatStr[MAX_PATH];
	TCHAR *RegPath = L"SYSTEM\\CurrentControlSet\\Services\\";
	HKEY hKey = 0;
	DWORD dwData = 0;

	hServicesMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (!hServicesMgr)
	{
		CloseServiceHandle(hServicesMgr);
		return FALSE;
	}

	ExpandEnvironmentStrings(L"%systemroot%", DriverFullPathNameBuffer,sizeof(DriverFullPathNameBuffer));
	wcsncat(DriverFullPathNameBuffer,L"\\",1);
	wcsncat(DriverFullPathNameBuffer,DRIVER_NAME,wcslen(DRIVER_NAME));
	wcsncat(DriverFullPathNameBuffer,L".sys",wcslen(L".sys"));

	//GetFullPathName(pSysPath, MAX_PATH, DriverFullPathNameBuffer, NULL);

	hNt = CreateService(hServicesMgr
		, DRIVER_NAME
		, DRIVER_NAME
		, SERVICE_ALL_ACCESS
		, SERVICE_FILE_SYSTEM_DRIVER
		, SERVICE_DEMAND_START
		, SERVICE_ERROR_IGNORE
		, DriverFullPathNameBuffer
		, L"FSFilter Activity Monitor"
		, NULL
		, L"FltMgr"
		, NULL
		, NULL);

	if (!hNt)
	{
		ULONG error = GetLastError();
		if (error == ERROR_SERVICE_EXISTS || error == 0x00000431)
		{
			CloseServiceHandle(hServicesMgr);
			CloseServiceHandle(hNt);
			return TRUE;
		}
		else
		{
			CloseServiceHandle(hServicesMgr);
			CloseServiceHandle(hNt);
			return FALSE;
		}
	}

	CloseServiceHandle(hServicesMgr);
	CloseServiceHandle(hNt);

	wcsncpy_s(FormatStr, RegPath, wcslen(RegPath));
	wcsncat_s(FormatStr, DRIVER_NAME, sizeof(DRIVER_NAME));
	wcsncat_s(FormatStr, L"\\Instances", wcslen(L"\\Instances"));

	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE
		, FormatStr
		, 0
		, L""
		, REG_OPTION_NON_VOLATILE
		, KEY_ALL_ACCESS
		, NULL
		, &hKey
		, &dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	wcsncpy_s(FormatStr, DRIVER_NAME, wcslen(DRIVER_NAME));
	wcsncat_s(FormatStr,L" Instance", wcslen(L" Instance"));
	if (RegSetValueEx(hKey
		, L"DefaultInstance"
		, 0
		, REG_SZ
		, (const BYTE *)FormatStr
		, wcslen(FormatStr) * sizeof(WCHAR)) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	RegFlushKey(hKey);
	RegCloseKey(hKey);

	//SYSTEM_LOCAL_MACHINE\CurrentControlSet\Services\DriverName\Instances\DriverName Instance
	wcsncpy_s(FormatStr, RegPath, wcslen(RegPath));
	wcsncat_s(FormatStr, DRIVER_NAME, wcslen(DRIVER_NAME));
	wcsncat_s(FormatStr, L"\\Instances\\", wcslen(L"\\Instances\\"));
	wcsncat_s(FormatStr, DRIVER_NAME, wcslen(DRIVER_NAME));
	wcsncat_s(FormatStr, L" Instance", wcslen(L" Instance"));

	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE
		, FormatStr
		, 0
		, L""
		, REG_OPTION_NON_VOLATILE
		, KEY_ALL_ACCESS
		, NULL
		, &hKey
		, &dwData) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	wcsncpy_s(FormatStr, DRIVER_ALTITUDE, wcslen(DRIVER_ALTITUDE));
	if (RegSetValueEx(hKey
		, L"Altitude"
		, 0
		, REG_SZ
		, (const BYTE *)FormatStr
		, (DWORD)(wcslen(FormatStr) * sizeof(WCHAR))) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	dwData = 0;
	if (RegSetValueEx(hKey
		, L"Flags"
		, 0
		, REG_DWORD
		, (const BYTE *)&dwData
		, sizeof(DWORD)) != ERROR_SUCCESS)
	{
		return FALSE;
	}

	RegFlushKey(hKey);
	RegCloseKey(hKey);

	return TRUE;
}

BOOL UnInstallMiniFilter(void)
{
	SC_HANDLE schManager = NULL;
	SC_HANDLE schService = NULL;
	SERVICE_STATUS svcStatus;

	schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!schManager)
	{
		return FALSE;
	}

	schService = OpenService(schManager,DRIVER_NAME,SERVICE_ALL_ACCESS);
	if (!schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}

	ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus);
	if (!DeleteService(schService))
	{
		CloseServiceHandle(schManager);
		CloseServiceHandle(schService);
		return FALSE;
	}

	CloseServiceHandle(schManager);
	CloseServiceHandle(schService);
	return TRUE;

}

BOOL StartFilter(void)
{
	SC_HANDLE schManager = NULL;
	SC_HANDLE schService = NULL;
	DWORD errorCode = 0;

 	schManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (!schManager)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}

	schService = OpenService(schManager,DRIVER_NAME,SERVICE_ALL_ACCESS);
	if (!schService)
	{
		CloseServiceHandle(schManager);
		CloseServiceHandle(schService);
		return FALSE;
	}

 	if (!StartService(schService, 0, NULL))
	{
		errorCode = GetLastError();
		CloseServiceHandle(schManager);
		CloseServiceHandle(schService);
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
		{
			return TRUE;
		}

		return FALSE;
	}

	CloseServiceHandle(schManager);
	CloseServiceHandle(schService);

	return TRUE;
}

BOOL StopFilter(void)
{
	SC_HANDLE schManager = NULL;
	SC_HANDLE schService = NULL;
	SERVICE_STATUS svcStatus;

	schManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (!schManager)
	{
		return FALSE;
	}

	schService = OpenService(schManager,DRIVER_NAME,SERVICE_ALL_ACCESS);
	if (!schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}

	if (!ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus) && svcStatus.dwCurrentState != SERVICE_STOPPED)
	{
		CloseServiceHandle(schManager);
		CloseServiceHandle(schService);
		return FALSE;
	}

	CloseServiceHandle(schManager);
	CloseServiceHandle(schService);
	return TRUE;
}


UINT CommunicationWork(COMMUNICATION_THREAD_CONTEXT *pContext)
{
	HRESULT hr;
	DWORD dwOutSize;
	ULONG_PTR dwKey;
	LPOVERLAPPED pOvlp = NULL;
	FE_MESSAGE *pMessage = NULL;
	FER3_REPLY_MESSAGE ReplyMessage;

	while(1)
	{
		hr = GetQueuedCompletionStatus(pContext->m_Completion,&dwOutSize,&dwKey,&pOvlp,INFINITE);
		pMessage = CONTAINING_RECORD(pOvlp,FE_MESSAGE,m_Ovlp);
		if(!hr)
			break;
		ReplyMessage.m_pReplyHeader.MessageId = pMessage->m_MessageHeader.MessageId;
		ReplyMessage.m_pReplyHeader.Status = 0;

		hr = FilterReplyMessage(pContext->m_Port,
			(PFILTER_REPLY_HEADER)&ReplyMessage,
			sizeof(FER3_REPLY_MESSAGE));

		if(!hr)
			break;
		memset(&pMessage->m_Ovlp,0x00,sizeof(OVERLAPPED));
		hr = FilterGetMessage(pContext->m_Port,
			&pMessage->m_MessageHeader,
			FIELD_OFFSET(FE_MESSAGE,m_Ovlp),
			&pMessage->m_Ovlp
			);
		

	}

	free(pMessage);

	return 0;
}

UINT CommunicationThreadFunc(void *pContext)
{
	COMMUNICATION_THREAD_CONTEXT Context = {0x00};
	HRESULT hr;
	ULONG i,j;
	HANDLE hThreads[DEFAULT_THREAD_COUNT] = {0x00};
	FE_MESSAGE *pMessage = NULL;
	char *pFileBuffer = NULL;
	LARGE_INTEGER llFileSize = {0x00};
	WCHAR *pSendBuffer = NULL;
	LARGE_INTEGER llSendSize = {0x00};
	ULONG dwRetLen = 0;
	HANDLE hFile = NULL;
	ULONG dwReadSize = 0;
	ULONG dwProcId = 0;
	HANDLE hDevice = NULL;

	do 
	{
		hr = FilterConnectCommunicationPort(FEPortName,
			0,
			NULL,
			0,
			NULL,
			&Context.m_Port);
		if(IS_ERROR(hr))
			break;
		Context.m_Completion = CreateIoCompletionPort(Context.m_Port,
			NULL,
			0,
			DEFAULT_THREAD_COUNT);
		if(!Context.m_Completion)
			break;
		
		hFile = CreateFileW(RULE_PATH,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			0,
			NULL
			);
		if(hFile == INVALID_HANDLE_VALUE)
		{
			printf("CreateFileW fail:%d!\n",GetLastError());
			break;
		}

		if(!GetFileSizeEx(hFile,&llFileSize))
		{
			printf("GetFileSizeEx fail:%d!\n",GetLastError());
			break;
		}

		pFileBuffer = (char *)malloc(llFileSize.QuadPart);
		if(!pFileBuffer)
			break;

		memset(pFileBuffer,0x00,llFileSize.QuadPart);

		long dwResidueSize = llFileSize.QuadPart;
		while(ReadFile(hFile,pFileBuffer,min(0x1000,llFileSize.QuadPart),&dwReadSize,NULL))
		{
			dwResidueSize -= dwReadSize;
			if(dwResidueSize <= 0 || !dwReadSize)
				break;
		}

		llSendSize.QuadPart = MultiByteToWideChar(CP_ACP,0,pFileBuffer,llFileSize.QuadPart,NULL,0);
		if(!llSendSize.QuadPart)
		{
			printf("MultiByteToWideChar fail:%d!\n",GetLastError());
			break;
		}

		pSendBuffer = (WCHAR *)malloc(llSendSize.QuadPart * sizeof(WCHAR));
		if(!pSendBuffer)
			break;
		memset(pSendBuffer,0x00,llSendSize.QuadPart * sizeof(WCHAR));

		MultiByteToWideChar(PAGE_READONLY,0,pFileBuffer,llFileSize.QuadPart,pSendBuffer,llSendSize.QuadPart * sizeof(WCHAR));
		//FilterSendMessage(Context.m_Port,pSendBuffer,llSendSize.QuadPart,NULL,0,&dwRetLen);
		
		hDevice = OpenDevice();

		if(!hDevice || hDevice == INVALID_HANDLE_VALUE)
			break;
		g_hDevice = hDevice;

		if(!DeviceIoControl(hDevice,
			FE_SETRULE_CODE,
			pSendBuffer,
			llSendSize.QuadPart * sizeof(WCHAR),
			NULL,
			0,
			&dwRetLen,
			NULL
			))
		{
			printf("DeviceIoControl Fail:%d!\n",GetLastError());
		}
		dwProcId = (ULONG)GetCurrentProcess();
		if(!DeviceIoControl(hDevice,
			FE_SETPROCESSID_CODE,
			&dwProcId,
			sizeof(ULONG),
			NULL,
			0,
			&dwRetLen,
			NULL))
		{
			printf("DeviceIoControl Fail:%d!\n",GetLastError());
		}

		for(i = 0; i < DEFAULT_THREAD_COUNT; ++i)
		{
			hThreads[i] = CreateThread(NULL,
				0,
				(LPTHREAD_START_ROUTINE)CommunicationWork,
				&Context,
				0,
				NULL
				);
			if(!hThreads[i])
				break;
			for(j = 0; j < DEFAULT_REQUEST_COUNT; ++j)
			{
				pMessage = (FE_MESSAGE *)malloc(sizeof(FE_MESSAGE));
				if(!pMessage)
					break;
				memset(pMessage,0x00,sizeof(FE_MESSAGE));

				hr = FilterGetMessage(Context.m_Port,
					&pMessage->m_MessageHeader,
					FIELD_OFFSET(FE_MESSAGE,m_Ovlp),
					&pMessage->m_Ovlp
					);
				if(hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
				{
					free(pMessage);
					break;
				}
			}
		}


	} while (0);

	WaitForMultipleObjectsEx(i,
		hThreads,
		TRUE,
		INFINITE,
		FALSE);

	if(Context.m_Port)
		CloseHandle(Context.m_Port);
	if(Context.m_Completion)
		CloseHandle(Context.m_Completion);
	if(hFile)
		CloseHandle(hFile);
	if(pFileBuffer)
		free(pFileBuffer);
	if(pSendBuffer)
		free(pSendBuffer);
	if(g_hDevice)
		CloseHandle(g_hDevice);

	
	return 0;
}

BOOL CreatePort(PCWSTR PortName)
{
	HANDLE threadHandle = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)CommunicationThreadFunc,(LPVOID)PortName,0,NULL);
	if (!threadHandle)
		return FALSE;

	return TRUE;
}

BOOL InitMiniFilter(void)
{
	if (!InstallMiniFilter())
	{
		return FALSE;
	}

	if (!StartFilter())
	{
		return FALSE;
	}

	if (!CreatePort(FEPortName))
	{
		return FALSE;
	}

	return TRUE;
}

int main(int argc, char *argv[])
{
	do 
	{
		printf("input anyting Install Driver!\n");
		getchar();

		if(!InitMiniFilter())
		{
			printf("Install Driver fail:%d!\n",GetLastError());
			break;
		}


		printf("input anything UnInstall Driver!\n");
		getchar();
		if(!UnInstallMiniFilter())
		{
			printf("UnInstall Driver fail:%d!\n");
			break;
		}

	} while (0);
	
	
	while(getchar() != '\n')
		continue;
	system("PAUSE");
	return 0;
}