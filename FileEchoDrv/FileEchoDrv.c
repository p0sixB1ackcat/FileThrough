/*++

Module Name:

    FileEchoDrv.c

Abstract:

    This is the main module of the FileEchoDrv miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <ntddk.h>
//#ifdef _DDK_WIN7
#include <minwindef.h>
//#endif
#include "FileEchoUK.h"

#define DEVICE_NAME L"\\Device\\FileEchoDrv"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\FileEchoDrv"

#define STATUS_FE_REPARSE 0xf00000001

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

/** 全局资源
*	m_pDriverObject:驱动对象
*	m_DeviceObject:控制设备对象
*	m_pFilter:MiniFilter对象
*	m_ServerPort:和R3通信的端口
*/
typedef struct _GLOBAL_CONTROL_DATA
{
	DRIVER_OBJECT* m_pDriverObject;
	DEVICE_OBJECT* m_DeviceObject;
	PFLT_FILTER m_pFilter;
	PFLT_PORT m_ServerPort;
	ULONG_PTR m_OperationStatusCtx;
	HANDLE m_ApplicationProcessId;
	ERESOURCE m_RuleListLock;
	LIST_ENTRY m_RuleList;
}GLOBAL_CONTROL_DATA,*PGLOBAL_CONTROL_DATA;

typedef struct _RULE_ECHO_DATA
{
	UNICODE_STRING m_SourcePath;
	UNICODE_STRING m_EchoPath;
	LIST_ENTRY m_List;
}RULE_ECHO_DATA,*PRULE_ECHO_DATA;

GLOBAL_CONTROL_DATA g_Global_Control_Data = {0x00};

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

//zEXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
     PDRIVER_OBJECT DriverObject,
     PUNICODE_STRING RegistryPath
    );

FLT_PREOP_CALLBACK_STATUS
CreateFilePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
CreateFilePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
WriteFilePreOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
WriteFilePostOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
);

NTSTATUS
FileEchoDrvUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FileEchoDrvPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );


FLT_POSTOP_CALLBACK_STATUS
FileEchoDrvPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );


NTSTATUS
FltPortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID* ConnectionCookie
);

VOID
FltPortDisconnect(
	__in_opt PVOID ConnectionCookie
);

NTSTATUS FltNotifyMessage(PVOID PortCookie
	, PVOID InputBuffer
	, ULONG InputBufferLength
	, PVOID OutputBuffer
	, ULONG OutputBufferLength
	, ULONG* ReturnOutputLength);

NTSTATUS DispatchIoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

NTSTATUS DispatchWrite(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

void ResolveRule(WCHAR* BufferPointer, ULONG BufferSize);

//EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FileEchoDrvUnload)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      CreateFilePreOperation,
      CreateFilePostOperation },

    { IRP_MJ_WRITE,
      0,
      WriteFilePreOperation,
      WriteFilePostOperation },


    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      FileEchoDrvPreOperation,
      FileEchoDrvPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      FileEchoDrvPreOperation,
      FileEchoDrvPostOperation },


    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    FileEchoDrvUnload,                           //  MiniFilterUnload

    NULL,                    //  InstanceSetup
    NULL,            //  InstanceQueryTeardown
    NULL,            //  InstanceTeardownStart
    NULL,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

VOID DriverUnload(PDRIVER_OBJECT pDeviceObject)
{
	KdPrint(("DriverUnload!\n"));
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

VOID LockList(PERESOURCE pLock)
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(pLock);
}

VOID UnlockList(PERESOURCE pLock)
{
	ExReleaseResourceAndLeaveCriticalRegion(pLock);
}

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
	UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES stObjAttr;
	UNICODE_STRING uPortName = {0x00};
	PSECURITY_DESCRIPTOR sd;
	UNICODE_STRING uDeviceName = {0x00};
	UNICODE_STRING uSymbolicLinkName = {0x00};
	ULONG i;

	DbgBreakPoint();

	__try
	{
		RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);
		Status = IoCreateDevice(DriverObject, 0, &uDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_Global_Control_Data.m_DeviceObject);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("IoCreateDevice Fail:%d!\n", Status));
			__leave;
		}

		RtlInitUnicodeString(&uSymbolicLinkName, SYMBOLIC_LINK_NAME);
		Status = IoCreateSymbolicLink(&uSymbolicLinkName, &uDeviceName);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("IoCreateSymbolicLink Fail:%d\n", Status));
			__leave;
		}

		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
		{
			DriverObject->MajorFunction[i] = DispatchIoControl;
		}

		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
		DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
		DriverObject->DriverUnload = DriverUnload;
		
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("FileEchoDrv!DriverEntry: Entered\n"));

		//
		//  Register with FltMgr to tell it our callback routines
		//

		Status = FltRegisterFilter(DriverObject,
			&FilterRegistration,
			&g_Global_Control_Data.m_pFilter);

		FLT_ASSERT(NT_SUCCESS(Status));

		g_Global_Control_Data.m_pDriverObject = DriverObject;

		Status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FltBuildDefaultSecurityDescriptor fail : 0x%x. \n", Status));
			__leave;
		}

		RtlInitUnicodeString(&uPortName, L"\\FileEchoPort");
		InitializeObjectAttributes(&stObjAttr,
			&uPortName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd
		);

		Status = FltCreateCommunicationPort(g_Global_Control_Data.m_pFilter, 
			&g_Global_Control_Data.m_ServerPort, 
			&stObjAttr,
			NULL, 
			FltPortConnect, 
			FltPortDisconnect, 
			FltNotifyMessage, 
			1); 

		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FltCreateCommunicationPort fail : 0x%x. \n"));
			__leave;
		}

		Status = FltStartFiltering(g_Global_Control_Data.m_pFilter);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FltStartFiltering fail : 0x%x. \n", Status));
			__leave;
		}

		FltFreeSecurityDescriptor(sd);
		InitializeListHead(&g_Global_Control_Data.m_RuleList);
		ExInitializeResourceLite(&g_Global_Control_Data.m_RuleListLock);

		Status = STATUS_SUCCESS;
	}
	
	__finally
	{
		if (!NT_SUCCESS(Status))
		{
			if (g_Global_Control_Data.m_DeviceObject)
			{
				IoDeleteDevice(g_Global_Control_Data.m_DeviceObject);
			}
			if (g_Global_Control_Data.m_pFilter)
			{
				FltUnregisterFilter(g_Global_Control_Data.m_pFilter);
			}
		}
	}

    return Status;
}

NTSTATUS
FileEchoDrvUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
	LIST_ENTRY* List = NULL;
	LIST_ENTRY* pTmpList = NULL;
	RULE_ECHO_DATA* pRuleData = NULL;
	UNICODE_STRING uSymbolicLinkName = {0x00};
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileEchoDrv!FileEchoDrvUnload: Entered\n") );

	FltCloseCommunicationPort(g_Global_Control_Data.m_ServerPort);

    FltUnregisterFilter( g_Global_Control_Data.m_pFilter );

	if (g_Global_Control_Data.m_DeviceObject)
	{
		IoDeleteDevice(g_Global_Control_Data.m_DeviceObject);
		RtlInitUnicodeString(&uSymbolicLinkName, SYMBOLIC_LINK_NAME);
		IoDeleteSymbolicLink(&uSymbolicLinkName);
	}

	LockList(&g_Global_Control_Data.m_RuleListLock);
	List = g_Global_Control_Data.m_RuleList.Flink;
	while (List && List != &g_Global_Control_Data.m_RuleList)
	{
		pRuleData = CONTAINING_RECORD(List,RULE_ECHO_DATA,m_List);
		if(!pRuleData)
			break;
		if (pRuleData->m_SourcePath.Buffer && pRuleData->m_SourcePath.Length)
			ExFreePoolWithTag(pRuleData->m_SourcePath.Buffer, 0);
		if (pRuleData->m_EchoPath.Buffer && pRuleData->m_EchoPath.Length)
			ExFreePoolWithTag(pRuleData->m_EchoPath.Buffer, 0);
		pTmpList = List;
		List = List->Flink;
		RemoveEntryList(pTmpList);
		ExFreePoolWithTag(pRuleData, 0);
	}
	UnlockList(&g_Global_Control_Data.m_RuleListLock);

    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
WriteFilePreOperation(
	PFLT_CALLBACK_DATA Data, 
	PCFLT_RELATED_OBJECTS FltObjects, 
	PVOID* CompletionContext
)
{
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
WriteFilePostOperation(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
)
{
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
CreateFilePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{	
	LIST_ENTRY* List = NULL;
	RULE_ECHO_DATA* pRuleData = NULL;
	PFLT_FILE_NAME_INFORMATION pFileNameInfo = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING uReplacePath = {0x00};
	BOOL bIsEcho = FALSE;
	FLT_PREOP_CALLBACK_STATUS fltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	__try
	{
		if (PsGetCurrentProcessId() == 4 || PsGetCurrentProcessId() == 0)
		{
			__leave;
		}
		if (!FltObjects->FileObject)
		{
			__leave;
		}
		if (!Data->Iopb->TargetFileObject->FileName.Length || !Data->Iopb->TargetFileObject->FileName.Buffer)
		{
			__leave;
		}

		Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &pFileNameInfo);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}

		Status = FltParseFileNameInformation(pFileNameInfo);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}

		LockList(&g_Global_Control_Data.m_RuleListLock);
		List = g_Global_Control_Data.m_RuleList.Flink;
		while (List != &g_Global_Control_Data.m_RuleList)
		{
			pRuleData = CONTAINING_RECORD(List, RULE_ECHO_DATA, m_List);
			if (pRuleData != NULL 
				&&
				RtlCompareUnicodeString(&pFileNameInfo->Name, &pRuleData->m_SourcePath, TRUE) == 0
				)
			{
				//当前写入目标文件和匹配规则
				//这里，UNICODE_STRING的Length一定要精准，不能多，就像周哥之前就说过，UNICODE_STRING的处理不是按照他的Buffer为\0来计算结尾，而是按照长度来定位结尾
				uReplacePath.Length = 0;
				uReplacePath.MaximumLength = MAX_PATH * sizeof(WCHAR);
				uReplacePath.Buffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH * sizeof(WCHAR), '3syS');
				if (uReplacePath.Buffer)
				{
					RtlZeroMemory(uReplacePath.Buffer, uReplacePath.Length);
					RtlCopyUnicodeString(&uReplacePath, &pRuleData->m_EchoPath);

					if (Data->Iopb->TargetFileObject->FileName.Buffer && Data->Iopb->TargetFileObject->FileName.Length)
					{
						ExFreePool(Data->Iopb->TargetFileObject->FileName.Buffer);
					}

					Data->Iopb->TargetFileObject->FileName.Buffer = uReplacePath.Buffer;
					Data->Iopb->TargetFileObject->FileName.Length = uReplacePath.Length;
					Data->Iopb->TargetFileObject->FileName.MaximumLength = uReplacePath.MaximumLength;
					//FltSetCallbackDataDirty(Data);

					KdPrint(("文件重定向%wZ--->%wZ\n", &pRuleData->m_SourcePath, &pRuleData->m_EchoPath));
					Data->IoStatus.Information = IO_REPARSE;
					Data->IoStatus.Status = STATUS_REPARSE;
					bIsEcho = TRUE;
					break;
				}
			}
			
			List = List->Flink;
		}

		UnlockList(&g_Global_Control_Data.m_RuleListLock);
	}
	__finally
	{
		if (bIsEcho == TRUE)
		{
			fltStatus = FLT_PREOP_COMPLETE;
		}
		else
		{
			if (!NT_SUCCESS(Status))
			{
				fltStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
			}
			else
			{
				fltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}

		if (pFileNameInfo)
		{
			FltReleaseFileNameInformation(pFileNameInfo);
		}
	}
	
	return fltStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CreateFilePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	do 
	{
		if (ExGetPreviousMode() == KernelMode ||
			KeGetCurrentIrql() > APC_LEVEL)
			break;

		if (Data->IoStatus.Status == STATUS_OBJECT_PATH_NOT_FOUND)
		{
			KdPrint(("\n"));
		}

	} while (0);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS DispatchWrite(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS DispatchIoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode)
	{
		case FE_SETPROCESSID_CODE:
		{
			RtlCopyMemory(&g_Global_Control_Data,pIrp->AssociatedIrp.SystemBuffer,sizeof(HANDLE));
		}
		break;
		case FE_SETRULE_CODE:
		{
			ResolveRule(pIrp->AssociatedIrp.SystemBuffer,pIrpStack->Parameters.DeviceIoControl.InputBufferLength);
		}
		break;
	}

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = ntStatus;

	IoCompleteRequest(pIrp,IO_NO_INCREMENT);

	return ntStatus;
}

FLT_PREOP_CALLBACK_STATUS
FileEchoDrvPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileEchoDrv!FileEchoDrvPreOperation: Entered\n") );

	
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
FileEchoDrvPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileEchoDrv!FileEchoDrvPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS
FltPortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID* ConnectionCookie
)
{
	KdPrint(("R3 App is Connect!\n"));
	*ConnectionCookie = NULL;
	return STATUS_SUCCESS;
}

VOID
FltPortDisconnect(
	__in_opt PVOID ConnectionCookie
)
{
	KdPrint(("R3 App is Disconnect!\n"));
}

BOOLEAN
SymbolicNameToDeviceName(
	__in PUNICODE_STRING puSymbolicName, 
	__out PUNICODE_STRING puDeviceName 
	)
{
	DECLARE_UNICODE_STRING_SIZE(uNotHasPartition, MAX_PATH);
	HANDLE hSymbolic = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uDeviceName = { 0x00 };
	WCHAR* pBuffer = NULL;
	ULONG ulNeedSize = 0;
	OBJECT_ATTRIBUTES stObjAttr = { 0x00 };
	UNICODE_STRING uSymbolicName = { 0x00 };
	WCHAR pSymbolic[6] = L"\\??\\c:";
	BOOLEAN bRet = FALSE;

	__try
	{
		if (puSymbolicName == NULL || puDeviceName == NULL)
		{
			Status = STATUS_INVALID_PARAMETER;
			__leave;
		}

		RtlAppendUnicodeToString((PUNICODE_STRING)&uNotHasPartition, puSymbolicName->Buffer + 2);

		pSymbolic[4] = *puSymbolicName->Buffer;
		RtlInitUnicodeString(&uSymbolicName, pSymbolic);

		InitializeObjectAttributes(&stObjAttr, &uSymbolicName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		Status = ZwOpenSymbolicLinkObject(&hSymbolic, SYMBOLIC_LINK_QUERY, &stObjAttr);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}

		Status = ZwQuerySymbolicLinkObject(hSymbolic, &uDeviceName, &ulNeedSize);
		if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_TOO_SMALL)
		{
			pBuffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, ulNeedSize, 'bveD');
			if (pBuffer == NULL)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			RtlZeroMemory(pBuffer, ulNeedSize);
			uDeviceName.Length = 0;
			uDeviceName.MaximumLength = ulNeedSize;
			uDeviceName.Buffer = pBuffer;

			Status = ZwQuerySymbolicLinkObject(hSymbolic, &uDeviceName, &ulNeedSize);
			if (!NT_SUCCESS(Status))
			{
				__leave;
			}
			
			RtlCopyUnicodeString(puDeviceName, &uDeviceName);
			RtlAppendUnicodeToString(puDeviceName, uNotHasPartition.Buffer);
			bRet = TRUE;
		}
	}
	__finally
	{
		if (hSymbolic)
		{
			ZwClose(hSymbolic);
		}
		if (pBuffer)
		{
			ExFreePool(pBuffer);
			pBuffer = NULL;
		}
	}

	return bRet;
}

void ResolveRule(WCHAR* BufferPointer, ULONG BufferSize)
{
	WCHAR* p = BufferPointer;
	WCHAR* q = p;
	WCHAR* SpaceFlagStr = L"--->";
	RULE_ECHO_DATA* pRuleEcho = NULL;
	ULONG dwSize = 0;
	WCHAR* pTail = NULL;
	ULONG i = 0;

	if (!MmIsAddressValid(BufferPointer) || !BufferSize)
		return;

	while (i < BufferSize)
	{
		if (wcsncmp(p, SpaceFlagStr, wcslen(SpaceFlagStr)) == 0)
		{
			pRuleEcho = (RULE_ECHO_DATA*)ExAllocatePoolWithTag(PagedPool, sizeof(RULE_ECHO_DATA), '0syS');
			if (!pRuleEcho)
				break;
			memset(pRuleEcho, 0x00, sizeof(RULE_ECHO_DATA));

			ULONG ulCopyLen = ((ULONG)p - (ULONG)q) + sizeof(WCHAR);
			pRuleEcho->m_SourcePath.Length = 0;
			pRuleEcho->m_SourcePath.MaximumLength = MAX_PATH * sizeof(WCHAR);
			pRuleEcho->m_SourcePath.Buffer = ExAllocatePoolWithTag(PagedPool, MAX_PATH * sizeof(WCHAR), '1syS');
			if (!pRuleEcho->m_SourcePath.Buffer)
			{
				ExFreePoolWithTag(pRuleEcho, 0);
				break;
			}
			memset(pRuleEcho->m_SourcePath.Buffer, 0x00, MAX_PATH * sizeof(WCHAR));
			RtlCopyMemory(pRuleEcho->m_SourcePath.Buffer, q, ulCopyLen - sizeof(WCHAR));
			
			pTail = p;
			while (*pTail != L'\0' && *pTail != L'\n')
				++pTail;
			if (*pTail == L'\n')
			{
				ulCopyLen = (ULONG)(pTail - 1) - (ULONG)(p + wcslen(SpaceFlagStr)) + sizeof(WCHAR);

				pRuleEcho->m_EchoPath.Length = 0;
				pRuleEcho->m_EchoPath.MaximumLength = MAX_PATH * sizeof(WCHAR);
				pRuleEcho->m_EchoPath.Buffer = ExAllocatePoolWithTag(PagedPool, MAX_PATH * sizeof(WCHAR), '2syS');
				if (!pRuleEcho->m_EchoPath.Buffer)
				{
					ExFreePoolWithTag(pRuleEcho->m_SourcePath.Buffer, 0);
					ExFreePoolWithTag(pRuleEcho, 0);
					break;
				}

				memset(pRuleEcho->m_EchoPath.Buffer, 0x00, MAX_PATH * sizeof(WCHAR));
				RtlCopyMemory(pRuleEcho->m_EchoPath.Buffer, p + wcslen(SpaceFlagStr), ulCopyLen - sizeof(WCHAR));

				q = pTail + 1;
			}

			LockList(&g_Global_Control_Data.m_RuleListLock);
			InsertTailList(&g_Global_Control_Data.m_RuleList, &pRuleEcho->m_List);
			UnlockList(&g_Global_Control_Data.m_RuleListLock);
		}
		i += sizeof(WCHAR);
		++p;
	}

	LockList(&g_Global_Control_Data.m_RuleListLock);

	for (LIST_ENTRY* Entry = g_Global_Control_Data.m_RuleList.Flink; Entry != &g_Global_Control_Data.m_RuleList; Entry = Entry->Flink)
	{
		PRULE_ECHO_DATA pRuleData = (PRULE_ECHO_DATA)CONTAINING_RECORD(Entry, RULE_ECHO_DATA, m_List);
		if (pRuleData)
		{
			SymbolicNameToDeviceName(&pRuleData->m_SourcePath, &pRuleData->m_SourcePath);
			SymbolicNameToDeviceName(&pRuleData->m_EchoPath, &pRuleData->m_EchoPath);
		}
	}

	UnlockList(&g_Global_Control_Data.m_RuleListLock);

}

NTSTATUS FltNotifyMessage(PVOID PortCookie
	, PVOID InputBuffer
	, ULONG InputBufferLength
	, PVOID OutputBuffer
	, ULONG OutputBufferLength
	, ULONG* ReturnOutputLength)
{
	KdPrint(("Recive R3 App Message：%ws!\n",(wchar_t *)InputBuffer));

	return STATUS_SUCCESS;
}

