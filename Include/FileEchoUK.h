#define FEPortName L"\\FileEchoPort"
#define DRIVER_NAME L"FileEchoDrv"
#define DRIVER_PATH L".\\FileEchoDrv.sys"
#define DRIVER_ALTITUDE L"370020"

#define BASE_CODE 0x8000
#define FE_CUSTOM_CODE(n) CTL_CODE(FILE_DEVICE_UNKNOWN, BASE_CODE + n, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FE_SETRULE_CODE FE_CUSTOM_CODE(1)
#define FE_SETPROCESSID_CODE FE_CUSTOM_CODE(2)

typedef struct _FE_UK_DATA
{
	unsigned long m_Len;
	unsigned char m_pBuffer[1];
}FE_UK_DATA,*PFE_UK_DATA;

typedef struct _FE_RELPY_DATA
{
	BOOLEAN SafeToOpen;
}FE_REPLY_DATA,*PFE_REPLY_DATA;

