/**
*******************************************************************************
*                                   4IF                       
*                   (c) Copyright 2011, INSA de Lyon, FR
*                      
*                          All Rights Reserved
*
* \brief            TODO. 
* \author           Rodrigo CASTRO.
*******************************************************************************
*/

/*
*******************************************************************************
*                                  Headers
*******************************************************************************
*/

#include <Windows.h>
#include <TlHelp32.h>

#include <stdio.h>

#include "firefox.h"
#include "config.h"

/*
*******************************************************************************
*                                  Defines
*******************************************************************************
*/

typedef LONG		(WINAPI *SETWINDOWLONG)	  (HWND,int,LONG); 
typedef LRESULT		(WINAPI *CALLWINDOWPROC)  (WNDPROC,HWND,UINT,WPARAM,LPARAM);

typedef struct {
	// TODO add injected data here
	int testData;

	FUNC_PR_Write originalPR_Write;
	FUNC_PR_Write functionHook;
	size_t functionHookSize;

	SETWINDOWLONG	fnSetWindowLong;
	CALLWINDOWPROC	fnCallWindowProc;	
	HWND hwnd;

	typedef LONG		(WINAPI *SETWINDOWLONG)	  (HWND,int,LONG); 
	typedef LRESULT		(WINAPI *CALLWINDOWPROC)  (WNDPROC,HWND,UINT,WPARAM,LPARAM);

} InjectedData;

/*
*******************************************************************************
*                              Global variables
*******************************************************************************
*/

/*
*******************************************************************************
*                              Private functions
*******************************************************************************
*/

#ifdef _DEBUG
#define HOOK_OFFSET 14
#else
#define HOOK_OFFSET 9
#endif

static PRInt32 firefoxPR_WriteHook(
	PRFileDesc * fd,
	const void * buf,
	PRInt32 amount )
{	
	// calculate the location of INJDATA
	// (remember that InjectedData in the remote process
	// is placed immediately before NewProc)	
	InjectedData * pData;	
	_asm {				
		call	dummy
dummy:
		pop		ecx			// <- ECX contains the current EIP (instruction pointer);
		sub		ecx, HOOK_OFFSET	// <- ECX contains the address of NewProc;
		mov		pData, ecx
	}
	pData--;


	//-------------------------------------
	// subclassing code starts here
	
	printf("%.*s\n----\n", amount, buf);

END:

	// call original window procedure
	return pData->originalPR_Write( fd, buf, amount );		
}

/**
 * TODO
 * @ return 
 */
BOOL findNamedProcess( char * processName,  PROCESSENTRY32 * outProcessInfo )
{
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); 
	outProcessInfo->dwSize = sizeof(PROCESSENTRY32);  

	BOOL notLastProcess;
  	do
    {
		notLastProcess = Process32Next( handle, outProcessInfo );
		// check process name
		if( notLastProcess == TRUE && strcmp( outProcessInfo->szExeFile, processName ) == 0 )
		{
			return TRUE;
		}
	} while (notLastProcess == TRUE);

	return FALSE;
}

void initInjectedData( InjectedData * injectedData, FUNC_PR_Write functionHook, size_t functionHookSize )
{
	// TODO
}

#define INJ_VIRTUAL_SIZE 480

static BOOL virtualInject( InjectedData * injectedData )
{
	return TRUE;
}

BOOL injectCodeFirefox( PROCESSENTRY32 firefoxInfo, InjectedData * injectedData, FUNC_PR_Write functionHook, size_t functionHookSize, BOOL useUnicode )
{
	HANDLE firefoxHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, firefoxInfo.th32ProcessID );
	if( firefoxHandle )
	{
		// init injectedData
		injectedData->functionHook = functionHook;
		injectedData->functionHookSize = functionHookSize;
		// hModule is null
		int error = TRUE;
		HMODULE hModule = GetModuleHandle( "nspr4.dll" );
		if( hModule == NULL )
			error = GetLastError();
		// TODO look for the next 'call' function
		return error;
		// injectedData->fnSetWindowLong = (SETWINDOWLONG)  GetProcAddress( hModule, useUnicode ? "SetWindowLongW" : "SetWindowLongA");
		// injectedData->fnCallWindowProc = 	(CALLWINDOWPROC) GetProcAddress( hModule, useUnicode ? "CallWindowProcW": "CallWindowProcA");

		// Virtual allocate memory for injected data + code
		size_t dataAndCodeSize = sizeof(InjectedData) + functionHookSize;
		BYTE * virtualData = (BYTE *)VirtualAllocEx( firefoxHandle, NULL, dataAndCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( virtualData != NULL)
		{
			BYTE * virtualHookCode = virtualData + sizeof(InjectedData);
			BOOL returnValue = WriteProcessMemory( firefoxHandle, virtualData,     injectedData, sizeof(InjectedData), NULL);
			returnValue &=     WriteProcessMemory( firefoxHandle, virtualHookCode, functionHook, functionHookSize, NULL);
			if( returnValue != FALSE)
			{
				// Virtual allocate memory for injected code
				LPVOID virtualInjectCode = VirtualAllocEx( firefoxHandle, NULL, INJ_FUNCTION_SIZE,  MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if( virtualInjectCode != NULL )
				{
					returnValue = WriteProcessMemory( firefoxHandle, virtualInjectCode, &virtualInject, INJ_VIRTUAL_SIZE, NULL);
					if( returnValue != FALSE)
					{           
						// Exectue the code !
						HANDLE remoteThread = CreateRemoteThread( firefoxHandle, NULL, 0, (LPTHREAD_START_ROUTINE) virtualInjectCode, virtualData, 0, NULL);
						if( remoteThread != NULL )
						{
							WaitForSingleObject(remoteThread, INFINITE);
							BOOL returnCode;
							GetExitCodeThread(remoteThread, (PDWORD)&returnCode);
							if( returnCode != FALSE )
							{
								// TODO dealloc virtual memory
								VirtualFreeEx(firefoxHandle, virtualData, 0, MEM_RELEASE);
								VirtualFreeEx(firefoxHandle, virtualInjectCode, 0, MEM_RELEASE);
								CloseHandle(firefoxHandle);
								return TRUE;
							}
						}
					}
					VirtualFreeEx(firefoxHandle, virtualInjectCode, 0, MEM_RELEASE);
				}
			}
			VirtualFreeEx(firefoxHandle, virtualData, 0, MEM_RELEASE);
		}

		// Some error arrived
		CloseHandle(firefoxHandle);
		return FALSE;
	}
	else
	{
		return FALSE;
	}
}


/*
*******************************************************************************
*                               Public functions
*******************************************************************************
*/

int main()
{
	PROCESSENTRY32 firefoxInfo;
	BOOL firefoxProcessFound = findNamedProcess( "firefox.exe", &firefoxInfo );

	if( firefoxProcessFound )
	{
		InjectedData data;
		data.testData = firefoxInfo.th32ProcessID;
		injectCodeFirefox( firefoxInfo, &data, firefoxPR_WriteHook, INJ_FUNCTION_SIZE, true );
	}
	return 0;
}
