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

#include "config.h"

/*
*******************************************************************************
*                                  Defines
*******************************************************************************
*/

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

/**
 * TODO
 * @ return 
 */
BOOL findNamedProcess( char * processName,  PROCESSENTRY32 * outProcessInfo )
{
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); 
	outProcessInfo->dwSize = sizeof(PROCESSENTRY32);  

	BOOL result;
  	do
    {
		result = Process32Next( handle, outProcessInfo );
		// check process name
		if( result == TRUE && strcmp( outProcessInfo->szExeFile, processName ) == 0 )
		{
			return TRUE;
		}
	} while (result != ERROR_NO_MORE_FILES);

	return FALSE;
}

void injectCode()
{

}


/*
*******************************************************************************
*                               Public functions
*******************************************************************************
*/

int main()
{
	PROCESSENTRY32 firefoxInfo;
	printf("%d", findNamedProcess( "firefox.exe", &firefoxInfo ));

	return 0;
}
