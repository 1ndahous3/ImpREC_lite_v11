#ifndef __IMPREC_HEADER__
#define __IMPREC_HEADER__

#define IMPREC_MAX_CHARS	1024

#define	MyRPM	ReadProcessMemory
/*extern BOOL MyRPM(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize,
				  LPDWORD lpNumberOfBytesRead);

extern DWORD MyVQEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer,
					DWORD dwLength);*/

// ERRORS
#define	IREC_ALL_OK						0
#define	IREC_PROCESS_ERROR				100
#define	IREC_PE_ERROR					101
#define	IREC_MODULE_NOT_FOUND_ERROR		102
#define	IREC_NO_MODULE_ERROR			103
#define	IREC_ADD_SECTION_ERROR			104
#define	IREC_RVA2OFFSET_ERROR			105
#define	IREC_INVALID_OFFSET_ERROR		106

#endif
