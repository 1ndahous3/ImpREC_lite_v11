========
DLL v1.1
========

Exported functions (C prototypes)
---------------------------------

- DWORD           SetModule(DWORD pid, DWORD base);

	+ <pid>  : PID of the process
	+ <base> : VA of the base of the module

- void            LogIATEntry(DWORD rva_iat_slot, DWORD va_api);

	+ <rva_iat_slot> : RVA of the slot (IAT)
	+ <va_api>       : VA of the resolved API

- DWORD           MakeImportTable(LPTSTR dump_filename);

	+ <dump_filename> : Filename of the dump to fix

	Note:
	-----
	The output filename contains a '_' just before the extension
	of <dump_filename>. (no need to backup)


Error codes:
------------
#define	IREC_ALL_OK				  0
#define	IREC_PROCESS_ERROR			100
#define	IREC_PE_ERROR				101
#define	IREC_MODULE_NOT_FOUND_ERROR		102
#define	IREC_NO_MODULE_ERROR			103
#define	IREC_ADD_SECTION_ERROR			104
#define	IREC_RVA2OFFSET_ERROR			105
#define	IREC_INVALID_OFFSET_ERROR		106
