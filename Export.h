#ifndef __MYEXPORT
#define __MYEXPORT

#include "PEFile.h"
#include <vector>
#include "Header.h"

class CExport
{
public:
	CExport();
	~CExport();

	int		Create(char *lib_name, DWORD pid, DWORD base, DWORD size, DWORD k32_base);
	BOOL	GetProcNameByIndex(DWORD index, WORD *ordinal, char *buffer,
							   DWORD buffer_length);
	BOOL	GetProcName(void *address, char *buffer, DWORD buffer_length, WORD *ordinal,
						char *module, BOOL do_forward);
	BOOL	GetNearestProcName(void *address, char *buffer, DWORD buffer_length,
							   WORD *ordinal, char *module, BOOL do_forward);
	BOOL	CheckInterval(void *address);
	char*	GetLibName();
	char*	GetFullLibName();
	HMODULE	GetHandle();
	DWORD	GetNumberOfFunction();
	void	WriteExport(char *filename);
	BOOL	GetForward(char *mod, char *name, char *buffer, DWORD buffer_length,
					   WORD *ordinal);
	DWORD	GetBase();
	BOOL	BuildForwards(/*CExport *exports, int nb_export*/);
	void	FillExport();

	// Static public methods
	static void			ClearForwards();
	static FARPROC		GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

	void	Clean();

private:
	// Protected Datas
public:
	char								m_fullpath_libname[IMPREC_MAX_CHARS];
	CPEFile								*m_pe_file;
	BYTE								*m_export_directory;
	HMODULE								m_hmod;
	HMODULE								m_hmod_for_renormalize;

	DWORD								imageBase;
	DWORD								imageSize;
	DWORD								NumberOfFunctions;
	DWORD								Base;
	DWORD								ExportDirectorySize;

	DWORD								*m_table_nameordinals;	// Table which contains pointer to
																// ordinal to name exported function

	IMAGE_EXPORT_DIRECTORY				*m_ptr_exp;				// Ptr to the export directory

	// Exports
	typedef struct
	{
		char	func_name[IMPREC_MAX_CHARS];
		WORD	ordinal;
		DWORD	address;
	} APIInfo;

	// Forward chaining
	typedef struct
	{
		char	module_name[IMPREC_MAX_CHARS];
		char	func_name[IMPREC_MAX_CHARS];
		WORD	ordinal;
		DWORD	address;
		DWORD	original_address;
	} ForwardInfo;

	static std::vector<ForwardInfo>		m_forwards;
	std::vector<APIInfo>				m_exports;
};

#endif
