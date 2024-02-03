/* 
	===== CImpREC Class =====
*/

#ifndef __IMP_REC__
#define __IMP_REC__

#include "Export.h"
#include "PEFile.h"
#include "Import.h"
#include <tlhelp32.h>
#include "psapi.h"
#include <string>
#include <vector>

typedef	std::vector<std::string> ProcessModuleList;
typedef	std::vector<DWORD> ProcessModuleHandle;
typedef	std::vector<DWORD> ProcessModuleSize;

class CImpREC
{
public:
			CImpREC();
			~CImpREC();

	BOOL	Init();
	DWORD	LoadProcess(DWORD pid, DWORD base);
	void	LogIAT(DWORD rva_iat_slot, DWORD va_api);
	DWORD	FixDump(LPTSTR dump_filename);

protected:

	BOOL	InitAPIs();
	void	UltraArrange();

	BOOL	AddImp(DWORD rva, char *mod_name, WORD ordinal, char *proc_name,
				   bool valid = true , bool force = false );

	void	ValidateImport();

	// Check, modify and validate import
	DWORD	GetImportSize();

protected:
	CExport	*m_exports;
	int		m_nb_exports;
	bool	m_nt_os;
	DWORD	m_pid;
	DWORD	m_imgbase;
//	DWORD	m_imgsize;
	bool	m_importbyordinal;
//	DWORD	m_tracer_max_recursion;
//	DWORD	m_tracer_buffer_size;
	bool	m_newsection;
	DWORD	m_iat_rva;
	DWORD	m_iat_size;
//	DWORD	m_oep;

	DWORD	m_k32_base;
	DWORD	m_k32_size;

	ProcessModuleList	m_proc_mods;
	ProcessModuleHandle	m_proc_hmods;
	ProcessModuleHandle	m_proc_szmods;
	CImport				m_imports;

	// Win 9* API'S (toolhelp32)
	typedef	HANDLE	(WINAPI *FUNC1)(DWORD dwFlags, DWORD th32ProcessID);
	typedef	BOOL	(WINAPI *FUNC2)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
	typedef	BOOL	(WINAPI *FUNC3)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
	typedef	BOOL	(WINAPI *FUNC4)(HANDLE hSnapshot, LPHEAPLIST32 lphl);
	typedef	BOOL	(WINAPI *FUNC5)(LPHEAPENTRY32 lphe, DWORD pid, DWORD hid);
	typedef	BOOL	(WINAPI *FUNC6)(LPHEAPENTRY32 lphe);


	FUNC1	MyCreateToolhelp32Snapshot;
	FUNC2	MyProcess32First;
	FUNC2	MyProcess32Next;
	FUNC3	MyModule32First;
	FUNC3	MyModule32Next;
	FUNC4	MyHeap32ListFirst;
	FUNC4	MyHeap32ListNext;
	FUNC5	MyHeap32First;
	FUNC6	MyHeap32Next;

	// Win NT/2000 API'S (psapi)
	HMODULE	m_psapi_hmod;

	typedef	BOOL	(WINAPI *FUNC_NT1)(DWORD *lpidProcess, DWORD cb, DWORD *cbNeeded);
	typedef	BOOL	(WINAPI *FUNC_NT2)(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded);
	typedef	BOOL	(WINAPI *FUNC_NT3)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
	typedef	BOOL	(WINAPI *FUNC_NT4)(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
	typedef	BOOL	(WINAPI *FUNC_NT5)(HANDLE hProcess, PPROCESS_MEMORY_COUNTERS lppmc, DWORD nSize);

	FUNC_NT1	MyEnumProcesses;
	FUNC_NT2	MyEnumProcessModules;
	FUNC_NT3	MyGetModuleInformation;
	FUNC_NT4	MyGetModuleFileNameEx;
	FUNC_NT5	MyGetProcessMemoryInfo;

};

#endif
