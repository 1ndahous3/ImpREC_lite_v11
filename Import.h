#ifndef __IMPORT_H__
#define __IMPORT_H__

#include <map>
#include <string>
#include <vector>
#include "Header.h"

class CExport;

typedef struct
{
	DWORD	va_to_fix;
	DWORD	va_api;
	DWORD	output_offset;
	bool	done;
} LoaderImport;

typedef struct _MyImpThunk
{
	char			module_name[IMPREC_MAX_CHARS];
	char			name[IMPREC_MAX_CHARS];
	DWORD			rva;
	WORD			ordinal;
	bool			valid;
	void*			view;
} MyImpThunk;

typedef	std::map<DWORD, MyImpThunk>	ImpThunkList;

typedef struct _MyModule
{
	char			name[IMPREC_MAX_CHARS];
	DWORD			first_thunk;
	ImpThunkList	thunk_list;
	DWORD			nb_thunks;
	bool			valid;
	void*			view;
} MyImpModule;

typedef	std::map<DWORD, MyImpModule>	ImpModuleList;


class CImport
{
public:
	CImport();
	~CImport();

	bool	AddFunction(char *module_name, DWORD rva, WORD ordinal, char *name,
						void **view, bool valid = true, bool force = false);
	bool	AddModule(char *module_name, DWORD first_thunk, DWORD nb_thunks,
					  void *view = NULL, bool valid = true);
	bool	DeleteModule(DWORD rva);
	void	StickModules();
	void	ShowAll();
	DWORD	GetNbModules();
	DWORD	GetNbFunctions();
	void	DeleteAll();
	bool	SetModuleName(DWORD rva, char *module_name);
	bool	SetModuleValidity(DWORD rva, bool valid);
	bool	GetFirstThunk(DWORD rva, DWORD *first_thunk);
	void*	GetModuleView(DWORD rva);
	bool	SetModuleView(DWORD first_thunk, void *view);
	bool	SetFunctionView(DWORD rva, void *view);
	void*	GetFunctionView(DWORD rva);
	bool	InvalidateFunction(DWORD rva, char *ptr);
	bool	GetFunctionValidity(DWORD rva);
	bool	GetModuleValidity(DWORD first_thunk);
	bool	CutThunk(DWORD rva);

	ImpModuleList	CImport::GetModel();

protected:
	ImpModuleList	m_module_list;
	DWORD			m_nb_functions;
};

#endif
