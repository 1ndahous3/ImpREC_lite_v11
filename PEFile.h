// PEFile.h: header for the CPEFile class.
//
//////////////////////////////////////////////////////////////////////

#ifndef PEFILE_H
#define PEFILE_H

#include "pe.h"
#include "Header.h"

class CPEFile  
{
// Public methods
public:
	CPEFile(HWND hwnd = NULL);
	virtual ~CPEFile();

	void  SetIsModule(bool is_module);
	bool  LoadExecutable(char *filename);
	bool  LoadPEVars(char *filename, DWORD pid, bool use_pe_header_from_disk,
					 DWORD image_base, DWORD image_size);
	bool  WriteInfos(char *filename);
	bool  SaveExecutable(char *filename);
	bool  SavePartialExecutable(char *filename, DWORD start, DWORD length);
	bool  SaveHeaderOnly(char *filename);
	bool  FixHeader();
	bool  UpdatePEVars(bool fix_sections = false);
	bool  RebuildImport(void **name_import);
	int   FindSectionIndex(DWORD addr);
	int   FindSectionIndexOffset(DWORD addr);
	bool  RVA2Offset(DWORD rva, DWORD *offset);
	int   GetLastSectionIndex();
	bool  AddSection(char *name, DWORD size, DWORD *my_rva, DWORD *new_sz, DWORD flags);

	static bool FixSections(unsigned char *pe_buffer);

// Protected methods
protected:

// Protected datas
public:
	bool				m_is_module;
	HWND				m_hwnd;							// for messagebox (can be NULL)
	char				m_filename[IMPREC_MAX_CHARS];	// name of executable
	unsigned char		*m_buffer;						// buffer of executable
	long				m_size;							// size of executable

	DWORD					*m_ord_table;	// Ordinal table for function names
	IMAGE_EXPORT_DIRECTORY	*m_ptr_exp;		// Ptr to the export directory

	// pe infos
	unsigned int		m_dosstub_size;
	PEHeader			*m_pe_header;
	StdOptionalHeader	*m_std_header;
	NTOptionalHeader	*m_nt_header;
	ROMOptionalHeader	*m_rom_header;
	DataDirectory		*m_directories;
	Section				*m_sections;
};

#endif
