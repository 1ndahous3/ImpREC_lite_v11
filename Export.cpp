#include "stdafx.h"
#include "Export.h"

// Static member variables
std::vector<CExport::ForwardInfo> CExport::m_forwards;


// Default constructor
CExport::CExport()
{
	m_hmod = 0;
	m_table_nameordinals = 0;
	m_ptr_exp = 0;
	m_pe_file = NULL;
	m_export_directory = NULL;
}

// Default destructor
CExport::~CExport()
{
	//	FreeLibrary(m_hmod_for_renormalize);
	if (m_pe_file)
	{
		delete m_pe_file;
		m_pe_file = NULL;
	}
	if (m_export_directory)
	{
		delete[] m_export_directory;
		m_export_directory = NULL;
	}

	Clean();
}

// Clear all forwards
void CExport::ClearForwards()
{
	m_forwards.clear();
}

// Clean all allocated memory
void CExport::Clean()
{
	if (m_hmod)
	{
		m_hmod = 0;
	}
	
	if (m_table_nameordinals)
	{
		delete[] m_table_nameordinals;
		m_table_nameordinals = 0;
	}
}

// Return the HMODULE of the export
HMODULE CExport::GetHandle()
{
	return (m_hmod);
}

// Create an export from its name
//
// Returned values:
// ----------------
// .	-1 : Can't open the process or can't read it at all
// .	 0 : Module has no export
// .	 1 : All is OK.
// .	 2 : OK partially because we couldn't read the module at all
int CExport::Create(char *lib_name, DWORD pid, DWORD base, DWORD size, DWORD k32_base)
{
	int    ret_val = 1;
	DWORD *ptr_name, i;
	WORD  *ptr_ord;
	Clean();

	m_pe_file = new CPEFile;
	
	// Load library for renormalize it
	//	m_hmod_for_renormalize = LoadLibraryEx(lib_name, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);

	if (strlen(lib_name) >= 12 && stricmp(lib_name+strlen(lib_name)-12, "kernel32.dll") == 0)
	{
		// Old method for loading modules
		m_hmod = LoadLibraryEx(lib_name, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
		m_pe_file->m_buffer = (unsigned char*)k32_base;
		m_pe_file->m_size = size;
		m_pe_file->SetIsModule(true);
		m_pe_file->UpdatePEVars(false);
	}
	else
	{
		// Get the PE infos of the library
		m_hmod = (HMODULE)base;

		m_pe_file->m_buffer = new unsigned char[size];
		m_pe_file->m_size = size;
		m_pe_file->SetIsModule(false);

		HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
		DWORD dwCheckSize;
		if (!handle)
		{
			if (m_pe_file)
			{
				delete m_pe_file;
				m_pe_file = NULL;
			}
			// Can't open the process
			return (-1);
		}
		if (!MyRPM(handle, (LPCVOID)base, (LPVOID)m_pe_file->m_buffer, size, &dwCheckSize))
		{
			if (m_pe_file)
			{
				delete m_pe_file;
				m_pe_file = NULL;
			}
			// Can't read anything!
			return (-1);
		}
		if (dwCheckSize != size)
		{
			m_pe_file->m_size = dwCheckSize;
			// Can't read the whole module
			ret_val = 2;
		}

		m_pe_file->UpdatePEVars(false);
		// VERY IMPORTANT!!!!!!!!!!!
		m_pe_file->m_nt_header->imageBase = base;

		CloseHandle(handle);
	}

	// No export??
	if ( !(m_ptr_exp=(IMAGE_EXPORT_DIRECTORY*)(m_pe_file->m_directories[ExportDataDirectory].RVA)) )
	{
		if (m_pe_file)
		{
			delete m_pe_file;
			m_pe_file = NULL;
		}
		return (0);
	}
	
	m_ptr_exp = (IMAGE_EXPORT_DIRECTORY*)((DWORD)m_ptr_exp+m_pe_file->m_buffer);
	
	// Initialize the ordinal table for all function names
	m_table_nameordinals = new DWORD[m_ptr_exp->NumberOfFunctions];
	memset(m_table_nameordinals, 0, sizeof(DWORD)*m_ptr_exp->NumberOfFunctions);
	
	// Fill the ordinal table with points to function name
	ptr_name = (DWORD*)((DWORD)m_pe_file->m_buffer + (DWORD)m_ptr_exp->AddressOfNames);
	ptr_ord = (WORD*)((DWORD)m_pe_file->m_buffer + (DWORD)m_ptr_exp->AddressOfNameOrdinals);
	
	for (i=0; i<m_ptr_exp->NumberOfNames; i++)
	{
		m_table_nameordinals[*ptr_ord] = (DWORD)m_pe_file->m_buffer + (DWORD)(*((DWORD*)ptr_name));
		ptr_name++;
		ptr_ord++;
	}
	
	strcpy(m_fullpath_libname, lib_name);
	BuildForwards();

	imageBase = m_pe_file->m_nt_header->imageBase;
	imageSize = m_pe_file->m_nt_header->imageSize;
	NumberOfFunctions = m_ptr_exp->NumberOfFunctions;
	Base = m_ptr_exp->Base;
	ExportDirectorySize = m_pe_file->m_directories[ExportDataDirectory].size;

	FillExport();

	// Allocate the Export Directory
	m_export_directory = new BYTE[m_pe_file->m_directories[ExportDataDirectory].size];
	memcpy(m_export_directory, m_pe_file->m_buffer+m_pe_file->m_directories[ExportDataDirectory].RVA,
		   m_pe_file->m_directories[ExportDataDirectory].size);

	if (m_pe_file)
	{
		delete m_pe_file;
		m_pe_file = NULL;
	}

	return (ret_val);
}

// Build the forwards list
BOOL CExport::BuildForwards(/*CExport *exports, int nb_export*/)
{
	// Build forwards if they exist
	int i;
	DWORD *ptr_func;
	ptr_func = (DWORD*)(m_pe_file->m_buffer + (DWORD)m_ptr_exp->AddressOfFunctions);
	
	for (i=0; i<m_ptr_exp->NumberOfFunctions; i++)
	{
		// To detect a forward : the pointed function is in the .edata section
		// (Thanks Matt Pietrek! :-))
		if (*ptr_func >= m_pe_file->m_directories[ExportDataDirectory].RVA &&
			*ptr_func < (m_pe_file->m_directories[ExportDataDirectory].RVA+m_pe_file->m_directories[ExportDataDirectory].size))
		{
			char mod[IMPREC_MAX_CHARS];
			char module_name[IMPREC_MAX_CHARS], *func_name;
			ForwardInfo fi;
			HMODULE hmod;

			fi.original_address = (*ptr_func) - m_pe_file->m_directories[ExportDataDirectory].RVA;

			strcpy(fi.module_name, GetLibName());
			if (m_table_nameordinals[i])
			{
				fi.ordinal = (WORD)(i+m_ptr_exp->Base);
				strcpy(fi.func_name, (char*)(m_table_nameordinals[i]));
			}
			else
			{
				fi.ordinal = (WORD)(i+m_ptr_exp->Base);
				strcpy(fi.func_name, "");
			}
			
			strcpy(module_name, (char*)(m_pe_file->m_buffer + *ptr_func));
			func_name = strchr(module_name, '.');
			if (!func_name)
			{
				//				continue;
				return (FALSE);
			}
			*func_name = '\0';
			func_name++;
			strcpy(mod, module_name);
			strcat(mod, ".dll");
			hmod = LoadLibrary(mod);
			if (!hmod)
			{
				//				continue;
				return (FALSE);
			}
			fi.address = (DWORD)(GetProcAddress(hmod, func_name));
			if (!fi.address)
			{
				//				continue;
				return (FALSE);
			}
			
			m_forwards.push_back(fi);
		}
		ptr_func++;
	}
	
	return (TRUE);
}

// Return the name of the module
char* CExport::GetLibName()
{
	if (m_hmod)
	{
		char *c;
		c = strrchr(m_fullpath_libname, '\\');
		if (c)
		{
			return (c+1);
		}
		c = strrchr(m_fullpath_libname, '/');
		if (c)
		{
			return (c+1);
		}
		return (m_fullpath_libname);
		//		return ((char*)( (DWORD)m_pe_file->m_buffer + (DWORD)m_ptr_exp->Name ));
	}
	
	return (NULL);
}

// Return the full path name of the module
char* CExport::GetFullLibName()
{
	if (m_hmod)
	{
		return (m_fullpath_libname);
	}
	
	return (NULL);
}


// Check if an address belongs to the module
BOOL CExport::CheckInterval(void *address)
{
	DWORD addr = (DWORD)address;
	if (!m_hmod)
	{
		//		MessageBox(0, "Library not loaded", "OK", 0);
		// No library loaded
		return (FALSE);
	}
	
	/*	if (stricmp(GetLibName(), "kernel32.dll") == 0)
	{
	if ( addr<m_pe_file->m_nt_header->imageBase)
	{
	return (FALSE);
	}
	}
	else*/
	{
		if ( addr < imageBase || addr > imageBase + imageSize)
		{
			//		MessageBox(0, "Wrong interval", "OK", 0);
			return (FALSE);
		}
	}
	return (TRUE);
}

// Return the number of export functions of the module
DWORD CExport::GetNumberOfFunction()
{
	if (!m_hmod)
	{
		// No library loaded
		return (0);
	}
	
	return (NumberOfFunctions);
}

// Return the name of a function by its ordinal
BOOL CExport::GetProcNameByIndex(DWORD index, WORD *ordinal, char *buffer,
								 DWORD buffer_length)
{
	if (!m_hmod)
	{
		// No library loaded
		return (FALSE);
	}
	
	if (buffer_length <= 1)
	{
		//		MessageBox(0, "Buffer too small", "OK", 0);
		// Wrong parameters!
		return (FALSE);
	}

	if (index >= m_exports.size())
	{
		return (FALSE);
	}

	*ordinal = m_exports[index].ordinal;
	strncpy(buffer, m_exports[index].func_name, buffer_length);
	return (TRUE);
}

// Reverse of GetProcAddress
BOOL CExport::GetProcName(void *address, char *buffer, DWORD buffer_length, WORD *ordinal,
						  char *module, BOOL do_forward)
{
	DWORD i;
	DWORD addr = (DWORD)address;
	int priority = 0;
	
	if (!CheckInterval(address))
	{
		// No library loaded or false interval
		return (FALSE);
	}
	if (buffer_length <= 1)
	{
		//		MessageBox(0, "Buffer too small", "OK", 0);
		// Wrong parameters!
		return (FALSE);
	}
	
	strcpy(module, GetLibName());
	
	for (i=0; i<m_exports.size(); i++)
	{
		if (m_exports[i].address == addr)
		{
			if (strlen(m_exports[i].func_name) > 0)
			{
				if (priority < 2)
				{
					priority = 2;
					*ordinal = m_exports[i].ordinal;
					strncpy(buffer, m_exports[i].func_name, buffer_length);
				}
			}
			else
			{
				if (priority < 1)
				{
					priority = 1;
					*ordinal = m_exports[i].ordinal;
					strcpy(buffer, "");
				}
			}
		}
	}
	
	if (priority)
	{
		if (do_forward)
		{
			// Check Forwards
			priority = 0;
			for (i=0; i<m_forwards.size(); i++)
			{
				if (addr == m_forwards[i].address)
				{
					strcpy(module, m_forwards[i].module_name);
					if (strlen(m_forwards[i].func_name) > 0)
					{
						if (priority<2)
						{
							strcpy(module, m_forwards[i].module_name);
							*ordinal = m_forwards[i].ordinal;
							priority = 2;
							if ( buffer_length >= (1+strlen(m_forwards[i].func_name)) )
							{
								strcpy(buffer, m_forwards[i].func_name);
							}
							else
							{
								memcpy(buffer, (void*)(m_forwards[i].func_name), buffer_length-1);
								buffer[buffer_length-1] = 0;
							}
						}
					}
					else
					{
						*ordinal = m_forwards[i].ordinal;
						priority = 1;
						strcpy(buffer, "");
					}
				}
			}
		}
		
		return (TRUE);
	}
	
	strcpy(module, "FUCK");
	strcpy(buffer, "");
	return (FALSE);
}

// For testing if a module has API with same function address
void CExport::WriteExport(char *filename)
{
/*	FILE *f;
	char buffer[IMPREC_MAX_CHARS];
	unsigned int i, j;
	DWORD *ptr_func, *ptr_func2, tmp, tmp2;
	WORD ordinal;
	bool *mark = new bool[m_ptr_exp->NumberOfFunctions];
	for (i=0; i<m_ptr_exp->NumberOfFunctions; i++)
	{
		mark[i] = false;
	}
	
	f = fopen(filename, "w");
	
	// Trace all function addresses and find a name if it exists
	ptr_func = (DWORD*)((DWORD)m_pe_file->m_buffer + (DWORD)m_ptr_exp->AddressOfFunctions);
	for (i=0; i<m_ptr_exp->NumberOfFunctions; i++, ptr_func++)
	{
		if (mark[i])
		{
			continue;
		}
		tmp = (DWORD)m_pe_file->m_buffer+*ptr_func;
		buffer[0] = '\0';
		ordinal = (WORD)(i+m_ptr_exp->Base);
		sprintf(buffer+strlen(buffer), "addr:%08X ord:%04X ", tmp, ordinal);
		if (m_table_nameordinals[i])
		{
			sprintf(buffer+strlen(buffer), "name:%s \n", (char*)(m_table_nameordinals[i]));
		}
		else
		{
			strcat(buffer, "- \n");
		}
		fprintf(f, buffer);
		
		for (j=i+1, ptr_func2 = ptr_func+1; j<m_ptr_exp->NumberOfFunctions; j++, ptr_func2++)
		{
			tmp2 = (DWORD)m_pe_file->m_buffer+*ptr_func2;
			if (tmp == tmp2)
			{
				mark[j] = true;
				ordinal = (WORD)(j+m_ptr_exp->Base);
				buffer[0] = '\0';
				sprintf(buffer+strlen(buffer), "addr:%08X ord:%04X ", tmp2, ordinal);
				if (m_table_nameordinals[j])
				{
					sprintf(buffer+strlen(buffer), "name:%s \n", (char*)(m_table_nameordinals[j]));
				}
				else
				{
					strcat(buffer, "- \n");
				}
				
				fprintf(f, buffer);
			}
		}
		
		fprintf(f, "\n");
	}
	
	delete[] mark;
	fclose(f);*/
}

// To get all exports into one vector of <APIInfo>
void CExport::FillExport()
{
	unsigned int i;
	DWORD *ptr_func;
	
	// Trace all function addresses and find a name if it exists
	ptr_func = (DWORD*)((DWORD)m_pe_file->m_buffer + (DWORD)m_ptr_exp->AddressOfFunctions);
	for (i=0; i<m_ptr_exp->NumberOfFunctions; i++, ptr_func++)
	{
		APIInfo ai;

		ai.ordinal = (WORD)(i+m_ptr_exp->Base);
//		ai.address = (DWORD)m_pe_file->m_buffer+*ptr_func;
		ai.address = imageBase+*ptr_func;

		if (m_table_nameordinals[i])
		{
			strcpy(ai.func_name, (char*)(m_table_nameordinals[i]));
		}
		else
		{
			strcpy(ai.func_name, "");
		}

		m_exports.push_back(ai);
	}
}

// Return the nearest export function (for ASProtect for example which does not redirect
// to the start of the export function)
BOOL CExport::GetNearestProcName(void *address, char *buffer, DWORD buffer_length,
								 WORD *ordinal, char *module, BOOL do_forward)
{
	BOOL found = false;
	DWORD addr = (DWORD)address, i, min, min_address = 0;
	
	if (!CheckInterval(address))
	{
		// No library loaded or false interval
		return (FALSE);
	}
	
	if (buffer_length <= 1)
	{
		//		MessageBox(0, "Buffer too small", "OK", 0);
		// Wrong parameters!
		return (FALSE);
	}
	
	strcpy(module, GetLibName());
	/*		if (stricmp(GetLibName(), "indicdll.dll") == 0)
	{
	int a;
	a = 0;
	MessageBox(NULL, "OH!", "MERDE", 0);
}*/
	
	for (i=0; i<m_exports.size(); i++)
	{
		if (addr >= m_exports[i].address && m_exports[i].address > min_address)
		{
			found = true;
			min = i;
			min_address = m_exports[i].address;
		}
	}
	
	if (found)
	{
		*ordinal = m_exports[min].ordinal;
		strncpy(buffer, m_exports[min].func_name, buffer_length);
		
		if (do_forward)
		{
			// Check Forwards
			int priority = 0;
			for (i=0; i<m_forwards.size(); i++)
			{
				if (min_address == m_forwards[i].address)
				{
					strcpy(module, m_forwards[i].module_name);
					if (strlen(m_forwards[i].func_name) > 0)
					{
						if (priority<2)
						{
							*ordinal = m_forwards[i].ordinal;
							priority = 2;
							if ( buffer_length >= (1+strlen(m_forwards[i].func_name)) )
							{
								strcpy(buffer, m_forwards[i].func_name);
							}
							else
							{
								memcpy(buffer, (void*)(m_forwards[i].func_name), buffer_length-1);
								buffer[buffer_length-1] = 0;
							}
						}
					}
					else
					{
						*ordinal = m_forwards[i].ordinal;
						priority = 1;
						strcpy(buffer, "");
					}
				}
			}
		}
		return (TRUE);
	}
	
	strcpy(module, "FUCK");
	strcpy(buffer, "");
	return (FALSE);
}

// Return the Base of all Ordinals
DWORD CExport::GetBase()
{
	return (Base);
}

// Our GetProcAddress for managing K32 ordinal exports
FARPROC CExport::GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	if (hModule != GetModuleHandle("kernel32.dll") || ((DWORD)lpProcName & 0xFFFF0000))
	{
		return (::GetProcAddress(hModule, lpProcName));
	}

	DWORD ret_val;
	DWORD hModule2 = (DWORD)hModule;
	DWORD lpProcName2 = (DWORD)lpProcName;
	
	__asm
	{
		;北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北
		; Load Address by Ordinal
		;北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北北
		
		;鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍
		;esp+4 : Handle Library
		;esp+8 : Ordinal value (80000000+XXXXXXXXh).
		;
		;eax=0 on failure.
		;鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍鞍
		push 	esi
		push	edi
		push 	ebx
		push 	ecx
		push 	edx

		mov	esi, lpProcName2			// OrdValue
//		sub	esi, 80000000h
		mov	eax, hModule2				// hmod

		lea	ecx, [eax+0x3C]				// offset which points to the 'PE'
		mov ecx, [ecx]
		add	ecx, eax
		mov	edx, ecx
		cmp	dword ptr[edx], 0x00004550	// DWORD 'PE'
		jnz	short NotOK

		mov edi, [edx+0x78]				// Directories (first = export RVA)
		lea	ecx, [edi+eax]				// Move to Export table.

		mov	edi, [ecx+0x1C]
		lea	edx, [edi+eax]

		sub	esi, [ecx+0x10]				// Sub ordinal base

		mov	ecx, [ecx+0x14]				// Number of exports

		cmp	ecx, esi
		jbe	short NotOK
		mov ebx, [edx+esi*4]
		add	eax, [edx+esi*4]

		jmp	short AllOK

NotOK:
		xor	eax, eax
AllOK:
		pop 	edx
		pop 	ecx
		pop 	ebx
		pop 	edi
		pop 	esi

		mov ret_val, eax;
	}
	
	return ((FARPROC)ret_val);
}

// Check if the module forwards a function from another module
BOOL CExport::GetForward(char *mod, char *name, char *buffer, DWORD buffer_length,
						 WORD *ordinal)
{
	if (!name)
	{
		return (FALSE);
	}

	char mod2[IMPREC_MAX_CHARS];
	unsigned int i, j;
	char *str;
	DWORD limit = (DWORD)m_export_directory+ExportDirectorySize;
	strcpy(mod2, mod);
	str = strrchr(mod2, '.');
	if (str)
	{
		*str = '\0';
	}
	
	if (buffer_length <= 1)
	{
		//		MessageBox(0, "Buffer too small", "OK", 0);
		// Wrong parameters!
		return (FALSE);
	}
	
	limit -= strlen(name);
	
	// Trace all function addresses and find a name if it exists
	for (i=0; i<m_forwards.size(); i++)
	{
		str = (char*)(m_export_directory+m_forwards[i].original_address);
		j = 0;
		mod = mod2;
		while ((DWORD)str < (DWORD)limit)
		{
			char a, b;
			if (*str >= 'a' && *str <= 'z')
			{
				a = *str - ('a'-'A');
			}
			else
			{
				a = *str;
			}
			
			if (*mod >= 'a' && *mod <= 'z')
			{
				b = *mod - ('a'-'A');
			}
			else
			{
				b = *mod;
			}
			
			if (a != b)
			{
				break;
			}
			
			j++;
			str++;
			mod++;
		}
		
		if (j >= strlen(mod) && *str == '.' &&
			stricmp(str+1, name) == 0)
		{
			*ordinal = m_forwards[i].ordinal;
			strncpy(buffer, m_forwards[i].func_name, buffer_length);
			return (TRUE);
		}
	}
	
	return (FALSE);
}
