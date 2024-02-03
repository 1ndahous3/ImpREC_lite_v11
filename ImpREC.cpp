// Import REConstructor DLL v1.01 (C) 2001 MackT/uCF
///////////////////////////////////////////////////////////////////////
// Main class for rebuilding import
///////////////////////////////////////////////////////////////////////
// You're allowed to use parts of this code if you mention my name.
///////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ImpREC.h"

// Constructor
CImpREC::CImpREC()
{
}

// Destructor
CImpREC::~CImpREC() 
{
	if (m_exports)
	{
		delete[] m_exports;
		m_exports = 0;
	}
}

// Initialize all what we need
BOOL CImpREC::Init()
{
	if (!InitAPIs())
		return FALSE;
	m_exports = 0;

	// Get the old editbox proc for replacing the new one
	m_importbyordinal = false;
	m_newsection = true;

	m_imports.DeleteAll();
	m_proc_mods.clear();
	m_proc_hmods.clear();
	m_proc_szmods.clear();

	// Delete the buffer which will contain the pe_header of the target
//	m_pe_header.SetIsModule(false);
	return (TRUE);  // return TRUE  unless you set the focus to a control
}

DWORD CImpREC::LoadProcess(DWORD pid, DWORD base)
{
	unsigned int ii, ret_val;
	int  i, j;
	bool module_found = false;

	char string[256];

	m_pid = pid;		// Get the PID

	MODULEENTRY32 module;
	module.dwSize=sizeof(MODULEENTRY32);
	HANDLE snap;

	// Now list all associated modules
	if (m_nt_os)
	{
		HMODULE hMods[1024];
		HANDLE hProcess;
		DWORD cbNeeded;

		// Get a list of all the modules in this process.
		hProcess = OpenProcess(  PROCESS_QUERY_INFORMATION |
										PROCESS_VM_READ,
										FALSE, m_pid );

		if (!hProcess)
		{
//				MessageBox("Can't open this process!", "OpenProcess Error");
			return (IREC_PROCESS_ERROR);
		}

		if (MyEnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			for (ii=0; ii<(cbNeeded / sizeof(HMODULE)); ii++)
			{
				char szModName[IMPREC_MAX_CHARS];

				// Get the full path to the module's file.
				if (MyGetModuleFileNameEx(hProcess, hMods[ii], szModName, sizeof(szModName)))
				{
					// Get the full infos of the module
					MODULEINFO mod_info;
					MyGetModuleInformation(hProcess, hMods[ii], &mod_info, sizeof(MODULEINFO));

					// Keep K32 Base
					if (!m_k32_base && strlen(szModName) >= 12 &&
						stricmp(szModName+strlen(szModName)-12, "kernel32.dll") == 0)
					{
						m_k32_base = (DWORD)(mod_info.lpBaseOfDll);
						m_k32_size = (DWORD)(mod_info.SizeOfImage);
					}

					strcpy(string, szModName);
					CharLower(string);

					m_proc_mods.push_back(string);
					m_proc_hmods.push_back((DWORD)(mod_info.lpBaseOfDll));
					m_proc_szmods.push_back((DWORD)(mod_info.SizeOfImage));

					if ((DWORD)(mod_info.lpBaseOfDll) == base)
					{
						m_imgbase = base;
						module_found = true;
					}
				}
			}
		}
		CloseHandle( hProcess );
	}
	else
	{
		snap = MyCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_pid);
		if (!snap)
		{
//				MessageBox("Can't take a snapshot of the module!", "THelp32 Error");
			return (IREC_PROCESS_ERROR);
		}

		// Read First Module
		if (MyModule32First(snap,&module))
		{
			// Keep K32 Base
			if (!m_k32_base && strlen(module.szExePath) >= 12 &&
				stricmp(module.szExePath+strlen(module.szExePath)-12, "kernel32.dll") == 0)
			{
				m_k32_base = (DWORD)(module.modBaseAddr);
				m_k32_size = (DWORD)(module.modBaseSize);
			}

			strcpy(string, module.szExePath);
			CharLower(string);

			{
				char mackt[IMPREC_MAX_CHARS];
				strcpy(mackt, string);
				m_proc_mods.push_back(mackt);
				m_proc_hmods.push_back((DWORD)(module.modBaseAddr));
				m_proc_szmods.push_back((DWORD)(module.modBaseSize));
			}

			if ((DWORD)(module.modBaseAddr) == base)
			{
				m_imgbase = base;
				module_found = true;
			}

			// Loop on next Module
			while (MyModule32Next(snap,&module))
			{
				// Keep K32 Base
				if (!m_k32_base && strlen(module.szExePath) >= 12 &&
					stricmp(module.szExePath+strlen(module.szExePath)-12, "kernel32.dll") == 0)
				{
					m_k32_base = (DWORD)(module.modBaseAddr);
					m_k32_size = (DWORD)(module.modBaseSize);
				}

				strcpy(string, module.szExePath);
				CharLower(string);

				{
					char mackt[IMPREC_MAX_CHARS];
					strcpy(mackt, string);
					m_proc_mods.push_back(mackt);
					m_proc_hmods.push_back((DWORD)(module.modBaseAddr));
					m_proc_szmods.push_back((DWORD)(module.modBaseSize));
				}

				if ((DWORD)(module.modBaseAddr) == base)
				{
					m_imgbase = base;
					module_found = true;
				}
			}
		}

		CloseHandle(snap);
	}

	if (!module_found)
	{
//			MessageBox("This module can't be selected!", "Invalid module");
		return (IREC_MODULE_NOT_FOUND_ERROR);
	}

	// Build all attached exports
	CExport::ClearForwards();
	j = 0;
	m_nb_exports = m_proc_mods.size();
	m_exports = new CExport[m_nb_exports];
	for (i=0; i<m_nb_exports; i++)
	{
		ret_val = m_exports[j].Create( (char*)(m_proc_mods[i].c_str()),m_pid,
									   m_proc_hmods[i], m_proc_szmods[i], m_k32_base );
		switch (ret_val)
		{
/*			case -1:
			sprintf(garbage, "* Cannot load module: %s", (char*)(m_proc_mods[i].c_str()));
			AddLog(garbage);
			break;
		case 0:
			sprintf(garbage, "* No export for module: %s", (char*)(m_proc_mods[i].c_str()));
			AddLog(garbage);
			break;*/
		case 1:
//				sprintf(garbage, "Module loaded: %s", (char*)(m_proc_mods[i].c_str()));
//				AddLog(garbage);
//				j++;
//				break;
		case 2:
//				sprintf(garbage, "Module loaded... : %s", (char*)(m_proc_mods[i].c_str()));
//				AddLog(garbage);
			j++;
			break;
		}
	}
	m_nb_exports = j;
//		AddLog("Getting associated modules done.");

	// Build forwards
//		AddLog("Building all forwards of all modules...");
//		for (i=0; i<m_nb_exports; i++)
//		{
//			if (!m_exports[i].BuildForwards(/*m_exports, m_nb_exports*/))
//			{
//				MessageBox("Can't build its forwards!", m_exports[i].GetLibName());
//			}
//		}
//		AddLog("All forwards are done.");

/*		// Write some last infos
	sprintf(buffer, "Image Base:%08X Size:%08X", m_imgbase, m_imgsize);
	AddLog(buffer);
	sprintf(buffer, "%08X", m_pe_header.m_nt_header->entryPoint);
	SetDlgItemText(IDC_OEP, buffer);
	UpdateData(FALSE);
//		m_limitend = GetProcHeapSize();
	m_limitend = 0xFFFFFFFF;			// DEBUG

	SendDlgItemMessage(IDC_OEP, WM_ENABLE, (WPARAM)TRUE, (LPARAM)0);
	SendDlgItemMessage(IDC_IAT_RVA, WM_ENABLE, (WPARAM)TRUE, (LPARAM)0);
	SendDlgItemMessage(IDC_IAT_SIZE, WM_ENABLE, (WPARAM)TRUE, (LPARAM)0);
	m_myLoadTree.EnableWindow(TRUE);
	m_mySaveTree.EnableWindow(TRUE);
	m_myGo.EnableWindow(TRUE);
	m_myAuto.EnableWindow(TRUE);
	m_myFixDump.EnableWindow(TRUE);
	m_myCheckAddSection.EnableWindow(TRUE);

	m_myClearImp.EnableWindow(TRUE);
	m_myShowInvalid.EnableWindow(TRUE);
	m_myShowSuspect.EnableWindow(TRUE);
	m_myPicDLL.EnableWindow(TRUE);
	m_myAutoTrace.EnableWindow(TRUE);*/

	return (IREC_ALL_OK);
}

// Init all needed API for playing with processes and modules
BOOL CImpREC::InitAPIs()
{
	// Try to load "PSAPI.DLL" if possible for NT/2000 OS
	m_psapi_hmod = LoadLibrary("psapi.dll");

	if (m_psapi_hmod)
	{
		MyEnumProcesses = (FUNC_NT1)GetProcAddress(m_psapi_hmod, "EnumProcesses");
		if (!MyEnumProcesses)
			goto W9xOS;
		MyEnumProcessModules = (FUNC_NT2)GetProcAddress(m_psapi_hmod, "EnumProcessModules");
		if (!MyEnumProcessModules)
			goto W9xOS;
		MyGetModuleInformation = (FUNC_NT3)GetProcAddress(m_psapi_hmod, "GetModuleInformation");
		if (!MyGetModuleInformation)
			goto W9xOS;
		MyGetModuleFileNameEx = (FUNC_NT4)GetProcAddress(m_psapi_hmod, "GetModuleFileNameExA");
		if (!MyGetModuleFileNameEx)
			goto W9xOS;
		MyGetProcessMemoryInfo = (FUNC_NT5)GetProcAddress(m_psapi_hmod, "GetProcessMemoryInfo");
		if (!MyGetProcessMemoryInfo)
			goto W9xOS;

		m_nt_os = true;
		return (TRUE);
	}

W9xOS:
	// else try "TOOLHELP32"
	HMODULE hmod;
	hmod = LoadLibrary("kernel32.dll");
	if (hmod)
	{
		MyCreateToolhelp32Snapshot = (FUNC1)GetProcAddress(hmod, "CreateToolhelp32Snapshot");
		if (!MyCreateToolhelp32Snapshot)
		{
			goto ERROR_OS;
		}
		MyProcess32First = (FUNC2)GetProcAddress(hmod, "Process32First");
		if (!MyProcess32First)
		{
			goto ERROR_OS;
		}
		MyProcess32Next = (FUNC2)GetProcAddress(hmod, "Process32Next");
		if (!MyProcess32Next)
		{
			goto ERROR_OS;
		}
		MyModule32First = (FUNC3)GetProcAddress(hmod, "Module32First");
		if (!MyModule32First)
		{
			goto ERROR_OS;
		}
		MyModule32Next = (FUNC3)GetProcAddress(hmod, "Module32Next");
		if (!MyModule32Next)
		{
			goto ERROR_OS;
		}
		MyHeap32ListFirst = (FUNC4)GetProcAddress(hmod, "Heap32ListFirst");
		if (!MyHeap32ListFirst)
		{
			goto ERROR_OS;
		}
		MyHeap32ListNext = (FUNC4)GetProcAddress(hmod, "Heap32ListNext");
		if (!MyHeap32ListNext)
		{
			goto ERROR_OS;
		}
		MyHeap32First = (FUNC5)GetProcAddress(hmod, "Heap32First");
		if (!MyHeap32First)
		{
			goto ERROR_OS;
		}
		MyHeap32Next = (FUNC6)GetProcAddress(hmod, "Heap32Next");
		if (!MyHeap32Next)
		{
			goto ERROR_OS;
		}

		// Toolhelp32 API'S library loaded successfully
		FreeLibrary(hmod);
		m_nt_os = false;
		return (TRUE);
	}

ERROR_OS:
	// Impressive error!!! Hehe :-)
	return (FALSE);
}

void CImpREC::UltraArrange() 
{
	ImpModuleList modlist = m_imports.GetModel();
	ImpModuleList::iterator my_iterator1 = modlist.begin();
	ImpThunkList::iterator my_iterator2;

	while (my_iterator1 != modlist.end())
	{
		// We have an invalid module => Kill it!
		if ( !((*my_iterator1).second).valid )
		{
			m_imports.DeleteModule(((*my_iterator1).second).first_thunk);
		}

		my_iterator1++;
	}
}

// Add an import function
BOOL CImpREC::AddImp(DWORD rva, char *mod_name, WORD ordinal, char *proc_name,
								 bool valid/* = true */, bool force/* = false */)
{
	DWORD item = 0;
	return (m_imports.AddFunction(mod_name, rva, ordinal, proc_name, (void**)&item, valid, force));
}

// Check, modify and validate import
void CImpREC::ValidateImport()
{
	ImpModuleList modlist;
	ImpModuleList::iterator my_iterator1;
	ImpThunkList::iterator my_iterator2;
	bool  first_output = true;
	DWORD old_rva = 0;
	DWORD old_ord;
	char  *old_str_mod = NULL;
	char  *old_proc_name = NULL;
	int   i;
	int   invalid = 0, first_invalid = -1;

	// We are going to cut forward
	modlist = m_imports.GetModel();
	my_iterator1 = modlist.begin();
	while (my_iterator1 != modlist.end())
	{
		if ( !((*my_iterator1).second).valid )
		{
			for (i=0, my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
				 my_iterator2 != ((*my_iterator1).second).thunk_list.end();)
			{
				// The function is invalid
				if ( !((*my_iterator2).second).valid )
				{
					// If the 2 modules are not the same and the rva's follow themselves
					// => Incorrect IAT!!
					if (i!=0 &&
						stricmp(old_str_mod, ((*my_iterator2).second).module_name)!=0 &&
						((*my_iterator2).second).rva==old_rva+4)
					{
						invalid++;
						if (first_invalid == -1)
						{
							first_invalid = i;
						}
					}

					old_rva = ((*my_iterator2).second).rva;
					old_str_mod = ((*my_iterator2).second).module_name;
					old_proc_name = NULL;

					i++;
					my_iterator2++;
					continue;
				}

				// The function is valid
				// If the 2 modules are not the same and the rva's follow themselves
				// => Incorrect IAT!!
				if (i!=0 &&
					stricmp(old_str_mod, ((*my_iterator2).second).module_name)!=0 &&
					((*my_iterator2).second).rva==old_rva+4)
				{
					invalid++;
					if (first_invalid == -1)
					{
						first_invalid = i;
					}
				}

				if (i!=0 && strlen(old_str_mod)>0)
				{
					if (stricmp(old_str_mod, ((*my_iterator2).second).module_name)!=0)

					// If the 2 modules are not the same and the rva's follow themselves
					// => Incorrect IAT!!
					if (stricmp(old_str_mod, ((*my_iterator2).second).module_name)!=0 &&
						((*my_iterator2).second).rva==old_rva+4 &&
						strlen(((*my_iterator2).second).name)>0)
					{
						// Try to solve the pb by checking forward pointers
						int j, ind = -1, old_ind = -1;

						// Get both index of each modules
						for (j=0; j<m_nb_exports; j++)
						{
							if (stricmp(((*my_iterator2).second).module_name,
								m_exports[j].GetLibName()) == 0)
							{
								ind = j;
								break;
							}
						}
						if (ind >= 0)
						{
							for (j=0; j<m_nb_exports; j++)
							{
								if (stricmp(old_str_mod, m_exports[j].GetLibName()) == 0)
								{
									old_ind = j;
									break;
								}
							}
							if (old_ind >= 0)
							{
								char new_proc_name[IMPREC_MAX_CHARS];
								WORD new_ord;

								// Look at forward exports
								if (m_exports[old_ind].GetForward(((*my_iterator2).second).module_name,
									((*my_iterator2).second).name,
									new_proc_name, IMPREC_MAX_CHARS, &new_ord))
								{
									AddImp(((*my_iterator2).second).rva,
										m_exports[old_ind].GetLibName(),
										new_ord, new_proc_name, true, true);

/*									char str[IMPREC_MAX_CHARS];
									sprintf(str, "rva:%08X mod:%s ord:%04X name:%s",
										((*my_iterator2).second).rva, m_exports[old_ind].GetLibName(), new_ord, new_proc_name);
									HTREEITEM item = (HTREEITEM)(m_imports.GetFunctionView(((*my_iterator2).second).rva));
									m_myImpTree.SetItemText(item, str);*/

									if (first_output)
									{
										first_output = false;
									}
/*									sprintf(tmp, "Forward -> rva:%08X mod:%s ord:%04X name:%s",
											((*my_iterator2).second).rva, m_exports[old_ind].GetLibName(),
											new_ord, new_proc_name);*/
/*									sprintf(tmp, "rva:%08X forwarded from mod:%s ord:%04X name:%s",
											((*my_iterator2).second).rva, m_exports[ind].GetLibName(),
											old_ord, ((*my_iterator2).second).name);
									AddLog(tmp);*/
									invalid--;

									modlist = m_imports.GetModel();
									my_iterator1 = modlist.begin();
									i=0;
									my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
									continue;
								}

								if (m_exports[ind].GetForward(old_str_mod, old_proc_name,
									new_proc_name, IMPREC_MAX_CHARS, &new_ord))
								{
									AddImp(old_rva, m_exports[ind].GetLibName(), new_ord, new_proc_name, true, true);

/*									char str[IMPREC_MAX_CHARS];
									sprintf(str, "rva:%08X mod:%s ord:%04X name:%s",
										old_rva, m_exports[ind].GetLibName(), new_ord, new_proc_name);
									HTREEITEM item = (HTREEITEM)(m_imports.GetFunctionView(old_rva));
									m_myImpTree.SetItemText(item, str);*/

									if (first_output)
									{
										first_output = false;
									}
/*									sprintf(tmp, "Forward -> rva:%08X mod:%s ord:%04X name:%s",
											old_rva, m_exports[ind].GetLibName(),
											new_ord, new_proc_name);*/
/*									sprintf(tmp, "rva:%08X forwarded from mod:%s ord:%04X name:%s",
											((*my_iterator2).second).rva, m_exports[old_ind].GetLibName(),
											old_ord, ((*my_iterator2).second).name);
									AddLog(tmp);*/
									invalid--;

									modlist = m_imports.GetModel();
									my_iterator1 = modlist.begin();
									i=0;
									my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
									continue;
								}

								// If we're here, the IAT can't be solve by forwarding export functions
								///////////////////////////////////////////////////////////////////////

							}			// if (old_ind >= 0)
						}				// if (ind >= 0)

					}
				}

				old_rva = ((*my_iterator2).second).rva;
				old_ord = ((*my_iterator2).second).ordinal;
				old_proc_name = ((*my_iterator2).second).name;
				old_str_mod = ((*my_iterator2).second).module_name;
				i++;
				my_iterator2++;
			}
		}

		my_iterator1++;
	}
	
	// We are going to update module name of each thunks
	modlist = m_imports.GetModel();
	my_iterator1 = modlist.begin();
	while (my_iterator1 != modlist.end())
	{
		first_output = true;
		old_str_mod = NULL;
		my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
		while (my_iterator2 != ((*my_iterator1).second).thunk_list.end())
		{
			if ( !((*my_iterator2).second).valid ||
				(old_str_mod &&
				stricmp( old_str_mod, ((*my_iterator2).second).module_name) != 0) )
			{
				first_output = false;
				break;
			}
			old_str_mod = ((*my_iterator2).second).module_name;
			my_iterator2++;
		}

		((*my_iterator1).second).valid = first_output;
		m_imports.SetModuleValidity(((*my_iterator1).second).first_thunk, first_output);
		if (first_output && old_str_mod)
		{
			m_imports.SetModuleName(((*my_iterator1).second).first_thunk, old_str_mod);
			strcpy(((*my_iterator1).second).name, old_str_mod);
		}

/*		sprintf(tmp, "%s FThunk:%08X NbFunc:%X (decimal:%d) valid:",
			((*my_iterator1).second).name, ((*my_iterator1).second).first_thunk,
			((*my_iterator1).second).nb_thunks, ((*my_iterator1).second).nb_thunks);
		if (((*my_iterator1).second).valid)
		{
			strcat(tmp, "YES");
		}
		else
		{
			strcat(tmp, "NO");
		}
		if (((*my_iterator1).second).relative)
		{
			strcat(tmp, " - (R)");
		}
		if (((*my_iterator1).second).loader)
		{
			strcat(tmp, " - *LOADER*");
		}
		m_myImpTree.SetItemText( (HTREEITEM)(((*my_iterator1).second).view), tmp );*/

		my_iterator1++;
	}
}

// Returns the size of the new import datas by simulating its reconstruction
//
// Need to optimize that!!!!!!!!!!!!!!!!!! (HARD...)
DWORD CImpREC::GetImportSize()
{
	int nb_mod, iid_nb_mod, rest;
	int nb, nb_wrong, real_wrong;
	DWORD section_rva, iid_rva, ascii_rva, iid_offset, ascii_offset;
	DWORD old_iid_offset, old_iid_rva;
	DWORD total_length, iid_length;
	DWORD iat_rva;

	ImpModuleList modlist;
	ImpModuleList::iterator my_iterator1;
	ImpThunkList::iterator my_iterator2;

	// Get some stats
	nb_mod = 0;
	nb = 0;
	nb_wrong = 0;
	real_wrong = 0;
	iid_nb_mod = 0;
	modlist = m_imports.GetModel();
	my_iterator1 = modlist.begin();

	while (my_iterator1 != modlist.end())
	{
		if ( !(((*my_iterator1).second).valid) )
		{
			my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
			while (my_iterator2 != ((*my_iterator1).second).thunk_list.end())
			{
				if ( !((*my_iterator2).second).valid)
				{
					nb_wrong++;
					real_wrong++;
				}

				nb++;
				my_iterator2++;
			}
		}
		else
		{
			nb += ((*my_iterator1).second).nb_thunks;
		}

		nb_mod++;
		my_iterator1++;
	}

	if (nb_mod == 0)
	{
		return (0);
	}


	iid_rva = 0;

	iid_offset = 0;

	section_rva = iid_rva;
	// Precompute size of IID
	iid_length = iid_nb_mod*(5*4); // <- 5*4 = size of one struct IID (4 DWORDS)
	// Do not forget to add the blank (4 NULL DWORDS) in the IID
	total_length = iid_length + (5*4);
	ascii_rva = iid_rva + iid_length + (5*4);
	ascii_offset = iid_offset + iid_length + (5*4);

	old_iid_rva = iid_rva;
	old_iid_offset = iid_offset;

	// Fill import from our tree
	my_iterator1 = modlist.begin();
	while (my_iterator1 != modlist.end())
	{
		{
			if (((*my_iterator1).second).valid)
			{
				// Fill the IID
				// OriginalFirstThunk
				iid_rva += 4;
				iid_offset += 4;
				// TimeDateStamp
				iid_rva += 4;
				iid_offset += 4;
				// ForwarderChain
				iid_rva += 4;
				iid_offset += 4;
				// Name of the DLL
				iid_rva += 4;
				iid_offset += 4;
				// First Thunk
				iid_rva += 4;
				iid_offset += 4;

				// Copy the module name
				ascii_rva += strlen(((*my_iterator1).second).name)+1;
				ascii_offset += strlen(((*my_iterator1).second).name)+1;
				total_length += strlen(((*my_iterator1).second).name)+1;

				// Alignment
				rest = total_length%2;
				if (rest)
				{
					rest = 2-rest;
					ascii_rva += rest;
					ascii_offset += rest;
					total_length += rest;
				}

				my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
				while (my_iterator2 != ((*my_iterator1).second).thunk_list.end())
				{
					iat_rva = ((*my_iterator2).second).rva;

					// Import by function name
					if (!m_importbyordinal && strlen(((*my_iterator2).second).name) > 0)
					{
						// Point the IAT function pointer to this string

						// Fill the ASCII function name

						// Hint (1 short = ordinal)
						ascii_rva += 2;
						ascii_offset += 2;
						// Copy the function name
						ascii_rva += strlen(((*my_iterator2).second).name)+1;
						ascii_offset += strlen(((*my_iterator2).second).name)+1;
						total_length += strlen(((*my_iterator2).second).name)+1+2;

						// Alignment
						rest = total_length%2;
						if (rest)
						{
							rest = 2-rest;
							ascii_rva += rest;
							ascii_offset += rest;
							total_length += rest;
						}
					}
					// Import by ordinal
					else
					{
						// Fill the IAT function with the ordinal followed by 0x8000
					}

					my_iterator2++;
				}

			}
		}

		my_iterator1++;
	}

	// Finish the IID and update IID size
	iid_rva += 4;
	iid_offset += 4;
	iid_rva += 4;
	iid_offset += 4;
	iid_rva += 4;
	iid_offset += 4;
	iid_rva += 4;
	iid_offset += 4;
	iid_rva += 4;
	iid_offset += 4;

	return (total_length);
}

// Fix a dumped file
DWORD CImpREC::FixDump(LPTSTR dump_filename) 
{
	CPEFile pe_file;
//	char buffer[IMPREC_MAX_CHARS];
//	char tmp[IMPREC_MAX_CHARS];
	char ext[5];
	int nb_mod, iid_nb_mod, rest;
	int nb, nb_wrong, real_wrong;
//	bool first_thunk;
	DWORD section_rva, offset, old_offset, iid_rva, ascii_rva, iid_offset, ascii_offset;
	DWORD old_iid_offset, old_iid_rva;
//	DWORD data_rva, old_data_offset, data_offset, data_mod_name_rva;
	DWORD total_length, iid_length;
	DWORD iat_rva = 0;
	DWORD /*oep,*/ import_size;
	bool  browse_dump = false;

	// Vector for keeping in memory, all import addresses to fix by the loader
	std::vector<LoaderImport> loader_imports;

	ImpModuleList modlist;
	ImpModuleList::iterator my_iterator1;
	ImpThunkList::iterator my_iterator2;

	// Before doing anything, validate all imports
	ValidateImport();

	// Get the size of the import
	import_size = GetImportSize();

	// Get some stats
	nb_mod = 0;
	nb = 0;
	nb_wrong = 0;
	real_wrong = 0;
	iid_nb_mod = 0;
	modlist = m_imports.GetModel();
	my_iterator1 = modlist.begin();
	while (my_iterator1 != modlist.end())
	{
		if ( !(((*my_iterator1).second).valid) )
		{
			my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
			while (my_iterator2 != ((*my_iterator1).second).thunk_list.end())
			{
				if ( !((*my_iterator2).second).valid)
				{
					nb_wrong++;
					real_wrong++;
				}
				else
				{
					// Get the first RVA of the IAT
					if (!iat_rva)
					{
						iat_rva = ((*my_iterator2).second).rva;
					}
				}

				nb++;
				my_iterator2++;
			}
		}
		else
		{
			// Get the first RVA of the IAT
			my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
			if (my_iterator2 != ((*my_iterator1).second).thunk_list.end() && !iat_rva)
			{
				iat_rva = ((*my_iterator2).second).rva;
			}

			nb += ((*my_iterator1).second).nb_thunks;
		}

		// Count this module only if it's not in the loader
		iid_nb_mod++;
		nb_mod++;
		my_iterator1++;
	}

	if (nb_mod == 0)
	{
		return (IREC_NO_MODULE_ERROR);
	}

/*	// Show numbers of modules
	AddLog("---------------------------------------------------------------------------------------------------------------------------");
	AddLog("Fixing a dumped file...");
	sprintf(tmp, "%X (decimal:%d) module(s)", nb_mod, nb_mod);
	AddLog(tmp);
	// Show numbers of imported functions
	sprintf(buffer, "%X (decimal:%d) imported function(s).", nb, nb);
	AddLog(buffer);
	if (nb_wrong > 0)
	{
		sprintf(buffer, "(%X (decimal:%d) unresolved pointer(s))", nb_wrong, nb_wrong);
		AddLog(buffer);
	}*/

	// Get the RVA to put the Image Import Descriptor if no section will be added
/*	if (!m_newsection)
	{
		GetDlgItemText(IDC_IID_RVA, tmp, IMPREC_MAX_CHARS);
		sscanf(tmp, "%X", &iid_rva);

		// Correct parity value of address
		if (iid_rva%2)
		{
			iid_rva++;
			sprintf(tmp, "%08X", iid_rva);
			SetDlgItemText(IDC_IID_RVA, tmp);
			UpdateData(FALSE);
			MessageBox("RVA of new import must be pair. It was automatically fixed", "Note!");
		}
	}*/

//fixing_start:					// Use it to reask valid values for the loader

	// Load the Dumped file
//	if (browse_dump || BrowseDump())
	{
		if (!pe_file.LoadExecutable(dump_filename))
		{
/*			RemoveTempExactCalls();
			sprintf(tmp, "Can't load %s", m_dump_filename);
			AddLog(tmp);*/
			return (IREC_PE_ERROR);
		}
//		browse_dump = true;
	}
/*	else
	{
		RemoveTempExactCalls();
		AddLog("No dump file?");
		return;
	}*/

	// DO NOT FORGET TO FIX the section characteristics of the .rdata section to WRITEABLE
	int iat_index = pe_file.FindSectionIndex(iat_rva);
	if (iat_index >= 0)
	{
		pe_file.m_sections[iat_index].flags |= 0x80000000;
	}

	//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	// Add a new section?
	//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	if (m_newsection/* || m_makeloader*/)
	{
		DWORD new_sz;
		if (pe_file.AddSection(".idata",
							   import_size/*+layers.GetSize()*/,
							   &iid_rva, &new_sz, 0xE0000060))
		{
//			sprintf(tmp, "*** New section added successfully. RVA:%08X SIZE:%08X", iid_rva, new_sz);
//			AddLog(tmp);

			// Do not forget to fix the Image Size
			pe_file.m_nt_header->imageSize = iid_rva + new_sz;
		}
		else
		{
/*			RemoveTempExactCalls();
			AddLog("Failed to add a new section :-(.");*/
			return (IREC_ADD_SECTION_ERROR);
		}
	}

	{
		total_length = 0;
	}

	// Check bounds
	if (!pe_file.RVA2Offset(iid_rva, &iid_offset))
	{
/*		RemoveTempExactCalls();
		AddLog("Invalid RVA for new import, nothing done.");
		MessageBox("Invalid RVA, it does not match a section", "Image Import Descriptor Problem");*/
		return (IREC_RVA2OFFSET_ERROR);
	}

	section_rva = iid_rva;
	// Precompute size of IID
	iid_length = iid_nb_mod*(5*4); // <- 5*4 = size of one struct IID (4 DWORDS)
	// Do not forget to add the blank (4 NULL DWORDS) in the IID
	total_length += iid_length + (5*4);
	ascii_rva = iid_rva + iid_length + (5*4);
	ascii_offset = iid_offset + iid_length + (5*4);

	// Invalid new import RVA
	if (iid_offset >= (DWORD)(pe_file.m_size))
	{
/*		RemoveTempExactCalls();
		AddLog("Invalid RVA, nothing done.");
		MessageBox("Can't put the whole new import datas. Please find antoher RVA", "Image Import Descriptor Problem");*/
		return (IREC_INVALID_OFFSET_ERROR);
	}
	if (ascii_offset >= (DWORD)(pe_file.m_size))
	{
/*		RemoveTempExactCalls();
		AddLog("Not enough space to put new import datas, nothing done.");
		MessageBox("Not enough space to put new import datas!", "Ascii Problem");*/
		return (IREC_INVALID_OFFSET_ERROR);
	}

/*	// Get the oep
	GetDlgItemText(IDC_OEP, buffer, IMPREC_MAX_CHARS);
	sscanf(buffer, "%X", &oep);

	// Fix the EIP (if option was checked) and Directories IID
	if (m_fix_oep && !m_makeloader)
	{
		pe_file.m_nt_header->entryPoint = oep;
	}*/
	old_iid_rva = iid_rva;
	old_iid_offset = iid_offset;

	// Fill import from our tree
	my_iterator1 = modlist.begin();
	while (my_iterator1 != modlist.end())
	{
/*		if (!m_bNewIAT && !pe_file.RVA2Offset(((*my_iterator1).second).first_thunk, &offset))
		{
			RemoveTempExactCalls();
			AddLog("Invalid dump file, nothing done.");
			MessageBox("Invalid dump file! Can't match RVA to Offset in the dump file", "Import Address Table Problem");
			return;
		}*/

		// IID
		{
			if (((*my_iterator1).second).valid)
			{
				// Fill the IID
				// OriginalFirstThunk
				*((DWORD*)(pe_file.m_buffer+iid_offset)) = 0;
				iid_rva += 4;
				iid_offset += 4;
				// TimeDateStamp
				*((DWORD*)(pe_file.m_buffer+iid_offset)) = 0;
				iid_rva += 4;
				iid_offset += 4;
				// ForwarderChain
				*((DWORD*)(pe_file.m_buffer+iid_offset)) = 0;
				iid_rva += 4;
				iid_offset += 4;
				// Name of the DLL
				*((DWORD*)(pe_file.m_buffer+iid_offset)) = ascii_rva;
				iid_rva += 4;
				iid_offset += 4;
				// First Thunk
				{
					*((DWORD*)(pe_file.m_buffer+iid_offset)) = ((*my_iterator1).second).first_thunk;
				}
				iid_rva += 4;
				iid_offset += 4;

				// Copy the module name
				strcpy((char*)(pe_file.m_buffer+ascii_offset), ((*my_iterator1).second).name);
				ascii_rva += strlen(((*my_iterator1).second).name)+1;
				ascii_offset += strlen(((*my_iterator1).second).name)+1;
				total_length += strlen(((*my_iterator1).second).name)+1;

				// Alignment
				rest = total_length%2;
				if (rest)
				{
					rest = 2-rest;
					ascii_rva += rest;
					ascii_offset += rest;
					total_length += rest;
				}

				old_offset = 0;
				my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
				while (my_iterator2 != ((*my_iterator1).second).thunk_list.end())
				{
					if (/*!m_bNewIAT &&*/ !pe_file.RVA2Offset(((*my_iterator2).second).rva, &offset))
					{
/*						RemoveTempExactCalls();
						AddLog("Invalid dump file, nothing done.");
						MessageBox("Invalid dump file! Can't match RVA to Offset in the dump file", "Import Address Table Problem");*/
						return (IREC_RVA2OFFSET_ERROR);
					}
					old_offset = offset;

					// Import by function name
					if (!m_importbyordinal && strlen(((*my_iterator2).second).name) > 0)
					{
						// Point the IAT function pointer to this string
/*						if (m_bNewIAT)
						{
							pe_file.RVA2Offset(m_new_iat_map[((*my_iterator2).second).rva], &new_iat_offset);
							*((DWORD*)(pe_file.m_buffer+new_iat_offset)) = ascii_rva;
//							new_iat_rva += 4;
//							new_iat_offset += 4;

							// Keep the table of IAT :  original RVA <=> new RVA
							m_new_iat_rva_table.push_back(((*my_iterator2).second).rva);
							m_new_iat_rva_table.push_back(m_new_iat_map[((*my_iterator2).second).rva]);
						}
						else*/
						{
							*((DWORD*)(pe_file.m_buffer+offset)) = ascii_rva;
						}

						// Fill the ASCII function name
						if ((ascii_offset+strlen(((*my_iterator2).second).name)+1+2) >= (DWORD)(pe_file.m_size))
						{
/*							RemoveTempExactCalls();
							AddLog("Not enough space to put new import datas, nothing done.");
							MessageBox("Not enough space to put new import datas!", "Ascii Problem");*/
							return (IREC_INVALID_OFFSET_ERROR);
						}

						// Hint (1 short = ordinal)
						*((WORD*)(pe_file.m_buffer+ascii_offset)) = (WORD)((*my_iterator2).second).ordinal;
						ascii_rva += 2;
						ascii_offset += 2;
						// Copy the function name
						strcpy((char*)(pe_file.m_buffer+ascii_offset), ((*my_iterator2).second).name);
						ascii_rva += strlen(((*my_iterator2).second).name)+1;
						ascii_offset += strlen(((*my_iterator2).second).name)+1;
						total_length += strlen(((*my_iterator2).second).name)+1+2;

						// Alignment
						rest = total_length%2;
						if (rest)
						{
							rest = 2-rest;
							ascii_rva += rest;
							ascii_offset += rest;
							total_length += rest;
						}
					}
					// Import by ordinal
					else
					{
/*						if (m_bNewIAT)
						{
							// Fill the IAT function with the ordinal followed by 0x8000
							pe_file.RVA2Offset(m_new_iat_map[((*my_iterator2).second).rva], &new_iat_offset);
							*((DWORD*)(pe_file.m_buffer+new_iat_offset)) = 0x80000000 | ((*my_iterator2).second).ordinal;
//							new_iat_rva += 4;
//							new_iat_offset += 4;
						}
						else*/
						{
							// Fill the IAT function with the ordinal followed by 0x8000
							*((DWORD*)(pe_file.m_buffer+offset)) = 0x80000000 | ((*my_iterator2).second).ordinal;
						}
					}

					my_iterator2++;
				}

/*				// Force a NULL DWORD at the end of the thunk
				if (m_bNewIAT)
				{
				}
				else*/
				{
					if (old_offset)
					{
						*((DWORD*)(pe_file.m_buffer+old_offset+4)) = 0;
					}
				}

//				new_iat_rva += 4;
//				new_iat_offset += 4;
			}
		}

		my_iterator1++;
	}

	// Finish the IID and update IID size
	*((DWORD*)(pe_file.m_buffer+iid_offset)) = 0;
	iid_rva += 4;
	iid_offset += 4;
	*((DWORD*)(pe_file.m_buffer+iid_offset)) = 0;
	iid_rva += 4;
	iid_offset += 4;
	*((DWORD*)(pe_file.m_buffer+iid_offset)) = 0;
	iid_rva += 4;
	iid_offset += 4;
	*((DWORD*)(pe_file.m_buffer+iid_offset)) = 0;
	iid_rva += 4;
	iid_offset += 4;
	*((DWORD*)(pe_file.m_buffer+iid_offset)) = 0;
	iid_rva += 4;
	iid_offset += 4;

	pe_file.m_directories[ImportDataDirectory].RVA = old_iid_rva;
	pe_file.m_directories[ImportDataDirectory].size = iid_offset - old_iid_offset - 5*4;

	pe_file.m_directories[IATDirectory].RVA = 0;
	pe_file.m_directories[IATDirectory].size = 0;

/*	// Final stats
	sprintf(tmp, "Image Import Descriptor size: %X; Total length: %X",
			pe_file.m_directories[ImportDataDirectory].size, total_length);
	AddLog(tmp);*/

	// Remove the exact calls added temporarly to the tree
//	RemoveTempExactCalls();

	// Save the results
	strcpy(ext, dump_filename+strlen(dump_filename)-4);
	strcpy(dump_filename+strlen(dump_filename)-4, "_");
	strcat(dump_filename, ext);
	if (pe_file.SaveExecutable(dump_filename))
	{
/*		sprintf(tmp, "%s saved successfully.", m_dump_filename);
		AddLog(tmp);*/

		if (real_wrong > 0)
		{
//			MessageBox("IAT is still invalid. You have to fix manually all unresolved pointers.", "Warning!");
		}
//		ValidateImport();
	}
	else
	{
//		sprintf(tmp, "Problem on saving %s.", m_dump_filename);
//		AddLog(tmp);
	}

	return (IREC_ALL_OK);
}

void CImpREC::LogIAT(DWORD rva_iat_slot, DWORD va_api)
{
	char proc_name[IMPREC_MAX_CHARS];
	char mod_name[IMPREC_MAX_CHARS];
	WORD ordinal;
	int j;
	void *view;
//	addr -= m_imgbase;
	char str[IMPREC_MAX_CHARS];
	sprintf(str, "%08X", va_api);
	// Look for address in our export datas
	for (j=0; j<m_nb_exports; j++)
	{
		// Export found
		if (m_exports[j].GetProcName((void*)va_api, proc_name, IMPREC_MAX_CHARS, &ordinal, mod_name,
									 FALSE))
		{
			m_imports.AddModule( "?", rva_iat_slot, 1, NULL, false);
			m_imports.AddFunction("?", rva_iat_slot, 0, str, &view, false);
			if (AddImp(rva_iat_slot, mod_name, ordinal, proc_name))
			{
//						nb_imp++;
			}
			break;
		}
	}
	if (j >= m_nb_exports)
	{
		m_imports.AddModule( "?", rva_iat_slot, 1, NULL, false);
		m_imports.AddFunction("?", rva_iat_slot, 0, str, &view, false);
	}
}
