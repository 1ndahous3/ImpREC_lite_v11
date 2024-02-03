#include "stdafx.h"

#include "import.h"
#include "export.h"
#include "Header.h"

// Constructor
CImport::CImport()
{
	m_module_list.clear();
	m_nb_functions = 0;
}

// Destructor
CImport::~CImport()
{
	DeleteAll();
}

void CImport::DeleteAll()
{
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();

	while (my_iterator1 != m_module_list.end())
	{
		((*my_iterator1).second).thunk_list.clear();

		my_iterator1++;
	}

	m_module_list.clear();
	m_nb_functions = 0;
}

bool CImport::AddFunction(char *module_name, DWORD rva, WORD ordinal, char *name,
						  void **view, bool valid/* = true*/, bool force/* = false*/)
{
	DWORD first_thunk;

	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			first_thunk = (*my_iterator1).second.first_thunk;
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (false);
	}

	// The thunk does not exist!
	if ( m_module_list[(*my_iterator1).second.first_thunk].thunk_list.find(rva) == m_module_list[(*my_iterator1).second.first_thunk].thunk_list.end() )
	{
		return (false);
	}

	// We must force overwritting else return false if:
	if (!force)
	{
		// the current function is valid
		if (m_module_list[(*my_iterator1).second.first_thunk].thunk_list[rva].valid)
		{
			return (false);
		}

		// We add exactly the same function!
		if (!valid &&
			m_module_list[(*my_iterator1).second.first_thunk].thunk_list[rva].rva == rva &&
			stricmp(name, m_module_list[(*my_iterator1).second.first_thunk].thunk_list[rva].name) == 0)
		{
			return (false);
		}
	}

	*view = m_module_list[(*my_iterator1).second.first_thunk].thunk_list[rva].view;

	MyImpThunk my_thunk;
	strcpy(my_thunk.name, name);
	strcpy(my_thunk.module_name, module_name);
	my_thunk.ordinal = ordinal;
	my_thunk.rva = rva;
	my_thunk.valid = valid;
	my_thunk.view = m_module_list[(*my_iterator1).second.first_thunk].thunk_list[rva].view;

	m_module_list[(*my_iterator1).second.first_thunk].thunk_list[rva] = my_thunk;
	return (true);
}

void CImport::StickModules()
{
	MyImpThunk my_thunk;
	DWORD rva, i;
	bool quit = false;
	ImpModuleList::iterator my_iterator1;
	ImpModuleList::iterator my_iterator2;

	strcpy(my_thunk.name, "");
	my_thunk.ordinal = 0;
	my_thunk.view = NULL;
	my_thunk.valid = false;

	// Check for sticking it
	my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		my_iterator1++;
		my_iterator2 = my_iterator1;
		my_iterator1--;
		while (my_iterator2 != m_module_list.end())
		{
			my_iterator2++;
			ImpModuleList::iterator tmp_iterator = my_iterator2;
			my_iterator2--;

			// 1
			if ((*my_iterator1).second.first_thunk < (*my_iterator2).second.first_thunk &&
				(*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4 == (*my_iterator2).second.first_thunk)
			{
				(*my_iterator1).second.nb_thunks += (*my_iterator2).second.nb_thunks;

				for (rva=(*my_iterator2).second.first_thunk, i=0; i<(*my_iterator2).second.nb_thunks; rva+=4, i++)
				{
					my_thunk = (*my_iterator2).second.thunk_list[rva];
					(*my_iterator1).second.thunk_list[rva] = my_thunk;
				}
				m_module_list.erase((*my_iterator2).second.first_thunk);

				my_iterator2 = tmp_iterator;
				continue;
			}

			my_iterator2++;
		}
		my_iterator1++;
	}
}

bool CImport::AddModule(char *module_name, DWORD first_thunk, DWORD nb_thunks,
						void *view/*= NULL*/, bool valid/* = true*/)
{
	MyImpThunk my_thunk;
	MyImpModule my_module;
	DWORD rva, i;
	bool quit = false;
	ImpModuleList::iterator my_iterator1;

	strcpy(my_thunk.name, "");
	my_thunk.ordinal = 0;
	my_thunk.view = NULL;
	my_thunk.valid = false;

	my_module.first_thunk = first_thunk;
	my_module.nb_thunks = nb_thunks;
	my_module.view = view;
	my_module.valid = valid;
	strcpy(my_module.name, module_name);

	my_iterator1 = m_module_list.begin();
	// Check for existing thunk
	while (my_iterator1 != m_module_list.end())
	{
		// This thunk already exists!
		if (first_thunk >= (*my_iterator1).second.first_thunk &&
			first_thunk+nb_thunks*4 <= (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			return (false);
		}
		my_iterator1++;
	}

	// Check for sticking it
	my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		// 1
		if (first_thunk < (*my_iterator1).second.first_thunk &&
			first_thunk+nb_thunks*4 == (*my_iterator1).second.first_thunk)
		{
			m_nb_functions += nb_thunks;
			nb_thunks += (*my_iterator1).second.nb_thunks;
			my_module.nb_thunks = nb_thunks;

			for (rva=first_thunk, i=0; i<nb_thunks; rva+=4, i++)
			{
				my_thunk.rva = rva;
				my_module.thunk_list[rva] = my_thunk;
			}
			for (rva=(*my_iterator1).second.first_thunk, i=0; i<(*my_iterator1).second.nb_thunks; rva+=4, i++)
			{
				my_module.thunk_list[rva] = (*my_iterator1).second.thunk_list[rva];
			}
			m_module_list.erase((*my_iterator1).second.first_thunk);
			m_module_list[first_thunk] = my_module;
			return (true);
		}
		// 2
		if (first_thunk < (*my_iterator1).second.first_thunk &&
			first_thunk+nb_thunks*4 > (*my_iterator1).second.first_thunk &&
			first_thunk+nb_thunks*4 <= (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			int sub = ((first_thunk+nb_thunks*4)-((*my_iterator1).second.first_thunk))/4;
			m_nb_functions += nb_thunks-sub;
			nb_thunks += (*my_iterator1).second.nb_thunks - sub;
			my_module.nb_thunks = nb_thunks;

			for (rva=first_thunk, i=0; i<nb_thunks; rva+=4, i++)
			{
				my_thunk.rva = rva;
				my_module.thunk_list[rva] = my_thunk;
			}
			for (rva=(*my_iterator1).second.first_thunk, i=0; i<(*my_iterator1).second.nb_thunks; rva+=4, i++)
			{
				my_module.thunk_list[rva] = (*my_iterator1).second.thunk_list[rva];
			}
			m_module_list.erase((*my_iterator1).second.first_thunk);
			m_module_list[first_thunk] = my_module;
			return (true);
		}
		// 3
		if (first_thunk == (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4 &&
			first_thunk+nb_thunks*4 > (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			m_nb_functions += nb_thunks;
			for (rva=first_thunk, i=0; i<nb_thunks; rva+=4, i++)
			{
				my_thunk.rva = rva;
				m_module_list[(*my_iterator1).second.first_thunk].thunk_list[rva] = my_thunk;
			}
			nb_thunks += (*my_iterator1).second.nb_thunks;
			m_module_list[(*my_iterator1).second.first_thunk].nb_thunks = nb_thunks;
			return (true);
		}
		// 5
		if (first_thunk >= (*my_iterator1).second.first_thunk &&
			first_thunk < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4 &&
			first_thunk+nb_thunks*4 > (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			int sub = (((*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)-(first_thunk))/4;
			m_nb_functions += nb_thunks-sub;
			for (rva=first_thunk, i=0; i<nb_thunks; rva+=4, i++)
			{
				if (rva >= (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
				{
					my_thunk.rva = rva;
					m_module_list[(*my_iterator1).second.first_thunk].thunk_list[rva] = my_thunk;
				}
			}
			nb_thunks += (*my_iterator1).second.nb_thunks - sub;
			m_module_list[(*my_iterator1).second.first_thunk].nb_thunks = nb_thunks;
			return (true);
		}
		// 4
		if (first_thunk < (*my_iterator1).second.first_thunk &&
			first_thunk+nb_thunks*4 > (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			m_nb_functions += nb_thunks-(*my_iterator1).second.nb_thunks;
			my_module.nb_thunks = nb_thunks;

			for (rva=first_thunk, i=0; i<nb_thunks; rva+=4, i++)
			{
				my_thunk.rva = rva;
				my_module.thunk_list[rva] = my_thunk;
			}
			for (rva=(*my_iterator1).second.first_thunk, i=0; i<(*my_iterator1).second.nb_thunks; rva+=4, i++)
			{
				my_module.thunk_list[rva] = (*my_iterator1).second.thunk_list[rva];
			}
			m_module_list.erase((*my_iterator1).second.first_thunk);
			m_module_list[first_thunk] = my_module;
			return (true);
		}

		my_iterator1++;
	}

	my_module.first_thunk = first_thunk;
	my_module.nb_thunks = nb_thunks;
	my_module.valid = valid;
	strcpy(my_module.name, module_name);
	my_module.thunk_list.clear();

	m_module_list[first_thunk] = my_module;
	for (rva=first_thunk, i=0; i<nb_thunks; rva+=4, i++)
	{
		my_thunk.rva = rva;
		m_module_list[first_thunk].thunk_list[rva] = my_thunk;
	}
	m_nb_functions += nb_thunks;
	return (true);
}

bool CImport::DeleteModule(DWORD rva)
{
	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (false);
	}
	
	m_nb_functions -= (*my_iterator1).second.thunk_list.size();
	(*my_iterator1).second.thunk_list.clear();

	m_module_list.erase((*my_iterator1).second.first_thunk);
	return (true);
}

void CImport::ShowAll()
{
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	ImpThunkList::iterator my_iterator2;

	while (my_iterator1 != m_module_list.end())
	{
		if (::GetAsyncKeyState(VK_SHIFT)<0)
		{
			return;
		}
		MessageBox(0, ((*my_iterator1).second).name, "Mod", 0);
		my_iterator2 = ((*my_iterator1).second).thunk_list.begin();
		while (my_iterator2 != ((*my_iterator1).second).thunk_list.end())
		{
			if (::GetAsyncKeyState(VK_SHIFT)<0)
			{
				return;
			}
			if (::GetAsyncKeyState(VK_CONTROL)<0)
			{
				break;
			}
			MessageBox(0, ((*my_iterator2).second).name, "Func", 0);
			my_iterator2++;
		}

		my_iterator1++;
	}
}

DWORD CImport::GetNbModules()
{
	return (m_module_list.size());
}

DWORD CImport::GetNbFunctions()
{
	return (m_nb_functions);
}

bool CImport::SetModuleValidity(DWORD rva, bool valid)
{
	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (false);
	}

	(*my_iterator1).second.valid = valid;
	return (true);
}

bool CImport::GetFirstThunk(DWORD rva, DWORD *first_thunk)
{
	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (false);
	}

	*first_thunk = (*my_iterator1).second.first_thunk;
	return (true);
}

bool CImport::SetModuleName(DWORD rva, char *module_name)
{
	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (false);
	}

	strcpy((*my_iterator1).second.name, module_name);
	return (true);
}

void* CImport::GetModuleView(DWORD rva)
{
	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (NULL);
	}
	
	return ((*my_iterator1).second.view);
}

bool CImport::SetModuleView(DWORD first_thunk, void *view)
{
	// The module already exists!
	if ( m_module_list.find(first_thunk) != m_module_list.end())
	{
		(*(m_module_list.find(first_thunk))).second.view = view;
		return (true);
	}

	return (false);
}

bool CImport::SetFunctionView(DWORD rva, void *view)
{
	DWORD first_thunk;

	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			first_thunk = (*my_iterator1).second.first_thunk;
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (false);
	}

	// The thunk does not exist!
	if ( m_module_list[(*my_iterator1).second.first_thunk].thunk_list.find(rva) == m_module_list[(*my_iterator1).second.first_thunk].thunk_list.end() )
	{
		return (false);
	}

	MyImpThunk my_thunk = m_module_list[first_thunk].thunk_list[rva];
	my_thunk.view = view;
	m_module_list[first_thunk].thunk_list[rva] = my_thunk;
	return (true);
}

void* CImport::GetFunctionView(DWORD rva)
{
	DWORD first_thunk;

	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			first_thunk = (*my_iterator1).second.first_thunk;
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (NULL);
	}

	// The thunk does not exist!
	if ( m_module_list[(*my_iterator1).second.first_thunk].thunk_list.find(rva) == m_module_list[(*my_iterator1).second.first_thunk].thunk_list.end() )
	{
		return (NULL);
	}

	return (m_module_list[first_thunk].thunk_list[rva].view);
}

bool CImport::InvalidateFunction(DWORD rva, char *ptr)
{
	DWORD first_thunk;

	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			first_thunk = (*my_iterator1).second.first_thunk;
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (false);
	}

	// The thunk does not exist!
	if ( m_module_list[(*my_iterator1).second.first_thunk].thunk_list.find(rva) == m_module_list[(*my_iterator1).second.first_thunk].thunk_list.end() )
	{
		return (false);
	}

	strcpy(m_module_list[first_thunk].thunk_list[rva].name, ptr);
	m_module_list[first_thunk].thunk_list[rva].valid = false;
	return (true);
}

bool CImport::GetFunctionValidity(DWORD rva)
{
	DWORD first_thunk;

	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			first_thunk = (*my_iterator1).second.first_thunk;
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (false);
	}

	// The thunk does not exist!
	if ( m_module_list[(*my_iterator1).second.first_thunk].thunk_list.find(rva) == m_module_list[(*my_iterator1).second.first_thunk].thunk_list.end() )
	{
		return (false);
	}

	return (m_module_list[first_thunk].thunk_list[rva].valid);
}

bool CImport::GetModuleValidity(DWORD first_thunk)
{
	// The module already exists!
	if ( m_module_list.find(first_thunk) != m_module_list.end())
	{
		return ((*(m_module_list.find(first_thunk))).second.valid);
	}

	return (false);
}

ImpModuleList CImport::GetModel()
{
	return (m_module_list);
}

bool CImport::CutThunk(DWORD rva)
{
	DWORD i, rva2;
	DWORD first_thunk;
	DWORD nb_thunks;
	DWORD nb_thunks2;
	ImpThunkList thunk_list;
	thunk_list.clear();

	// Look for the associated module
	ImpModuleList::iterator my_iterator1 = m_module_list.begin();
	while (my_iterator1 != m_module_list.end())
	{
		if (rva >= (*my_iterator1).second.first_thunk &&
			rva < (*my_iterator1).second.first_thunk+(*my_iterator1).second.nb_thunks*4)
		{
			first_thunk = (*my_iterator1).second.first_thunk;
			break;
		}
		my_iterator1++;
	}
	// No module found
	if (my_iterator1 == m_module_list.end())
	{
		return (false);
	}

	// The thunk does not exist!
	if ( m_module_list[(*my_iterator1).second.first_thunk].thunk_list.find(rva) == m_module_list[(*my_iterator1).second.first_thunk].thunk_list.end() )
	{
		return (false);
	}

	nb_thunks = m_module_list[first_thunk].nb_thunks;
	m_module_list[first_thunk].nb_thunks = (rva - first_thunk)/4;
	nb_thunks2 = nb_thunks-m_module_list[first_thunk].nb_thunks;
	nb_thunks2--;	// We lost one function

	// ALGO: - Copy all second part functions into our local <thunk_list>
	//       - Delete them from first thunk
	//       - Create a new thunk and give it our local <thunk_list>
	//
	// Don't create a new thunk if we has cutted at the end
	if (nb_thunks2 > 0)
	{
		for (i=0, rva2 = rva+4; i<nb_thunks2; i++, rva2+=4)
		{
			thunk_list[rva2] = m_module_list[first_thunk].thunk_list[rva2];
		}
	}

	for (i=0, rva2 = rva; i<nb_thunks2+1; i++, rva2+=4)
	{
		m_module_list[first_thunk].thunk_list.erase(rva2);
	}

	if (nb_thunks2 > 0)
	{
		AddModule("?", rva+4, nb_thunks2, NULL, false);
		m_module_list[rva+4].thunk_list = thunk_list;
	}

	// If the original thunk has now 0 function (cutted at the beginning), delete it
	if (m_module_list[first_thunk].nb_thunks == 0)
	{
		m_module_list.erase(first_thunk);
	}

	return (true);
}
