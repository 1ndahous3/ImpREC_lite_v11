// Import REConstructor DLL v1.01 (C) 2001 MackT/uCF
///////////////////////////////////////////////////////////////////////
// You're allowed to use parts of this code if you mention my name.
///////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ImpREC.h"

#define DllExport extern "C" __declspec( dllexport )
CImpREC my_impREC;

// Initialization
BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	return (my_impREC.Init());
}

// Exported functions to use
///////////////////////////////////////////////////////////////////////

DllExport DWORD SetModule(DWORD pid, DWORD base)
{
	if (my_impREC.LoadProcess(pid, base))
	{
		return (1);
	}
	return (0);
}

// <rva_iat_slot>		: RVA of the IAT slot
// <va_api>				: VA of the resolved API at this slot
DllExport void LogIATEntry(DWORD rva_iat_slot, DWORD va_api)
{
	my_impREC.LogIAT(rva_iat_slot, va_api);
}

// <dump_filename>		: Filename of the dump to fix imports
DllExport DWORD MakeImportTable(LPTSTR dump_filename)
{
	if (my_impREC.FixDump(dump_filename))
	{
		return (1);
	}
	return (0);
}
