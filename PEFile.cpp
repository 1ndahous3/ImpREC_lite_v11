// PEFile.cpp: implementation of the CPEFile class.
//
//////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Imagehlp.h>
#include "PEFile.h"
#include "Header.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CPEFile::CPEFile(HWND hwnd/* = NULL*/)
{
	m_is_module = false;
	m_hwnd = hwnd;
	strcpy(m_filename, "");
	m_buffer = 0;
	m_size = 0;
	m_dosstub_size = 0;
	m_pe_header = 0;
	m_std_header = 0;
	m_nt_header = 0;
	m_rom_header = 0;
	m_directories = 0;
	m_sections = 0;

	m_ptr_exp = 0;
	m_ord_table = 0;
}

CPEFile::~CPEFile()
{
	if (m_buffer)
	{
		if (!m_is_module)
		{
			delete[] m_buffer;
		}
		else
		{
			FreeLibrary((HMODULE)m_buffer);
		}
		m_buffer = 0;
	}
}

// SetIsModule
//
// - Set if it's a module or no... If yes so do not free its memory!!!
//==============================================================================================
void CPEFile::SetIsModule(bool is_module)
{
	m_is_module = is_module;
}

// LoadExecutable
//
// - Load the executable in memory and parse the pe header
//==============================================================================================
bool CPEFile::LoadExecutable(char *filename)
{
	bool result;
	FILE *f;

	// Delete all previous buffer
	if (m_buffer)
	{
		if (!m_is_module)
		{
			delete[] m_buffer;
		}
		m_buffer = 0;
	}

	// Load the file into memory
	f = fopen(filename, "rb");
	if (!f)
	{
		printf("Can't open for reading the file %s\n", filename);
		return (false);
	}
	fseek(f, 0, SEEK_END);
	m_size = ftell(f);
	fseek(f, 0, SEEK_SET);
	m_buffer = new unsigned char[m_size];

	if (fread(m_buffer, sizeof(unsigned char), m_size, f) != (size_t)m_size)
	{
		printf("Can't open for reading the whole file %s\n", filename);
		fclose(f);

		if (m_buffer)
		{
			if (!m_is_module)
			{
				delete[] m_buffer;
			}
			m_buffer = 0;
		}
		return (false);
	}
	fclose (f);

	// Update all variables
	result = UpdatePEVars(false);
	if (result)
	{
		strcpy(m_filename, filename);
	}

	return (result);
}

// UpdatePEVars
//
// - Parse all pe headers into our variables
//==============================================================================================
bool CPEFile::UpdatePEVars(bool fix_sections/* = false*/)
{
	unsigned int	i;
	unsigned short	dos_stub;
	unsigned int	pe_offset, pe_signature;
	unsigned int	current_pos;

	// Executable not yet loaded!!!!
	if (!m_buffer)
	{
		printf("Open a file before\n");
		return (false);
	}

	// Check DosStub infos
	dos_stub = ((unsigned short*)m_buffer)[0];
	if (dos_stub != 0x5a4d)
	{
		printf("Not a windows executable\n");
		return (false);
	}

	pe_offset = *((unsigned int*)(m_buffer + 0x3c));

	// Check PE Format signature
	pe_signature = *((unsigned int*)(m_buffer + pe_offset));
	if (pe_signature != 0x00004550)
	{
		printf("Not a PE format executable\n");
		return (false);
	}

	// Get PE Infos
	DWORD tmp_pos;
	current_pos = pe_offset + 4;
	m_dosstub_size = current_pos;

	m_pe_header = (PEHeader*)(m_buffer + current_pos);
	current_pos += sizeof(PEHeader);

	tmp_pos = current_pos;

	m_nt_header = (NTOptionalHeader*)(m_buffer + current_pos);
	current_pos += sizeof(NTOptionalHeader);
	m_directories = (DataDirectory*)(m_buffer + current_pos);
	current_pos += sizeof(DataDirectory) * m_nt_header->numDataDirectories;

	// Compute section position dynamically depending on the optional header size
	current_pos = tmp_pos + m_pe_header->optionalHeaderSize;
	m_sections = (Section*)(m_buffer + current_pos);
	current_pos += sizeof(Section) * m_pe_header->numSections;

	// Do we need to fix all Raw Infos for each section? (Especially for a dumped task)
	if (fix_sections)
	{
		for (i=0; i<m_pe_header->numSections; i++)
		{
			m_sections[i].dataOffset = m_sections[i].RVA;
			m_sections[i].dataAlignSize = m_sections[i].misc.virtualSize;
		}
	}

	return (true);
}

// LoadPEVars
//
// - Load all pe headers without the rest
//==============================================================================================
bool CPEFile::LoadPEVars(char *filename, DWORD pid, bool use_pe_header_from_disk,
						 DWORD image_base, DWORD image_size)
{
	unsigned int pe_offset;
	NTOptionalHeader nt_header;
	bool result;
	FILE *f;

	// Delete all previous buffer
	if (m_buffer)
	{
		if (!m_is_module)
		{
			delete[] m_buffer;
		}
		m_buffer = 0;
	}

	// Load the file into memory
	f = fopen(filename, "rb");
	if (!f)
	{
		printf("Can't open for reading the file %s\n", filename);
		return (false);
	}

	fseek(f, 0x3c, SEEK_CUR);
	fread(&pe_offset, sizeof(unsigned int), 1, f);
	fseek(f, pe_offset+4+sizeof(PEHeader), SEEK_SET);
	fread(&nt_header, sizeof(NTOptionalHeader), 1, f);
	m_size = nt_header.headersSize;
	m_buffer = new unsigned char[m_size];

	fseek(f, 0, SEEK_SET);
	fread(m_buffer, sizeof(unsigned char), m_size, f);
	fclose(f);

	if (!use_pe_header_from_disk)
	{
		HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (handle)
		{
			DWORD dwCheckSize;
//			DWORD dwOldProt;
//			if (VirtualProtectEx( handle, (void*)(rva+m_imgbase), 4, PAGE_READWRITE, &dwOldProt ))
			{
				if (MyRPM( handle, (void*)(image_base),
									   (LPVOID)m_buffer, m_size ,
									   &dwCheckSize)
					&& dwCheckSize == (DWORD)m_size)
				{
//					VirtualProtectEx( handle, (void*)(rva+m_imgbase), 4, dwOldProt, &dwCheckSize );
				}
				else
				{
					CloseHandle(handle);
					return (false);
				}
			}
/*			else
			{
				CloseHandle(handle);
				break;
			}*/
			CloseHandle(handle);
		}
		else
		{
			return (false);
		}
	}

	// Update all variables
	result = UpdatePEVars(false);
	if (result)
	{
		if (!use_pe_header_from_disk)
		{
			m_nt_header->imageBase = image_base;
			m_nt_header->imageSize = image_size;
		}
		strcpy(m_filename, filename);
	}

	return (result);
}


// WriteInfos
//
// - Write pe infos into a txt file
//==============================================================================================
bool CPEFile::WriteInfos(char *filename)
{
	unsigned int i;
	char buffer[9];
	FILE *fd;

	// Executable not yet loaded!!!!
	if (!m_buffer)
	{
		printf("Open a file before!!\n");
		return (false);
	}
	
	fd = fopen(filename, "w");
	if (!fd)
	{
		printf("Can't open for writing the file %s\n", filename);
		return (false);
	}

	// pe header
	fprintf(fd, "---==== PE Infos ====---\n\n");
	fprintf(fd, "\tdosStubSize 0x%x\n", m_dosstub_size);
	fprintf(fd, "\nPEHeader\n");
	fprintf(fd, "\tcpuType 0x%x\n", m_pe_header->cpuType);
	fprintf(fd, "\tnumSections 0x%x\n", m_pe_header->numSections);
	fprintf(fd, "\tdateStamp 0x%x\n", m_pe_header->dateStamp);
	fprintf(fd, "\tsymbolTable 0x%x\n", m_pe_header->symbolTable);
	fprintf(fd, "\tnumSymbols 0x%x\n", m_pe_header->numSymbols);
	fprintf(fd, "\toptionalHeaderSize 0x%x\n", m_pe_header->optionalHeaderSize);
	fprintf(fd, "\tflags 0x%x\n", m_pe_header->flags);

	// pe optional header
	fprintf(fd, "\nNTOptionalHeader\n");
	fprintf(fd, "\tmagic 0x%x\n", m_nt_header->magic);
	fprintf(fd, "\tlinkerMajor 0x%x\n", m_nt_header->linkerMajor);
	fprintf(fd, "\tlinkerMinor 0x%x\n", m_nt_header->linkerMinor);
	fprintf(fd, "\tcodeSize 0x%x\n", m_nt_header->codeSize);
	fprintf(fd, "\tinitDataSize 0x%x\n", m_nt_header->initDataSize);
	fprintf(fd, "\tuninitDataSize 0x%x\n", m_nt_header->uninitDataSize);
	fprintf(fd, "\tentryPoint 0x%x\n", m_nt_header->entryPoint);
	fprintf(fd, "\tcodeBase 0x%x\n", m_nt_header->codeBase);
	fprintf(fd, "\tdataBase 0x%x\n", m_nt_header->dataBase);
	fprintf(fd, "\timageBase 0x%x\n", m_nt_header->imageBase);
	fprintf(fd, "\tsectionAlign 0x%x\n", m_nt_header->sectionAlign);
	fprintf(fd, "\tfileAlign 0x%x\n", m_nt_header->fileAlign);
	fprintf(fd, "\tosMajor 0x%x\n", m_nt_header->osMajor);
	fprintf(fd, "\tosMinor 0x%x\n", m_nt_header->osMinor);
	fprintf(fd, "\timageMajor 0x%x\n", m_nt_header->imageMajor);
	fprintf(fd, "\timageMinor 0x%x\n", m_nt_header->imageMinor);
	fprintf(fd, "\tsubsystemMajor 0x%x\n", m_nt_header->subsystemMajor);
	fprintf(fd, "\tsubsystemMinor 0x%x\n", m_nt_header->subsystemMinor);
	fprintf(fd, "\treserved 0x%x\n", m_nt_header->reserved);
	fprintf(fd, "\timageSize 0x%x\n", m_nt_header->imageSize);
	fprintf(fd, "\theadersSize 0x%x\n", m_nt_header->headersSize);
	fprintf(fd, "\tchecksum 0x%x\n", m_nt_header->checksum);
	fprintf(fd, "\tsubsystem 0x%x\n", m_nt_header->subsystem);
	fprintf(fd, "\tdllFlags 0x%x\n", m_nt_header->dllFlags);
	fprintf(fd, "\tstackReserveSize 0x%x\n", m_nt_header->stackReserveSize);
	fprintf(fd, "\tstackCommitSize 0x%x\n", m_nt_header->stackCommitSize);
	fprintf(fd, "\theapReserveSize 0x%x\n", m_nt_header->heapReserveSize);
	fprintf(fd, "\theapCommitSize 0x%x\n", m_nt_header->heapCommitSize);
	fprintf(fd, "\tloaderFlags 0x%x\n", m_nt_header->loaderFlags);
	fprintf(fd, "\tnumDataDirectories 0x%x\n", m_nt_header->numDataDirectories);

	// data directories
	fprintf(fd, "\nDataDirectories\n");
	fprintf(fd, "\t;RVA\t\tSize\n");
	for(i=0; i< m_nt_header->numDataDirectories; i++)
	{
		fprintf(fd, "\t0x%x\t\t0x%x", 
		m_directories[i].RVA, m_directories[i].size);

		if (i < (sizeof(dataDirNames) / sizeof(char*)))
			fprintf(fd, "\t\t; %s", dataDirNames[i]);
		else
			fprintf(fd, "\t\t; !!!UNKNOWN DIRECTORY!!!");

		fprintf(fd, "\n");
	}

	// sections
	fprintf(fd, "\nSections\n");
	fprintf(fd, "\t;Name\t\tVSize\tRVA\tSize\tOffset\tRel\tLines\t#Rel\t#Line\tFlags\n");
	for(i=0; i < m_pe_header->numSections; i++)
	{
		strncpy(buffer, (char*)(m_sections[i].name), 8);
		*(buffer+8) = 0;
		fprintf(fd, "\t%s\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t\n", 
		buffer,
		m_sections[i].misc.virtualSize,
		m_sections[i].RVA,
		m_sections[i].dataAlignSize,
		m_sections[i].dataOffset,
		m_sections[i].relocationsOffset,
		m_sections[i].lineNumbersOffset,
		m_sections[i].numRelocations,
		m_sections[i].numLineNumbers,
		m_sections[i].flags);
	}

	fclose(fd);
	return (true);
}

// SaveExecutable
//
// - Write the current executable
//==============================================================================================
bool CPEFile::SaveExecutable(char *filename)
{
	FILE *f;

	// Executable not yet loaded!!!!
	if (!m_buffer)
	{
		printf("Open a file before!!\n");
		return (false);
	}

	// Write the current buffer into a file
	f = fopen(filename, "wb");
	if (!f)
	{
		printf("Can't open for writing the file %s\n", filename);
		return (false);
	}

	if (fwrite(m_buffer, sizeof(unsigned char), m_size, f) !=
		(size_t)m_size)
	{
		printf("Can't write the whole executable\n");
		fclose(f);
		return (false);
	}

	fclose(f);
	return (true);
}

// SavePartialExecutable
//
// - Write the current executable in partial mode
//==============================================================================================
bool CPEFile::SavePartialExecutable(char *filename, DWORD start, DWORD length)
{
	FILE *f;

	start -= m_nt_header->imageBase;

	// Executable not yet loaded!!!!
	if (!m_buffer)
	{
		printf("Open a file before!!\n");
		return (false);
	}

	// Write the current buffer into a file
	f = fopen(filename, "wb");
	if (!f)
	{
		printf("Can't open for writing the file %s\n", filename);
		return (false);
	}

	if (fwrite(m_buffer+start, sizeof(unsigned char), length, f) !=
		(size_t)length)
	{
		printf("Can't write a part of this executable\n");
		fclose(f);
		return (false);
	}

	fclose(f);
	return (true);
}

// SaveHeaderOnly
//
// - Write the header of the current executable
//==============================================================================================
bool CPEFile::SaveHeaderOnly(char *filename)
{
	FILE *f;
	DWORD dwHeaderSize;

	// Executable not yet loaded!!!!
	if (!m_buffer)
	{
		printf("Open a file before!!\n");
		return (false);
	}

	// Write the current buffer into a file
	f = fopen(filename, "wb");
	if (!f)
	{
		printf("Can't open for writing the file %s\n", filename);
		return (false);
	}

	dwHeaderSize = m_dosstub_size +
		sizeof(PEHeader) +
		sizeof(NTOptionalHeader) +
		sizeof(DataDirectory)*m_nt_header->numDataDirectories +
		sizeof(Section)*m_pe_header->numSections;

	// Save the whole headers
	if (fwrite(m_buffer, sizeof(unsigned char), dwHeaderSize, f) !=
		(size_t)dwHeaderSize)
	{
		printf("Can't write the whole headers\n");
		fclose(f);
		return (false);
	}

	fclose(f);
	return (true);
}


// FindSectionIndex
//
// - Return the index of a section which contains <addr> else -1 if there's no one
//
// NOTE : <addr> is an RVA address
//==============================================================================================
int CPEFile::FindSectionIndex(DWORD addr)
{
	int i;
	for (i=0; i<m_pe_header->numSections; i++)
	{
		if (addr >= m_sections[i].RVA && 
			addr < m_sections[i].RVA + m_sections[i].misc.virtualSize)
		{
			return (i);
		}
	}

	return (-1);
}

// FindSectionIndexOffset
//
// - Return the index of a section which contains <addr> else -1 if there's no one
//
// NOTE : <addr> is an Offset address
//==============================================================================================
int CPEFile::FindSectionIndexOffset(DWORD addr)
{
	int i;
	for (i=0; i<m_pe_header->numSections; i++)
	{
		if (addr >= m_sections[i].dataOffset && 
			addr < m_sections[i].dataOffset + m_sections[i].dataAlignSize)
		{
			return (i);
		}
	}

	return (-1);
}

// ImageRVAToVA - like
bool CPEFile::RVA2Offset(DWORD rva, DWORD *offset)
{
	DWORD tmp;
	int i = FindSectionIndex(rva);
	if (i >= 0)
	{
		tmp = rva - m_sections[i].RVA + m_sections[i].dataOffset;

		if (tmp < (m_sections[i].dataOffset+m_sections[i].dataAlignSize))
		{
			*offset = tmp;
			return (TRUE);
		}
	}

	return (FALSE);
}

// GetHeader
//
// - Replace the header of buffer into the current
//==============================================================================================
bool CPEFile::FixHeader()
{
	// Executable not yet loaded!!!!
	if (!m_buffer)
	{
		printf("Open a file before!!\n");
		return (false);
	}

	CPEFile pe_file_header(m_hwnd);
	if (pe_file_header.LoadExecutable(m_filename) &&
		pe_file_header.UpdatePEVars(true))	// FIX RAW=RVA for all sections
	{
		memcpy(m_buffer, pe_file_header.m_buffer, pe_file_header.m_nt_header->headersSize);
		return (true);
	}

	return (false);
}

// Rebuild Import
//
// - Rebuild the import table
//==============================================================================================
bool CPEFile::RebuildImport(void **name_import)
{
	// Executable not yet loaded!!!!
	if (!m_buffer)
	{
		printf("Open a file before!!\n");
		return (false);
	}

	char buf[IMPREC_MAX_CHARS];
	int  i;

	if ((i=FindSectionIndex(m_directories[ImportDataDirectory].RVA)) >= 0)
	{
		int nb_dll = 0, nn = 0;

		// Cut the import table to 3 parts
		//
		// 1 - Image Import Descriptor
		// 2 - Import Array Table
		// 3 - Function Name

		// FIRST
		IMAGE_IMPORT_DESCRIPTOR *tmp = 
			(IMAGE_IMPORT_DESCRIPTOR*)(m_buffer+m_sections[i].dataOffset+
			m_directories[ImportDataDirectory].RVA-m_sections[i].RVA);
		DWORD *tmp2;

		void *imp1 = tmp;
		void *imp2;
		void *imp3;

		// SECOND
		while (tmp->Name)
		{
			tmp++;
			nb_dll++;
		}
		tmp++;
		imp2 = tmp;

		// THIRD
		tmp2 = (DWORD*)tmp;
		while (nn < nb_dll)
		{
			if (!(*tmp2))
			{
				nn++;
			}
			tmp2++;
		}
		imp3 = tmp2;

		sprintf(buf, "%X %X %X",
			(DWORD)imp1-(DWORD)m_buffer,
			(DWORD)imp2-(DWORD)m_buffer,
			(DWORD)imp3-(DWORD)m_buffer);

		*name_import = imp3;
		printf("%s\n", buf);
		return (true);
	}

	printf("Argh! No section found.!!\n");
	return (false);
}

// GetLastSectionIndex
//
// - Return the index of the last section
//==============================================================================================
int CPEFile::GetLastSectionIndex()
{
	int i, last = -1;
	DWORD rva = 0;

	for (i=0; i < m_pe_header->numSections; i++)
	{
		if (rva < m_sections[i].RVA)
		{
			rva = m_sections[i].RVA;
			last = i;
		}
	}

	return (last);
}

// Add Section
//
// - Add a new section with 0 bytes written in it
//==============================================================================================
bool CPEFile::AddSection(char *name, DWORD size, DWORD *new_rva, DWORD *new_sz, DWORD flags)
{
	unsigned char *new_buffer;
	int i = m_pe_header->numSections, last;
	DWORD old_size;
	DWORD offset, rva;

	// Pffff!
	if (size == 0)
	{
		return (true);
	}

	// Check if we can add a section??
	if (FindSectionIndex( (DWORD)(m_sections+i)+sizeof(Section) ) >= 0)
	{
		MessageBox(0, "Can't add any section to this dump file!", "Not enough space", 0);
		return (false);
	}
	
	// Ok that's right! ;-)
	// Compute the size needed with a 0x1000 alignment
	size = 0x1000*( ((size-1)/0x1000)+1 );

	offset = 0x1000*( ((m_size-1)/0x1000)+1 );

	last = GetLastSectionIndex();
	if (last >= 0)
	{
		rva = m_sections[last].RVA + m_sections[last].misc.virtualSize;
		rva = 0x1000*( ((rva-1)/0x1000)+1 );
	}
	else
	{
		rva = 0x1000;
	}

	strcpy((char*)(m_sections[i].name), name);
	m_sections[i].misc.virtualSize = size;
	m_sections[i].RVA = rva;
	m_sections[i].dataAlignSize = size;
	m_sections[i].dataOffset = offset;
	m_sections[i].relocationsOffset = 0;
	m_sections[i].lineNumbersOffset = 0;
	m_sections[i].numRelocations = 0;
	m_sections[i].numLineNumbers = 0;
	m_sections[i].flags = flags;

	old_size = m_size;
	m_size = offset+size;
	m_nt_header->imageSize = rva+size;
	m_pe_header->numSections++;

	// Write output values
	*new_rva = rva;
	*new_sz = size;

	// Allocate a new memory block
	size = offset+size;
	new_buffer = new unsigned char[size];
	memset(new_buffer, 0, sizeof(unsigned char)*size);
	memcpy(new_buffer, m_buffer, sizeof(unsigned char)*old_size);
	if (!m_is_module)
	{
		delete[] m_buffer;
	}
	m_buffer = new_buffer;

	// Fix the size
	UpdatePEVars(false);

	return (true);
}

bool CPEFile::FixSections(unsigned char *pe_buffer)
{
	// pe infos
	unsigned int		dosstub_size;
	PEHeader			*pe_header;
	NTOptionalHeader	*nt_header;
	DataDirectory		*directories;
	Section				*sections;
	unsigned int		i;
	unsigned short		dos_stub;
	unsigned int		pe_offset, pe_signature;
	unsigned int		current_pos;

	// Check pointer validity
	if (!pe_buffer)
	{
		return (false);
	}

	// Check DosStub infos
	dos_stub = ((unsigned short*)pe_buffer)[0];
	if (dos_stub != 0x5a4d)
	{
		printf("Not a windows executable\n");
		return (false);
	}

	pe_offset = *((unsigned int*)(pe_buffer + 0x3c));

	// Check PE Format signature
	pe_signature = *((unsigned int*)(pe_buffer + pe_offset));
	if (pe_signature != 0x00004550)
	{
		printf("Not a PE format executable\n");
		return (false);
	}

	// Get PE Infos
	DWORD tmp_pos;
	current_pos = pe_offset + 4;
	dosstub_size = current_pos;

	pe_header = (PEHeader*)(pe_buffer + current_pos);
	current_pos += sizeof(PEHeader);

	tmp_pos = current_pos;

	nt_header = (NTOptionalHeader*)(pe_buffer + current_pos);
	current_pos += sizeof(NTOptionalHeader);
	directories = (DataDirectory*)(pe_buffer + current_pos);
	current_pos += sizeof(DataDirectory) * nt_header->numDataDirectories;

	// Compute section position dynamically depending on the optional header size
	current_pos = tmp_pos + pe_header->optionalHeaderSize;
	sections = (Section*)(pe_buffer + current_pos);
	current_pos += sizeof(Section) * pe_header->numSections;

	// Do we need to fix all Raw Infos for each section? (Especially for a dumped task)
	for (i=0; i<pe_header->numSections; i++)
	{
		sections[i].dataOffset = sections[i].RVA;
		sections[i].dataAlignSize = sections[i].misc.virtualSize;
	}
	return (true);
}
