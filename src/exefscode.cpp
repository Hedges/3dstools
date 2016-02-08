#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "exefscode.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)

ExefsCode::ExefsCode() :
	m_CodeBlob(NULL),
	m_CodeBlobSize(0)
{
	initCodeSegment(m_Text);
	initCodeSegment(m_Rodata);
	initCodeSegment(m_Data);
	initCodeSegment(m_ModuleId);
}

ExefsCode::~ExefsCode()
{
	freeCodeBlob();
	freeCodeSegment(m_Text);
	freeCodeSegment(m_Rodata);
	freeCodeSegment(m_Data);
	freeCodeSegment(m_ModuleId);
}


int ExefsCode::parseElf(const u8 *elf)
{
	const Elf32_Ehdr *ehdr = (const Elf32_Ehdr*)elf;

	if (memcmp(ehdr->e_ident, ELF_MAGIC, 4) != 0)
	{
		die("[ERROR] Not a valid ELF");
	}

	if (ehdr->e_ident[EI_CLASS] != 1 || \
		ehdr->e_ident[EI_DATA] != ELFDATA2LSB || \
		le_hword(ehdr->e_type) != ET_EXEC || \
		le_hword(ehdr->e_machine) != ET_ARM)
	{
		die("[ERROR] Unsupported ELF");
	}

	const Elf32_Phdr *phdr = (const Elf32_Phdr*)(elf + le_word(ehdr->e_phoff));

	for (u16 i = 0; i < le_hword(ehdr->e_phnum); i++)
	{
		if (le_word(phdr[i].p_type) != PT_LOAD)
		{
			continue;
		}

		switch ((le_word(phdr[i].p_flags) & ~PF_CTRSDK))
		{
			// text
			case (PF_R | PF_X) :
			{
				createCodeSegment(m_Text, phdr[i], elf);
				break;
			}
			// rodata
			case (PF_R) :
			{
				// CTRSDK ELFs have ModuleId segments at the end
				if (i == le_hword(ehdr->e_phnum) - 1)
				{
					createCodeSegment(m_ModuleId, phdr[i], elf);
				}
				else
				{
					createCodeSegment(m_Rodata, phdr[i], elf);
				}
				break;
			}
			// data
			case (PF_R | PF_W) :
			{
				createCodeSegment(m_Data, phdr[i], elf);
				break;
			}
		}
	}

	if (!m_Text.fileSize)
	{
		die("[ERROR] Failed to locate Text ELF Segment");
	}
	if (!m_Data.fileSize)
	{
		die("[ERROR] Failed to locate Data ELF Segment");
	}



	return 0;
}

// internally generate code blob
// code blobs are normally page aligned, except in builtin sysmodules
void ExefsCode::createCodeBlob(bool pageAligned)
{
	u8 *textPos, *rodataPos, *dataPos;

	if (m_CodeBlob != NULL)
	{
		freeCodeBlob();
	}

	if (pageAligned)
	{
		m_CodeBlobSize = pageToSize(m_Text.pageNum + m_Rodata.pageNum + m_Data.pageNum);
		m_CodeBlob = (u8*)calloc(1, m_CodeBlobSize);

		textPos = (m_CodeBlob + 0);
		rodataPos = (m_CodeBlob + pageToSize(m_Text.pageNum));
		dataPos = (m_CodeBlob + pageToSize(m_Text.pageNum + m_Rodata.pageNum));
	}
	else
	{
		m_CodeBlobSize = m_Text.fileSize + m_Rodata.fileSize + m_Data.fileSize;
		m_CodeBlob = (u8*)calloc(1, m_CodeBlobSize);

		textPos = (m_CodeBlob + 0);
		rodataPos = (m_CodeBlob + m_Text.fileSize);
		dataPos = (m_CodeBlob + m_Text.fileSize + m_Rodata.fileSize);
	}
	
	memcpy(textPos, m_Text.data, m_Text.fileSize);
	memcpy(rodataPos, m_Rodata.data, m_Rodata.fileSize);
	memcpy(dataPos, m_Data.data, m_Data.fileSize);
}

// data relevant for CXI creation
const u8* ExefsCode::getCodeBlob()
{
	return m_CodeBlob;
}

u32 ExefsCode::getCodeBlobSize()
{
	return m_CodeBlobSize;
}

const u8* ExefsCode::getModuleIdBlob()
{
	return m_ModuleId.data;
}

u32 ExefsCode::getModuleIdBlobSize()
{
	return m_ModuleId.fileSize;
}

// data relevant for exheader
u32 ExefsCode::getTextAddress()
{
	return m_Text.address;
}

u32 ExefsCode::getTextSize()
{
	return m_Text.fileSize;
}

u32 ExefsCode::getTextPageNum()
{
	return m_Text.pageNum;
}

u32 ExefsCode::getRodataAddress()
{
	return m_Rodata.address;
}

u32 ExefsCode::getRodataSize()
{
	return m_Rodata.fileSize;
}

u32 ExefsCode::getRodataPageNum()
{
	return m_Rodata.pageNum;
}

u32 ExefsCode::getDataAddress()
{
	return m_Data.address;
}

u32 ExefsCode::getDataSize()
{
	return m_Data.fileSize;
}

u32 ExefsCode::getDataPageNum()
{
	return m_Data.pageNum;
}

u32 ExefsCode::getBssSize()
{
	return m_Data.memSize - m_Data.fileSize;
}

void ExefsCode::freeCodeBlob()
{
	if (m_CodeBlob != NULL)
	{
		free(m_CodeBlob);
		m_CodeBlob = NULL;
	}

	m_CodeBlobSize = 0;
}

void ExefsCode::initCodeSegment(struct sCodeSegment& segment)
{
	segment.data = NULL;
	segment.address = 0;
	segment.memSize = 0;
	segment.fileSize = 0;
	segment.pageNum = 0;
}


void ExefsCode::freeCodeSegment(struct sCodeSegment& segment)
{
	if (segment.data != NULL)
	{
		free(segment.data);
	}

	initCodeSegment(segment);
}

void ExefsCode::createCodeSegment(struct sCodeSegment& segment, const Elf32_Phdr& phdr, const u8 *elf)
{
	freeCodeSegment(segment);

	segment.address = le_word(phdr.p_vaddr);
	segment.fileSize = le_word(phdr.p_filesz);
	segment.memSize = le_word(phdr.p_memsz);

	segment.pageNum = sizeToPage(segment.fileSize);
	segment.data = (u8*)malloc(segment.fileSize);
	if (segment.data == NULL)
	{
		initCodeSegment(segment);
		return; // error maybe?
	}

	memcpy(segment.data, elf + le_word(phdr.p_offset), segment.fileSize);
}