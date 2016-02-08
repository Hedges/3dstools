#include <cstdlib>
#include <cstdio>
#include <cstring>
#include "exefs.h"
#include "crypto.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

Exefs::Exefs() :
	m_BlockSize(DEFAULT_BLOCK_SIZE),
	m_FileNum(0)
{

}

Exefs::~Exefs()
{
}

int Exefs::createExefs()
{
	struct sExefsHeader *header;
	u32 offset;
	u32 size;

	size = sizeof(struct sExefsHeader);
	for (u32 i = 0; i < m_FileNum; i++)
	{
		size += align(m_Files[i].size, m_BlockSize);
	}

	safe_call(m_Data.alloc(size));

	header = (struct sExefsHeader*)m_Data.data();
	offset = 0;

	for (u32 i = 0; i < m_FileNum; i++)
	{
		// copy data to header
		strncpy(header->files[i].name, m_Files[i].name, MAX_EXEFS_FILE_NAMELEN);
		header->files[i].offset = le_word(offset);
		header->files[i].size = le_word(m_Files[i].size);
		memcpy(header->fileHashes[7 - i], m_Files[i].hash, 0x20);

		// copy file to exefs
		memcpy(m_Data.data() + sizeof(struct sExefsHeader) + offset, m_Files[i].data, m_Files[i].size);

		// update offset
		offset += align(m_Files[i].size, m_BlockSize);
	}

	hashSha256(m_Data.data(), sizeof(struct sExefsHeader), m_HeaderHash);

	return 0;
}

int Exefs::setExefsFile(const u8 *data, u32 size, const char *name)
{
	if (m_FileNum >= MAX_EXEFS_FILE_NUM)
	{
		die("[ERROR] Too many files for Exefs.");
	}

	// copy details
	m_Files[m_FileNum].name = name;
	m_Files[m_FileNum].data = data;
	m_Files[m_FileNum].size = size;

	// hash file
	hashSha256(m_Files[m_FileNum].data, m_Files[m_FileNum].size, m_Files[m_FileNum].hash);
	
	// increment file counter
	m_FileNum++;

	return 0;
}

const u8 * Exefs::getData() const
{
	return m_Data.dataConst();
}

u32 Exefs::getDataSize() const
{
	return m_Data.size();
}

u32 Exefs::getHashedDataSize() const
{
	return sizeof(struct sExefsHeader);
}

const u8 * Exefs::getHash() const
{
	return m_HeaderHash;
}
