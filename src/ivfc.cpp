#include <cmath>
#include "ivfc.h"
#include "crypto.h"

#define IVFC_MAGIC "IVFC"

#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

Ivfc::Ivfc()
{
}

Ivfc::~Ivfc()
{
}

int Ivfc::createIvfcHashTree()
{
	struct sIvfcHeader hdr;
	memset((u8*)&hdr, 0, sizeof(struct sIvfcHeader));

	memcpy(hdr.magic, IVFC_MAGIC, 4);
	hdr.type = le_word(IVFC_TYPE_ROMFS);

	// set data level size
	hdr.level[2].size = le_dword(m_Level2TrueSize);
	hdr.level[2].blockSize = le_word(log2l(IVFC_BLOCK_SIZE));
	hdr.level[1].size = le_dword((align(le_dword(hdr.level[2].size), IVFC_BLOCK_SIZE) / IVFC_BLOCK_SIZE) * IVFC_HASH_SIZE);
	hdr.level[1].blockSize = le_word(log2l(IVFC_BLOCK_SIZE));
	hdr.level[0].size = le_dword((align(le_dword(hdr.level[1].size), IVFC_BLOCK_SIZE) / IVFC_BLOCK_SIZE) * IVFC_HASH_SIZE);
	hdr.level[0].blockSize = le_word(log2l(IVFC_BLOCK_SIZE));

	// set "logical" offsets
	hdr.level[0].logicalOffset = 0;
	for (int i = 1; i < IVFC_LEVEL_NUM; i++)
	{
		hdr.level[i].logicalOffset = le_dword(align(le_dword(hdr.level[i - 1].logicalOffset) + le_dword(hdr.level[i - 1].size), IVFC_BLOCK_SIZE));
	}

	// set master hash size & optional size
	hdr.masterHashSize = le_word((align(le_dword(hdr.level[0].size), IVFC_BLOCK_SIZE) / IVFC_BLOCK_SIZE) * IVFC_HASH_SIZE);
	hdr.optionalSize = le_word(sizeof(struct sIvfcHeader));
	
	// allocate memory for each hash level & the header
	safe_call(m_Level[1].alloc(le_dword((align(hdr.level[1].size, IVFC_BLOCK_SIZE)))));
	safe_call(m_Level[0].alloc(le_dword((align(hdr.level[0].size, IVFC_BLOCK_SIZE)))));
	safe_call(m_Header.alloc(align(align(sizeof(struct sIvfcHeader),0x10) + le_dword(hdr.masterHashSize), IVFC_BLOCK_SIZE)));

	// copy hashes into level 1
	for (size_t i = 0; i < m_DataHashes.size(); i++)
	{
		memcpy(m_Level[1].data() + IVFC_HASH_SIZE*i, m_DataHashes[i].data, IVFC_HASH_SIZE);
	}

	// create level 0 hashes from level 1
	for (size_t i = 0; i < (m_Level[1].size() / IVFC_BLOCK_SIZE); i++)
	{
		hashSha256(m_Level[1].data() + IVFC_BLOCK_SIZE*i, IVFC_BLOCK_SIZE, m_Level[0].data() + IVFC_HASH_SIZE*i);
	}

	// create master hashes from level 0
	for (size_t i = 0; i < (m_Level[2].size() / IVFC_BLOCK_SIZE); i++)
	{
		hashSha256(m_Level[0].data() + IVFC_BLOCK_SIZE*i, IVFC_BLOCK_SIZE, m_Header.data() + align(sizeof(struct sIvfcHeader), 0x10) + IVFC_HASH_SIZE*i);
	}

	// copy header into header buffer
	memcpy(m_Header.data(), (u8*)&hdr, sizeof(struct sIvfcHeader));

	return 0;
}

const u8 * Ivfc::getIvfcLevel(u8 level) const
{
	if (level >= IVFC_LEVEL_NUM-1)
	{
		return NULL;
	}

	return m_Level[level].dataConst();
}

u64 Ivfc::getIvfcLevelSize(u8 level) const
{
	if (level >= IVFC_LEVEL_NUM-1)
	{
		return 0;
	}

	return m_Level[level].size();
}

const u8 * Ivfc::getIvfcHeader() const
{
	return m_Header.dataConst();
}

u32 Ivfc::getIvfcHeaderSize() const
{
	return m_Header.size();
}

u32 Ivfc::getIvfcUsedHeaderSize() const
{
	return sizeof(struct sIvfcHeader) + (m_Level[0].size() / IVFC_BLOCK_SIZE) * IVFC_HASH_SIZE;
}

void Ivfc::processDataBlock(const u8 *block)
{
	struct sHash hash;
	hashSha256(block, IVFC_BLOCK_SIZE, hash.data);
	m_DataHashes.push_back(hash);
}

void Ivfc::setLevel2Size(u64 size)
{
	m_Level2TrueSize = size;
}
