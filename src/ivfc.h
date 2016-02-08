#pragma once
#include "types.h"
#include "ByteBuffer.h"
#include <vector>

class Ivfc
{
public:
	static const int IVFC_BLOCK_SIZE = 0x1000;

	Ivfc();
	~Ivfc();

	int createIvfcHashTree();

	const u8* getIvfcLevel(u8 level) const;
	u64 getIvfcLevelSize(u8 level) const;
	const u8* getIvfcHeader() const;
	u32 getIvfcHeaderSize() const;
	u32 getIvfcUsedHeaderSize() const;

	void processDataBlock(const u8* block);
	void setLevel2Size(u64 size);
private:
	static const int IVFC_HASH_SIZE = 0x20;
	static const int IVFC_LEVEL_NUM = 3;
	static const u32 IVFC_TYPE_ROMFS = 0x10000;

#pragma pack (push, 1)
	struct sIvfcHeader
	{
		char magic[4];
		u32 type;
		u32 masterHashSize;
		struct sIvfcLevelHeader
		{
			u64 logicalOffset;
			u64 size;
			u32 blockSize;
			u8 reserved[4];
		} level[IVFC_LEVEL_NUM];
		u32 optionalSize;
		u8 reserved0[4];
	};
#pragma pack (pop)

	struct sHash
	{
		u8 data[IVFC_HASH_SIZE];
	};

	std::vector<struct sHash> m_DataHashes;

	ByteBuffer m_Level[IVFC_LEVEL_NUM-1];
	u64 m_Level2TrueSize;

	ByteBuffer m_Header;
};

