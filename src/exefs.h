#pragma once
#include "types.h"
#include "ByteBuffer.h"

class Exefs
{
public:
	Exefs();
	~Exefs();

	// trigger internal exefs creation
	int createExefs();

	// add files to Exefs
	int setExefsFile(const u8 *data, u32 size, const char *name);
	
	// data extraction
	const u8* getData() const;
	u32 getDataSize() const;
	u32 getHashedDataSize() const;
	const u8* getHash() const;
private:
	static const int DEFAULT_BLOCK_SIZE = 0x200;
	static const int MAX_EXEFS_FILE_NAMELEN = 8;
	static const int MAX_EXEFS_FILE_NUM = 8;

	struct sFile
	{
		const u8 *data;
		const char *name;
		u32 size;
		u8 hash[0x20];
	};

	struct sFileEntry
	{
		char name[MAX_EXEFS_FILE_NAMELEN];
		u32 offset;
		u32 size;
	};

	struct sExefsHeader
	{
		struct sFileEntry files[MAX_EXEFS_FILE_NUM];
		u8 reserved[0x80];
		u8 fileHashes[MAX_EXEFS_FILE_NUM][0x20];
	};

	u32 m_BlockSize;

	u32 m_FileNum;
	struct sFile m_Files[MAX_EXEFS_FILE_NUM];

	ByteBuffer m_Data;
	
	u8 m_HeaderHash[0x20];
};