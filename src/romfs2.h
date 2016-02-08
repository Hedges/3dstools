#pragma once
#include "types.h"
#include "ByteBuffer.h"
#include "Ivfc.h"
#include "romfsdirscanner.h"

class Romfs
{
public:
	Romfs();
	~Romfs();

	// trigger creating romfs (this is where the memory allocation and hashing happens)
	int createRomfs(const char *dir);
	
	// use later
	u64 getTotalSize() const;
	u32 getHashedDataSize() const;
	const u8* getHash() const;

	const u8* getIvfcHeader() const;
	u32 getIvfcHeaderSize() const;

	const u8* getIvfcLevel(u8 level) const;
	u64 getIvfcLevelSize(u8 level) const;

private:
	static const int DEFAULT_NCCH_HASH_BLOCK_SIZE = 0x200;
	static const int MAX_HEADER_SECTIONS = 4;
	static const u32 EMPTY_OFFSET = 0xffffffff;

	enum RomfsHeaderSections
	{
		ROMFS_SECTION_DIR_HASHTABLE,
		ROMFS_SECTION_DIR_TABLE,
		ROMFS_SECTION_FILE_HASHTABLE,
		ROMFS_SECTION_FILE_TABLE
	};

#pragma pack (push, 1)
	struct sRomfsHeader
	{
		u32 headerSize;
		struct sRomfsSectionGeometry
		{
			u32 offset;
			u32 size;
		} section[MAX_HEADER_SECTIONS];
		u32 dataOffset;
	};

	struct sRomfsDirEntry
	{
		u32 parentOffset;
		u32 siblingOffset;
		u32 childOffset;
		u32 fileOffset;
		u32 hashOffset;
		u32 nameSize;
	};

	struct sRomfsFileEntry
	{
		u32 parentOffset;
		u32 siblingOffset;
		u64 dataOffset;
		u64 dataSize;
		u32 hashOffset;
		u32 nameSize;
	};
#pragma pack (pop)

	struct {
		u32 dirHashNum;
		u32* dirHashTable;	

		u32 fileHashNum;
		u32* fileHashTable;

		u32 dirTablePos;
		u8* dirTable;

		u32 fileTablePos;
		u8* fileTable;

		u64 dataPos;
		u8* data;
	} m_Fs;
	
	RomfsDirScanner m_Scanner;

	Ivfc m_Ivfc; // hash tree
	ByteBuffer m_Level2; // romfs filesystem
	u64 m_Level2TrueSize;

	u32 m_HashedDataSize;
	u8 m_Hash[0x20];

	u32 getDirTableSize(const struct RomfsDirScanner::sDirectory& dir);
	u32 getFileTableSize(const struct RomfsDirScanner::sDirectory& dir);
	u64 getDataSize(const struct RomfsDirScanner::sDirectory& dir);

	int createLevel2Layout();

	void addDirToRomfs(const struct RomfsDirScanner::sDirectory& dir, u32 parent, u32 sibling);
	int addDirChildToRomfs(const struct RomfsDirScanner::sDirectory& dir, u32 parent, u32 diroff);
	int addFileToRomfs(const RomfsDirScanner::sFile & file, u32 parent, u32 sibling);

	void setupIvfcHashTree();
};