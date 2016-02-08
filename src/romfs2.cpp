#include "romfs2.h"
#include "crypto.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

// Apparently this is Nintendo's version of "Smallest prime >= the input"
static u32 calcHashTableLen(u32 entryCount)
{
#define D(a) (count % (a) == 0)
	u32 count = entryCount;
	if (count < 3) count = 3;
	else if (count < 19) count |= 1;
	else while (D(2) || D(3) || D(5) || D(7) || D(11) || D(13) || D(17)) count++;
	return count;
#undef D
}

static u32 calcHash(u32 parent, const utf16char_t *str, u32 total)
{
	u32 len = utf16_strlen(str);
	u32 hash = parent ^ 123456789;
	for (u32 i = 0; i < len; i++)
	{
		hash = (u32)((hash >> 5) | (hash << 27));
		hash ^= (u16)str[i];
	}
	return hash % total;
}

u32 CalcPathHash(u32 parent, const utf16char_t* path)
{
	u32 len = utf16_strlen(path);
	u32 hash = parent ^ 123456789;
	for (u32 i = 0; i < len; i++)
	{
		hash = (u32)((hash >> 5) | (hash << 27));//ror
		hash ^= (u16)path[i];
	}
	return hash;
}


Romfs::Romfs() :
	m_HashedDataSize(0)
{
	memset(m_Hash, 0, sizeof(m_Hash));
}

Romfs::~Romfs()
{
}

int Romfs::createRomfs(const char * dir)
{
	// scan directory
	safe_call(m_Scanner.openDir(dir));

	// return if there's nothing in the directory
	if (m_Scanner.getDirNum(m_Scanner.getDir()) == 0 && m_Scanner.getFileNum(m_Scanner.getDir()) == 0)
		return 0;

	// allocate memory for ivfc level2 (romfs)
	safe_call(createLevel2Layout());

	// fill the romfs
	addDirToRomfs(m_Scanner.getDir(), 0, EMPTY_OFFSET);
	safe_call(addDirChildToRomfs(m_Scanner.getDir(), 0, 0));

	// create Ivfc
	setupIvfcHashTree();
	safe_call(m_Ivfc.createIvfcHashTree());

	// hash 
	m_HashedDataSize = align(m_Ivfc.getIvfcUsedHeaderSize(), DEFAULT_NCCH_HASH_BLOCK_SIZE);
	hashSha256(m_Ivfc.getIvfcHeader(), m_HashedDataSize, m_Hash);

	return 0;
}

u64 Romfs::getTotalSize() const
{
	return m_Ivfc.getIvfcHeaderSize() + m_Ivfc.getIvfcLevelSize(0) + m_Ivfc.getIvfcLevelSize(1) + m_Level2.size();
}

u32 Romfs::getHashedDataSize() const
{
	return m_HashedDataSize;
}

const u8 * Romfs::getHash() const
{
	return m_Hash;
}

const u8 * Romfs::getIvfcHeader() const
{
	return m_Ivfc.getIvfcHeader();
}

u32 Romfs::getIvfcHeaderSize() const
{
	return m_Ivfc.getIvfcHeaderSize();
}

const u8 * Romfs::getIvfcLevel(u8 level) const
{
	if (level < 2)
		return m_Ivfc.getIvfcLevel(level);
	if (level == 2)
		return m_Level2.dataConst();

	return NULL;
}

u64 Romfs::getIvfcLevelSize(u8 level) const
{
	if (level < 2)
		return m_Ivfc.getIvfcLevelSize(level);
	if (level == 2)
		return m_Level2.size();

	return 0;
}

u32 Romfs::getDirTableSize(const RomfsDirScanner::sDirectory & dir)
{
	u32 size = sizeof(struct sRomfsDirEntry) + align(dir.namesize, 4);
	for (size_t i = 0; i < dir.child.size(); i++)
	{
		size += getDirTableSize(dir.child[i]);
	}

	return size;
}

u32 Romfs::getFileTableSize(const RomfsDirScanner::sDirectory & dir)
{
	u32 size = 0;
	for (size_t i = 0; i < dir.file.size(); i++)
	{
		size += sizeof(struct sRomfsFileEntry) + align(dir.file[i].namesize, 4);
	}

	for (size_t i = 0; i < dir.child.size(); i++)
	{
		size += getFileTableSize(dir.child[i]);
	}

	return size;
}

u64 Romfs::getDataSize(const RomfsDirScanner::sDirectory & dir)
{
	u64 size = 0;
	for (size_t i = 0; i < dir.file.size(); i++)
	{
		size = align(size, 0x10) + dir.file[i].size;
	}

	for (size_t i = 0; i < dir.child.size(); i++)
	{
		size += getDataSize(dir.child[i]);
	}

	return size;
}

int Romfs::createLevel2Layout()
{
	// get sizes
	m_Fs.dirHashNum = calcHashTableLen(m_Scanner.getDirNum(m_Scanner.getDir()) + 1);
	m_Fs.fileHashNum = calcHashTableLen(m_Scanner.getFileNum(m_Scanner.getDir()));
	u32 dirHashTableSize, dirTableSize, fileHashTableSize, fileTableSize;
	dirHashTableSize = (m_Fs.dirHashNum) * sizeof(u32);
	fileHashTableSize = (m_Fs.fileHashNum) * sizeof(u32);
	dirTableSize = getDirTableSize(m_Scanner.getDir());
	fileTableSize = getFileTableSize(m_Scanner.getDir());

	u32 headerSize = align(\
		sizeof(struct sRomfsHeader) \
		+ dirHashTableSize \
		+ dirTableSize \
		+ fileHashTableSize \
		+ fileTableSize \
		, 0x10);

	u64 dataSize = getDataSize(m_Scanner.getDir());

	m_Level2TrueSize = headerSize + dataSize;

	// allocate memory
	safe_call(m_Level2.alloc(align(m_Level2TrueSize, Ivfc::IVFC_BLOCK_SIZE)));

	// set header
	struct sRomfsHeader* hdr = (struct sRomfsHeader*)m_Level2.data();
	hdr->headerSize = le_word(sizeof(struct sRomfsHeader));
	hdr->dataOffset = le_word(headerSize);

	u32 offset = sizeof(struct sRomfsHeader);
	for (size_t i = 0; i < MAX_HEADER_SECTIONS; i++)
	{
		switch (i)
		{
		case(ROMFS_SECTION_DIR_HASHTABLE) :
		{
			hdr->section[i].size = le_word(dirHashTableSize);
			m_Fs.dirHashTable = (u32*)(m_Level2.data() + offset);
			break;
		}
		case(ROMFS_SECTION_DIR_TABLE) :
		{
			hdr->section[i].size = le_word(dirTableSize);
			m_Fs.dirTable = (m_Level2.data() + offset);
			m_Fs.dirTablePos = 0;
			break;
		}
		case(ROMFS_SECTION_FILE_HASHTABLE) :
		{
			hdr->section[i].size = le_word(fileHashTableSize);
			m_Fs.fileHashTable = (u32*)(m_Level2.data() + offset);
			break;
		}
		case(ROMFS_SECTION_FILE_TABLE) :
		{
			hdr->section[i].size = le_word(fileTableSize);
			m_Fs.fileTable = (m_Level2.data() + offset);
			m_Fs.fileTablePos = 0;
			break;
		}
		}
		hdr->section[i].offset = le_word(offset);
		offset += le_word(hdr->section[i].size);
	}

	m_Fs.data = m_Level2.data() + headerSize;
	m_Fs.dataPos = 0;

	// set initial state for the hash tables
	for (u32 i = 0; i < m_Fs.dirHashNum; i++)
	{
		m_Fs.dirHashTable[i] = le_word(EMPTY_OFFSET);
	}
	for (u32 i = 0; i < m_Fs.fileHashNum; i++)
	{
		m_Fs.fileHashTable[i] = le_word(EMPTY_OFFSET);
	}

	

	return 0;
}

void Romfs::addDirToRomfs(const RomfsDirScanner::sDirectory & dir, u32 parent, u32 sibling)
{
	struct sRomfsDirEntry *entry = (struct sRomfsDirEntry*)(m_Fs.dirTable + m_Fs.dirTablePos);
	utf16char_t *name = (utf16char_t*)(m_Fs.dirTable + m_Fs.dirTablePos + sizeof(struct sRomfsDirEntry));

	entry->parentOffset = le_word(parent);
	entry->siblingOffset = le_word(sibling);
	entry->childOffset = le_word(EMPTY_OFFSET);
	entry->fileOffset = le_word(EMPTY_OFFSET);

	u32 hash = calcHash(parent, dir.name, m_Fs.dirHashNum);
	entry->hashOffset = m_Fs.dirHashTable[hash];
	m_Fs.dirHashTable[hash] = le_word(m_Fs.dirTablePos);

	entry->nameSize = le_dword(dir.namesize);
	for (u32 i = 0; i < dir.namesize / sizeof(utf16char_t); i++)
	{
		name[i] = le_hword(dir.name[i]);
	}

	m_Fs.dirTablePos += (sizeof(struct sRomfsDirEntry) + align(dir.namesize, 4));
}

int Romfs::addDirChildToRomfs(const RomfsDirScanner::sDirectory & dir, u32 parent, u32 diroff)
{
	struct sRomfsDirEntry *entry = (struct sRomfsDirEntry*)(m_Fs.dirTable + diroff);
	
	if (dir.file.size())
	{
		u32 sibling;
		entry->fileOffset = le_word(m_Fs.fileTablePos);
		for (size_t i = 0; i < dir.file.size(); i++)
		{
			sibling = (i == dir.file.size() - 1) ? EMPTY_OFFSET : (m_Fs.fileTablePos + sizeof(struct sRomfsFileEntry) + align(dir.file[i].namesize, 4));
			safe_call(addFileToRomfs(dir.file[i], diroff, sibling));
		}
	}
	
	if (dir.child.size())
	{
		u32 sibling;
		std::vector<u32> child;
		entry->childOffset = le_word(m_Fs.dirTablePos);
		for (size_t i = 0; i < dir.child.size(); i++)
		{
			/* Store address for child */
			child.push_back(m_Fs.dirTablePos);

			/* If is the last child directory, no more siblings  */
			sibling = (i == dir.file.size() - 1) ? EMPTY_OFFSET : (m_Fs.dirTablePos + sizeof(struct sRomfsDirEntry) + align(dir.child[i].namesize, 4));
		
			/* Create child directory entry */
			addDirToRomfs(dir.child[i], diroff, sibling);
		}

		/* Populate child's childs */
		for (size_t i = 0; i < dir.child.size(); i++)
		{
			safe_call(addDirChildToRomfs(dir.child[i], diroff, child[i]));
		}
	}

	return 0;
}

int Romfs::addFileToRomfs(const RomfsDirScanner::sFile & file, u32 parent, u32 sibling)
{
	struct sRomfsFileEntry *entry = (struct sRomfsFileEntry*)(m_Fs.fileTable + m_Fs.fileTablePos);
	utf16char_t *name = (utf16char_t*)(m_Fs.fileTable + m_Fs.fileTablePos + sizeof(struct sRomfsFileEntry));

	entry->parentOffset = le_word(parent);
	entry->siblingOffset = le_word(sibling);
	entry->dataOffset = le_dword(0);
	entry->dataSize = le_dword(file.size);

	u32 hash = calcHash(parent, file.name, m_Fs.fileHashNum);
	entry->hashOffset = m_Fs.fileHashTable[hash];
	m_Fs.fileHashTable[hash] = le_word(m_Fs.fileTablePos);

	entry->nameSize = le_dword(file.namesize);
	for (u32 i = 0; i < file.namesize / sizeof(utf16char_t); i++)
	{
		name[i] = le_hword(file.name[i]);
	}
	
	if (file.size)
	{
		FILE *fp = os_fopen(file.path, OS_MODE_READ);
		if (!fp)
		{
			fprintf(stderr, "[ERROR] Failed to open file for romfs: ");
			os_fputs(file.path, stderr);
			fputs("\n", stderr);
			return 1;
		}

		// align data pos to 0x10 bytes
		m_Fs.dataPos = align(m_Fs.dataPos, 0x10);
		entry->dataOffset = le_dword(m_Fs.dataPos);

		fread(m_Fs.data + m_Fs.dataPos, 1, file.size, fp);
		fclose(fp);
	}

	m_Fs.dataPos += file.size;
	m_Fs.fileTablePos += (sizeof(struct sRomfsFileEntry) + align(file.namesize, 4));

	return 0;
}

void Romfs::setupIvfcHashTree()
{
	size_t blockNum = m_Level2.size() / Ivfc::IVFC_BLOCK_SIZE;
	for (size_t i = 0; i < blockNum; i++)
	{
		m_Ivfc.processDataBlock(m_Level2.dataConst() + Ivfc::IVFC_BLOCK_SIZE*i);
	}
	m_Ivfc.setLevel2Size(m_Level2TrueSize);
}
