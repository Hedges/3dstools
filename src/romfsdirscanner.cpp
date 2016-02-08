#include <cstdlib>
#include "romfsdirscanner.h"

#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

RomfsDirScanner::RomfsDirScanner()
{
	initDirectory(m_Root);
}

RomfsDirScanner::~RomfsDirScanner()
{
	freeDirectory(m_Root);
}

int RomfsDirScanner::openDir(const char *root)
{
	static const utf16char_t EMPTY_PATH[1] = { '\0' };
	m_Root.path = os_CopyConvertCharStr(root);
	m_Root.name = utf16_CopyStr(EMPTY_PATH);
	m_Root.namesize = 0;

	return populateDir(m_Root);
}

struct RomfsDirScanner::sDirectory const & RomfsDirScanner::getDir() const
{
	return m_Root;
}

u32 RomfsDirScanner::getDirNum(const struct RomfsDirScanner::sDirectory& dir)
{
	u32 num = 0;

	num = dir.child.size();

	for (size_t i = 0; i < dir.child.size(); i++)
	{
		num += getDirNum(dir.child[i]);
	}

	return num;
}

u32 RomfsDirScanner::getFileNum(const struct RomfsDirScanner::sDirectory& dir)
{
	u32 num = 0;

	num = dir.file.size();

	for (size_t i = 0; i < dir.child.size(); i++)
	{
		num += getFileNum(dir.child[i]);
	}

	return num;
}

u64 RomfsDirScanner::getDirFileSize(const struct RomfsDirScanner::sDirectory& dir)
{
	u64 size = 0;
	for (size_t i = 0; i < dir.child.size(); i++)
	{
		size += getDirFileSize(dir.child[i]);
	}
	for (size_t i = 0; i < dir.file.size(); i++)
	{
		size += dir.file[i].size;
	}
	return size;
}

void RomfsDirScanner::initDirectory(struct RomfsDirScanner::sDirectory& dir)
{
	dir.path = NULL;
	dir.name = NULL;
	dir.namesize = 0;
	dir.child.clear();
	dir.file.clear();
}

void RomfsDirScanner::freeDirectory(struct RomfsDirScanner::sDirectory& dir)
{
	// free memory allocations
	if (dir.path)
	{
		free(dir.path);
	}
	if (dir.name)
	{
		free(dir.name);
	}

	// free child dirs
	for (size_t i = 0; i < dir.child.size(); i++)
	{
		freeDirectory(dir.child[i]);
	}

	// free files
	for (size_t i = 0; i < dir.file.size(); i++)
	{
		if (dir.file[i].path)
		{
			free(dir.file[i].path);
		}

		if (dir.file[i].name)
		{
			free(dir.file[i].name);
		}

		dir.file[i].path = NULL;
		dir.file[i].name = NULL;
		dir.file[i].namesize = 0;
		dir.file[i].size = 0;
	}

	// clear this directory
	initDirectory(dir);
}

int RomfsDirScanner::populateDir(struct RomfsDirScanner::sDirectory& dir)
{
	_OSDIR *dp;
	struct _osstat st;
	struct _osdirent *entry;

	// Open Directory
	if ((dp = os_opendir(dir.path)) == NULL)
	{
		printf("[ERROR] Failed to open directory: \"");
		os_fputs(dir.path, stdout);
		printf("\"\n");
		return 1;
	}

	// Process Entries
	while ((entry = os_readdir(dp)) != NULL)
	{
		// Skip hidden files and directories (starting with ".")
		if (entry->d_name[0] == (oschar_t)'.')
			continue;

		// Get native FS path
		oschar_t *path = os_AppendToPath(dir.path, entry->d_name);

		// Opening directory with fs path to test if directory
		if (os_stat(path, &st) == 0 && S_IFDIR&st.st_mode) {
			struct sDirectory child;
			child.path = path;
			child.name = utf16_CopyConvertOsStr(entry->d_name);
			child.namesize = utf16_strlen(child.name)*sizeof(utf16char_t);

			// populate child
			populateDir(child);

			// add to parent struct
			dir.child.push_back(child);
		}
		// Otherwise this is a file
		else {
			struct sFile file;
			file.path = path;
			file.name = utf16_CopyConvertOsStr(entry->d_name);
			file.namesize = utf16_strlen(file.name)*sizeof(utf16char_t);
			file.size = os_fsize(path);
			dir.file.push_back(file);
		}
	}

	os_closedir(dp);

	return 0;
}