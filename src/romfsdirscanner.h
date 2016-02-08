#pragma once
#include <vector>
#include "oschar.h"
#include "types.h"

class RomfsDirScanner
{
public:
	struct sFile
	{
		oschar_t *path;
		utf16char_t *name;
		u32 namesize;
		u64 size;
	};

	struct sDirectory
	{
		oschar_t *path;
		utf16char_t *name;
		u32 namesize;

		std::vector<struct sDirectory> child;
		std::vector<struct sFile> file;
	};

	RomfsDirScanner();
	~RomfsDirScanner();

	int openDir(const char *root);

	struct sDirectory const & getDir() const;
	u32 getDirNum(const struct sDirectory& dir);
	u32 getFileNum(const struct sDirectory& dir);
	u64 getDirFileSize(const struct sDirectory& dir);

private:
	struct sDirectory m_Root;

	void initDirectory(struct sDirectory& dir);
	void freeDirectory(struct sDirectory& dir);
	int populateDir(struct sDirectory& dir);
};