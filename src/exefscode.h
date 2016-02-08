#pragma once
#include "types.h"
#include "elf.h"

class ExefsCode
{
public:
	ExefsCode();
	~ExefsCode();

	int parseElf(const u8 *elf);

	// internally generate code blob
	// code blobs are normally page aligned, except in builtin sysmodules
	void createCodeBlob(bool pageAligned);

	// data relevant for CXI creation
	const u8* getCodeBlob();
	u32 getCodeBlobSize();
	const u8* getModuleIdBlob();
	u32 getModuleIdBlobSize();

	// data relevant for exheader
	u32 getTextAddress();
	u32 getTextSize();
	u32 getTextPageNum();

	u32 getRodataAddress();
	u32 getRodataSize();
	u32 getRodataPageNum();

	u32 getDataAddress();
	u32 getDataSize();
	u32 getDataPageNum();

	u32 getBssSize();
private:
	static const int CODE_PAGE_SIZE = 0x1000;

	struct sCodeSegment
	{
		u32 address;
		u32 memSize;
		u32 fileSize;
		u32 pageNum;
		u8 *data;
	};

	u8 *m_CodeBlob;
	u32 m_CodeBlobSize;

	struct sCodeSegment m_Text;
	struct sCodeSegment m_Rodata;
	struct sCodeSegment m_Data;
	struct sCodeSegment m_ModuleId;

	void freeCodeBlob();
	
	void initCodeSegment(struct sCodeSegment& segment);
	void freeCodeSegment(struct sCodeSegment& segment);
	void createCodeSegment(struct sCodeSegment& segment, const Elf32_Phdr& phdr, const u8 *elf);

	inline u32 sizeToPage(u32 size)
	{
		return align(size, CODE_PAGE_SIZE) / CODE_PAGE_SIZE;
	}

	inline u32 pageToSize(u32 pageNum)
	{
		return pageNum * CODE_PAGE_SIZE;
	}
};