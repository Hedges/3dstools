#pragma once
#include "types.h"

class NcchHeader
{
public:
	enum FormType
	{
		UNASSIGNED,
		SIMPLE_CONTENT,
		EXECUTABLE_WITHOUT_ROMFS,
		EXECUTABLE
	};

	enum ContentType
	{
		APPLICATION,
		SYSTEM_UPDATE,
		MANUAL,
		CHILD,
		TRIAL,
		EXTENDED_SYSTEM_UPDATE
	};

	enum Platform
	{
		CTR = 1,
		SNAKE = 2
	};

	NcchHeader();
	~NcchHeader();

	// create + sign header
	int createHeader(const u8 modulus[0x100], const u8 privExponent[0x100]);
	const u8* getHeader() const;
	u32 getHeaderSize() const;

	// Basic Data
	void setTitleId(u64 titleId);
	void setProgramId(u64 programId);
	void setMakerCode(const char *makerCode);
	void setProductCode(const char *productCode);
	
	// Flags
	void setNcchType(ContentType contentType, FormType formType);
	void setPlatform(Platform platorm);
	void setBlockSize(u32 size);
	void setNoCrypto();
	void setFixedAesKey();
	void setSecureAesKey(u8 keyXindex);

	// Data segments
	void setExheaderData(u32 size, u32 additionalSize, const u8 *hash);
	void setPlainRegionData(u32 size);
	void setLogoData(u32 size, const u8 *hash);
	void setExefsData(u32 size, u32 hashedDataSize, const u8 *hash);
	void setRomfsData(u32 size, u32 hashedDataSize, const u8 *hash);
	void finaliseNcchLayout();

	// Get data from header
	u32 getNcchSize() const;
	u32 getExheaderOffset() const;
	u32 getPlainRegionOffset() const;
	u32 getLogoOffset() const;
	u32 getExefsOffset() const;
	u32 getRomfsOffset() const;

private:
	enum OtherFlag
	{
		FIXED_AES_KEY = BIT(0),
		NO_MOUNT_ROMFS = BIT(1),
		NO_AES = BIT(2),
		SEED_KEY = BIT(5)
	};

	struct sSectionGeometry
	{
		u32 offset;
		u32 size;
	};

	struct sNcchHeader
	{
		u8 signature[0x100];
		char magic[4];
		u32 size;
		u64 titleId;
		char makerCode[2];
		u16 formatVersion;
		u32 seedCheck;
		u64 programId;
		u8 reserved1[0x10];
		u8 logoHash[0x20];
		char productCode[0x10];
		u8 exhdrHash[0x20];
		u32 exhdrSize;
		u8 reserved2[0x4];
		struct sFlags
		{
			u8 reserved[3];
			u8 keyXindex;
			u8 platform;
			u8 contentType;
			u8 blockSize;
			u8 otherFlag;
		} flags;
		struct sSectionGeometry plainRegion;
		struct sSectionGeometry logo;
		struct sSectionGeometry exefs;
		u32 exefsHashedDataSize;
		u8 reserved3[4];
		struct sSectionGeometry romfs;
		u32 romfsHashedDataSize;
		u8 reserved4[4];
		u8 exefsHash[0x20];
		u8 romfsHash[0x20];
		
	};

	struct sNcchHeader m_Header;
	u32 m_ExheaderExtraSize;

	u32 getBlockSize() const;
	u32 toBlockSize(u32 size) const;
};

