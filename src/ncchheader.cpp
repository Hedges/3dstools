#include <cstring>
#include <cmath>
#include "ncchheader.h"
#include "crypto.h"


#define NCCH_MAGIC "NCCH"

#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)


NcchHeader::NcchHeader() :
	m_ExheaderExtraSize(0)
{
	memset((u8*)&m_Header, 0, sizeof(struct sNcchHeader));
	memcpy(m_Header.magic, NCCH_MAGIC, 4);
	setBlockSize(0x200);
}

NcchHeader::~NcchHeader()
{

}

int NcchHeader::createHeader(const u8 modulus[0x100], const u8 privExponent[0x100])
{
	u8 hash[0x20];

	// If the header size is 0, the ncch layout hasn't been determined
	if (m_Header.size == 0)
	{
		finaliseNcchLayout();
	}

	// if the keys are provided, sign header
	if (modulus != NULL && privExponent != NULL)
	{
		// hash header
		hashSha256((u8*)m_Header.magic, 0x100, hash);
		// sign header
		safe_call(signRsa2048Sha256(m_Header.signature, hash, modulus, privExponent));
	} 
	// otherwise clear signature
	else
	{
		memset(m_Header.signature, 0xFF, 0x100);
	}

	return 0;
}

const u8 * NcchHeader::getHeader() const
{
	return (const u8*)&m_Header;
}

u32 NcchHeader::getHeaderSize() const
{
	return sizeof(struct sNcchHeader);
}

// Basic Data
void NcchHeader::setTitleId(u64 titleId)
{
	m_Header.titleId = le_dword(titleId);
}

void NcchHeader::setProgramId(u64 programId)
{
	m_Header.programId = le_dword(programId);
}

void NcchHeader::setMakerCode(const char *makerCode)
{
	memset(m_Header.makerCode, 0, 2);
	strncpy(m_Header.makerCode, makerCode, 2);
}

void NcchHeader::setProductCode(const char *productCode)
{
	memset(m_Header.productCode, 0, 0x10);
	strncpy(m_Header.productCode, productCode, 0x10);
}

// Flags
void NcchHeader::setNcchType(NcchHeader::ContentType contentType, NcchHeader::FormType formType)
{
	m_Header.flags.contentType = ((formType&3) | (contentType << 2));
	if (formType == EXECUTABLE_WITHOUT_ROMFS || formType == UNASSIGNED)
	{
		m_Header.flags.otherFlag |= NO_MOUNT_ROMFS;
	}

	if (formType == EXECUTABLE_WITHOUT_ROMFS || formType == EXECUTABLE)
	{
		m_Header.formatVersion = 2;
	} else 
	{
		m_Header.formatVersion = 0;
	}
}

void NcchHeader::setPlatform(NcchHeader::Platform platform)
{
	m_Header.flags.platform = platform;
}

void NcchHeader::setBlockSize(u32 size)
{
	m_Header.flags.blockSize = log2l(size) - 9;
}

void NcchHeader::setNoCrypto()
{
	m_Header.flags.otherFlag &= ~(NO_AES|FIXED_AES_KEY|SEED_KEY);
	m_Header.flags.otherFlag |= NO_AES;
}

void NcchHeader::setFixedAesKey()
{
	m_Header.flags.otherFlag &= ~(NO_AES|FIXED_AES_KEY|SEED_KEY);
	m_Header.flags.otherFlag |= FIXED_AES_KEY;
}

void NcchHeader::setSecureAesKey(u8 keyXindex)
{
	m_Header.flags.otherFlag &= ~(NO_AES|FIXED_AES_KEY);
	m_Header.flags.keyXindex = keyXindex;
}

// Data segments
void NcchHeader::setExheaderData(u32 size, u32 additionalSize, const u8 *hash)
{
	m_Header.exhdrSize = le_word(size);
	m_ExheaderExtraSize = additionalSize;
	memcpy(m_Header.exhdrHash, hash, 0x20);
}

void NcchHeader::setPlainRegionData(u32 size)
{
	m_Header.plainRegion.size = le_word(toBlockSize(size));
}

void NcchHeader::setLogoData(u32 size, const u8 *hash)
{
	m_Header.logo.size = le_word(toBlockSize(size));
	memcpy(m_Header.logoHash, hash, 0x20);
}

void NcchHeader::setExefsData(u32 size, u32 hashedDataSize, const u8 *hash)
{
	m_Header.exefs.size = le_word(toBlockSize(size));
	m_Header.exefsHashedDataSize = le_word(toBlockSize(hashedDataSize));
	memcpy(m_Header.exefsHash, hash, 0x20);
}

void NcchHeader::setRomfsData(u32 size, u32 hashedDataSize, const u8 *hash)
{
	m_Header.romfs.size = le_word(toBlockSize(size));
	m_Header.romfsHashedDataSize = le_word(toBlockSize(hashedDataSize));
	memcpy(m_Header.romfsHash, hash, 0x20);
}

void NcchHeader::finaliseNcchLayout()
{
	u32 size = toBlockSize(sizeof(struct sNcchHeader));
	
	// exheader
	if (le_word(m_Header.exhdrSize))
	{
		size += toBlockSize(le_word(m_Header.exhdrSize) + m_ExheaderExtraSize);
	}

	// logo
	if (le_word(m_Header.logo.size))
	{
		m_Header.logo.offset = le_word(size);
		size += le_word(m_Header.logo.size);
	}

	// plain region
	if (le_word(m_Header.plainRegion.size))
	{
		m_Header.plainRegion.offset = le_word(size);
		size += le_word(m_Header.plainRegion.size);
	}

	// exefs region
	if (le_word(m_Header.exefs.size))
	{
		m_Header.exefs.offset = le_word(size);
		size += le_word(m_Header.exefs.size);
	}

	// exefs region
	if (le_word(m_Header.romfs.size))
	{
		size = toBlockSize(align(size*getBlockSize(), 0x1000));
		m_Header.romfs.offset = le_word(size);
		size += le_word(m_Header.romfs.size);
	}

	m_Header.size = le_word(size);
}

// Get data from header
u32 NcchHeader::getNcchSize() const
{
	return le_word(m_Header.size) * getBlockSize();
}

u32 NcchHeader::getExheaderOffset() const
{
	return le_word(m_Header.exhdrSize)? sizeof(struct sNcchHeader) : 0;
}

u32 NcchHeader::getPlainRegionOffset() const
{
	return le_word(m_Header.plainRegion.offset) * getBlockSize();
}

u32 NcchHeader::getLogoOffset() const
{
	return le_word(m_Header.logo.offset) * getBlockSize();
}

u32 NcchHeader::getExefsOffset() const
{
	return le_word(m_Header.exefs.offset) * getBlockSize();
}

u32 NcchHeader::getRomfsOffset() const
{
	return le_word(m_Header.romfs.offset) * getBlockSize();
}

u32 NcchHeader::getBlockSize() const
{
	return 1 << (m_Header.flags.blockSize + 9);
}

u32 NcchHeader::toBlockSize(u32 size) const
{
	return align(size, getBlockSize()) / getBlockSize();
}