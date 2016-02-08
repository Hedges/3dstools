#include <cstdlib>
#include <cstring>
#include "ncchextendedheader.h"
#include "crypto.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

ExtendedHeader::ExtendedHeader()
{
	memset((u8*)&m_ExheaderHash, 0, 0x20);
	memset((u8*)&m_Header, 0, sizeof(struct sExtendedHeader));
	memset((u8*)&m_AccessDesc, 0, sizeof(struct sAccessDescriptor));
}

ExtendedHeader::~ExtendedHeader()
{

}

int ExtendedHeader::createExheader()
{
	safe_call(commitArm11KernelCapabilities());

	hashSha256((u8*)&m_Header, sizeof(struct sExtendedHeader), m_ExheaderHash);

	return 0;
}

// accessdesc needs to be signed
int ExtendedHeader::createAccessDesc(const u8 ncchRsaModulus[0x100], const u8 modulus[0x100], const u8 privExponent[0x100])
{
	u8 hash[0x20];

	// Copy NCCH Modulus
	if (ncchRsaModulus)
	{
		memcpy(m_AccessDesc.ncchRsaModulus, ncchRsaModulus, 0x100);
	}
	else
	{
		memset(m_AccessDesc.ncchRsaModulus, 0xFF, 0x100);
	}

	// copy exheader data
	memcpy((u8*)&m_AccessDesc.arm11Local, (u8*)&m_Header.arm11Local, sizeof(struct sArm11LocalCapabilities));
	memcpy((u8*)&m_AccessDesc.arm11Kernel, (u8*)&m_Header.arm11Kernel, sizeof(struct sArm11KernelCapabilities));
	memcpy((u8*)&m_AccessDesc.arm9, (u8*)&m_Header.arm9, sizeof(struct sArm9AccessControl));

	// modify data
	m_AccessDesc.arm11Local.idealProcessor = 1 << m_AccessDesc.arm11Local.idealProcessor;
	m_AccessDesc.arm11Local.threadPriority = 0; // thread priority cannot be lower than in accessdesc

	// sign data
	if (modulus != NULL && privExponent != NULL)
	{
		hashSha256((u8*)&m_AccessDesc.ncchRsaModulus, 0x300, hash);
		safe_call(signRsa2048Sha256(m_AccessDesc.signature, hash, modulus, privExponent));
	}
	else
	{
		memset(m_AccessDesc.signature, 0xFF, 0x100);
	}

	return 0;
}

const u8 * ExtendedHeader::getExheader() const
{
	return (const u8*)&m_Header;
}

u32 ExtendedHeader::getExheaderSize() const
{
	return sizeof(struct sExtendedHeader);
}

const u8 * ExtendedHeader::getExheaderHash() const
{
	return m_ExheaderHash;
}

const u8 * ExtendedHeader::getAccessDesc() const
{
	return (const u8*)&m_AccessDesc;
}

u32 ExtendedHeader::getAccessDescSize() const
{
	return sizeof(struct sAccessDescriptor);
}

// Set Process Info
void ExtendedHeader::setProcessName(const char *name)
{
	memset(m_Header.processInfo.name, 0, 8);
	strncpy(m_Header.processInfo.name, name, 8);
}

void ExtendedHeader::setIsCodeCompressed(bool isCodeCompressed)
{
	m_Header.processInfo.codeCompressed = isCodeCompressed;
}

void ExtendedHeader::setIsSdmcTitle(bool isSdmcTitle)
{
	m_Header.processInfo.sdmcTitle = isSdmcTitle;
}

void ExtendedHeader::setRemasterVersion(u16 version)
{
	m_Header.processInfo.remasterVersion = le_hword(version);
}

void ExtendedHeader::setTextSegment(u32 address, u32 pageNum, u32 codeSize)
{
	m_Header.processInfo.codeInfo.text.address = le_word(address);
	m_Header.processInfo.codeInfo.text.pageNum = le_word(pageNum);
	m_Header.processInfo.codeInfo.text.codeSize = le_word(codeSize);
}

void ExtendedHeader::setRoDataSegment(u32 address, u32 pageNum, u32 codeSize)
{
	m_Header.processInfo.codeInfo.rodata.address = le_word(address);
	m_Header.processInfo.codeInfo.rodata.pageNum = le_word(pageNum);
	m_Header.processInfo.codeInfo.rodata.codeSize = le_word(codeSize);
}

void ExtendedHeader::setDataSegment(u32 address, u32 pageNum, u32 codeSize)
{
	m_Header.processInfo.codeInfo.data.address = le_word(address);
	m_Header.processInfo.codeInfo.data.pageNum = le_word(pageNum);
	m_Header.processInfo.codeInfo.data.codeSize = le_word(codeSize);
}

void ExtendedHeader::setStackSize(u32 stackSize)
{
	m_Header.processInfo.codeInfo.stackSize = le_word(stackSize);
}

void ExtendedHeader::setBssSize(u32 bssSize)
{
	m_Header.processInfo.codeInfo.bssSize = le_word(bssSize);
}

int ExtendedHeader::setDependencies(std::vector<u64>& dependencies)
{
	if (dependencies.size() > MAX_DEPENDENCY_NUM)
	{
		die("[ERROR] Too many Dependencies. (Maximum 48)");
	}

	for (u32 i = 0; i < dependencies.size() && i < MAX_DEPENDENCY_NUM; i++)
	{
		m_Header.processInfo.dependencyList[i] = le_dword(dependencies[i]);
	}
    
    return 0;
}

void ExtendedHeader::setSaveSize(u32 size)
{
	m_Header.processInfo.saveSize = le_word(size);
}

void ExtendedHeader::setJumpId(u64 id)
{
	m_Header.processInfo.jumpId = le_dword(id);
}


// Set Arm11 Local Capabilities
void ExtendedHeader::setProgramId(u64 id)
{
	m_Header.arm11Local.programId = le_dword(id);
}

void ExtendedHeader::setKernelId(u64 firmTitleId)
{
	m_Header.arm11Local.firmTidLow = le_word(firmTitleId&0x0fffffff);
}

void ExtendedHeader::setEnableL2Cache(bool enable)
{
	m_Header.arm11Local.enableL2Cache = enable;
}

void ExtendedHeader::setCpuSpeed(CpuSpeed speed)
{
	m_Header.arm11Local.cpuSpeed = (speed == CLOCK_804MHz);
}

void ExtendedHeader::setSystemModeExt(SystemModeExt mode)
{
	m_Header.arm11Local.systemModeExt = mode; 
}

int ExtendedHeader::setIdealProcessor(u8 processor)
{
	if (processor > 1)
	{
		die("[ERROR] Invalid IdealProcessor. (Only 0 or 1 allowed)");
	}

	m_Header.arm11Local.idealProcessor = processor; 

	return 0;
}

int ExtendedHeader::setProcessAffinityMask(u8 affinityMask)
{
	if (affinityMask > 3)
	{
		die("[ERROR] AffinityMask is too large. (Maximum 3)");
	}

	m_Header.arm11Local.affinityMask = affinityMask;

	return 0;
}

void ExtendedHeader::setSystemMode(SystemMode mode)
{
	m_Header.arm11Local.systemMode = mode; 
}

int ExtendedHeader::setProcessPriority(int8_t priority)
{
	if (priority < 0)
	{
		die("[ERROR] Invalid Priority. (Allowed range: 0-127).");
	}

	m_Header.arm11Local.threadPriority = priority; 

	return 0;
}

void ExtendedHeader::setExtdataId(u64 id)
{
	m_Header.arm11Local.extdataId = le_dword(id);
	m_Header.arm11Local.fsRights &= ~le_dword(USE_EXTENDED_SAVEDATA_ACCESS_CONTROL);
}

int ExtendedHeader::setSystemSaveIds(std::vector<u32>& ids)
{
	if (ids.size() > MAX_SYSTEM_SAVE_IDS)
	{
		die("[ERROR] Too many SystemSaveIds. (Maximum 2)");
	}

	for (u32 i = 0; i < ids.size() && i < MAX_SYSTEM_SAVE_IDS; i++)
	{
		m_Header.arm11Local.systemSaveId[i] = le_word(ids[i]);
	}

	return 0;
}

int ExtendedHeader::setOtherUserSaveIds(std::vector<u32>& ids, bool UseOtherVariationSaveData)
{
	u64 saveIds = 0;

	if (ids.size() > 3)
	{
		die("[ERROR] Too many OtherUserSaveIds. (Maximum 3)");
	}

	for (u32 i = 0; i < ids.size() && i < 3; i++)
	{
		saveIds = (saveIds << 20) | (ids[i] & 0xffffff);
	}

	// set bit60 if UseOtherVariationSaveData
	if (UseOtherVariationSaveData)
	{
		saveIds |= BIT(60);
	}
		

	m_Header.arm11Local.fsRights &= ~le_dword(USE_EXTENDED_SAVEDATA_ACCESS_CONTROL);
	m_Header.arm11Local.otherUserSaveIds = le_dword(saveIds);

	return 0;
}

int ExtendedHeader::setAccessibleSaveIds(std::vector<u32>& ids, bool UseOtherVariationSaveData)
{
	if (ids.size() > 6)
	{
		die("[ERROR] Too many AccessibleSaveIds. (Maximum 6)");
	}

	u64 extdataId = 0;
	u64 otherUserSaveIds = 0;

	// first three ids are written to otherUserSaveIds
	for (u32 i = 0; i < ids.size() && i < 3; i++)
	{
		otherUserSaveIds = (otherUserSaveIds << 20) | (ids[i] & 0xffffff);
	}

	// final three ids are written to extdataId
	for (u32 i = 3; i < ids.size() && i < 6; i++)
	{
		extdataId = (extdataId << 20) | (ids[i] & 0xffffff);
	}

	// set bit60 if UseOtherVariationSaveData
	if (UseOtherVariationSaveData)
	{
		otherUserSaveIds |= BIT(60);
	}

	m_Header.arm11Local.extdataId = le_dword(extdataId);
	m_Header.arm11Local.otherUserSaveIds = le_dword(otherUserSaveIds);
	m_Header.arm11Local.fsRights |= le_dword(USE_EXTENDED_SAVEDATA_ACCESS_CONTROL);

	return 0;
}

void ExtendedHeader::setFsAccessRights(u64 rights)
{
	m_Header.arm11Local.fsRights |= le_dword(rights & 0x00ffffffffffffff);
}

void ExtendedHeader::setNotUseRomfs()
{
	m_Header.arm11Local.fsRights |= le_dword(NOT_USE_ROMFS);
}

int ExtendedHeader::setServiceList(std::vector<std::string>& serviceList)
{
	if (serviceList.size() > MAX_SERVICE_NUM)
	{
		die("[ERROR] Too many services. (Maximum 34)");
	}

	if (serviceList.size() > 32)
	{
		fprintf(stderr, "[WARNING] Service \"%s\" will not be available on firmwares <= 9.3.0\n", serviceList[32].c_str());
	}
	if (serviceList.size() > 33)
	{
		fprintf(stderr, "[WARNING] Service \"%s\" will not be available on firmwares <= 9.3.0\n", serviceList[33].c_str());
	}

	for (u32 i = 0; i < serviceList.size() && i < MAX_SERVICE_NUM; i++)
	{
		strncpy(m_Header.arm11Local.serviceList[i], serviceList[i].c_str(), 8);
	}

	return 0;
}

void ExtendedHeader::setMaxCpu(u16 maxCpu)
{
	m_Header.arm11Local.resourceLimits[0] = le_hword(maxCpu);
}

void ExtendedHeader::setResourceLimitCategory(ResourceLimitCategory category)
{
	m_Header.arm11Local.resourceLimitCategory = (u8)category;
}


// Set Arm11 Kernel Capabilities
inline u32 makeKernelCapability(u32 prefix, u32 value)
{
	return prefix | ((value) & ~prefix);
}

void ExtendedHeader::setInterupts(std::vector<u8>& interuptList)
{
	u32 desc[8] = {0};
	u32 i, j;
	for (i = j = 0; j < interuptList.size() && i < MAX_INTERUPT_NUM; i++, j++)
	{
		while (interuptList[j] > MAX_INTERUPT_VALUE && j < interuptList.size())
		{
			j++;
		}
		if (j >= interuptList.size())
		{
			break;
		}

		// if this is a new desc, set all bits
		if (i % 4)
		{
			desc[i/4] = 0xffffffff;
		}

		// shift the desc 7 bits
		desc[i/4] = (desc[i/4] << 7) | interuptList[j];
	}
	for (i = 0; i < 8; i++)
	{
		if (desc[i] > 0)
		{
			m_Interupts.push_back(makeKernelCapability(INTERUPT_LIST, desc[i]));
		}
	}
}

void ExtendedHeader::setSystemCalls(std::vector<u8>& svcList)
{
	u32 desc[8] = {0}; 
	for (u32 i = 0; i < svcList.size(); i++)
	{
		if (svcList[i] > MAX_SVC_VALUE)
		{
			continue;
		}

		desc[(svcList[i]/24)] |= 1 << ((svcList[i] % 24) & 31);
	}
	for (u32 i = 0; i < 8; i++)
	{
		if (desc[i] > 0)
		{
			m_ServiceCalls.push_back(makeKernelCapability(SVC_LIST | (i << 24), desc[i]));
		}
	}
}

void ExtendedHeader::setReleaseKernelVersion(u8 major, u8 minor)
{
	m_ReleaseKernelVersion = makeKernelCapability(KERNEL_RELEASE_VERSION, (major << 8 | minor));
}

void ExtendedHeader::setHandleTableSize(u16 size)
{
	m_HandleTableSize = makeKernelCapability(HANDLE_TABLE_SIZE, size);
}

void ExtendedHeader::setMemoryType(MemoryType type)
{
	m_KernelFlags &= ~(0x00000f00);
	m_KernelFlags |= ((type << 8) & 0x00000f00);
	m_KernelFlags = makeKernelCapability(KERNEL_FLAG, m_KernelFlags);
}

void ExtendedHeader::setKernelFlags(u32 flags)
{
	m_KernelFlags &= ~(0x00fff0ff);
	m_KernelFlags |= (flags & 0x00fff0ff);
	m_KernelFlags = makeKernelCapability(KERNEL_FLAG, m_KernelFlags);
}

inline u32 makeMappingDesc(u32 prefix, u32 address, bool readOnly)
{
	return makeKernelCapability(prefix, (address >> 12) | (readOnly << 20));
}

inline u32 alignToPage(u32 address)
{
	return (address & 0xFFF)? (address & ~0xFFF) + 0x1000 : address;
}

void ExtendedHeader::setStaticMapping(std::vector<struct sMemoryMapping>& mapping)
{
	// todo: be more strict?
	for (int i = 0; i < mapping.size(); i++)
	{
		if (mapping[i].start == 0)
		{
			continue;
		}

		// if the end offset is valid
		if (alignToPage(mapping[i].end) > mapping[i].start)
		{
			m_StaticMapping.push_back(makeMappingDesc(MAPPING_STATIC, mapping[i].start, mapping[i].readOnly));
			m_StaticMapping.push_back(makeMappingDesc(MAPPING_STATIC, alignToPage(mapping[i].end), true));
		}
		else 
		{
			m_StaticMapping.push_back(makeMappingDesc(MAPPING_STATIC, mapping[i].start, mapping[i].readOnly));
			m_StaticMapping.push_back(makeMappingDesc(MAPPING_STATIC, mapping[i].start + 0x1000, true));
		}
		
	}
}

void ExtendedHeader::setIOMapping(std::vector<struct sMemoryMapping>& mapping)
{
	// todo: be more strict?
	for (int i = 0; i < mapping.size(); i++)
	{
		if (mapping[i].start == 0)
		{
			continue;
		}

		// if the end offset is valid
		if (alignToPage(mapping[i].end) > mapping[i].start)
		{
			m_IOMapping.push_back(makeMappingDesc(MAPPING_STATIC, mapping[i].start, false));
			m_IOMapping.push_back(makeMappingDesc(MAPPING_STATIC, alignToPage(mapping[i].end), false));
		}
		else
		{
			m_IOMapping.push_back(makeMappingDesc(MAPPING_IO, mapping[i].start, false));
		}
	}
}


// Set Arm9 Access Control
void ExtendedHeader::setArm9IOControl(u32 ioRights, u8 descVersion)
{
	m_Header.arm9.ioRights = le_word(ioRights);
	m_Header.arm9.version = descVersion;
}

// commit the kernel descriptors to exheader
int ExtendedHeader::commitArm11KernelCapabilities()
{
	u32 pos, i;

	// return error if there are more than MAX_KERNEL_DESC descriptors
	if ((m_ServiceCalls.size() \
		+ m_Interupts.size() \
		+ m_IOMapping.size() \
		+ m_StaticMapping.size() \
		+ (m_KernelFlags > 0) \
		+ (m_HandleTableSize > 0) \
		+ (m_ReleaseKernelVersion > 0)) \
		> MAX_KERNEL_DESC)
	{
		die("[ERROR] Too many kernel descriptors");
	}

	pos = 0;

	for (i = 0; i < m_ServiceCalls.size() && pos < MAX_KERNEL_DESC; i++)
	{
		m_Header.arm11Kernel.descriptors[pos++] = le_word(m_ServiceCalls[i]);
	}

	for (i = 0; i < m_Interupts.size() && pos < MAX_KERNEL_DESC; i++)
	{
		m_Header.arm11Kernel.descriptors[pos++] = le_word(m_Interupts[i]);
	}

	for (i = 0; i < m_IOMapping.size() && pos < MAX_KERNEL_DESC; i++)
	{
		m_Header.arm11Kernel.descriptors[pos++] = le_word(m_IOMapping[i]);
	}

	for (i = 0; i < m_StaticMapping.size() && pos < MAX_KERNEL_DESC; i++)
	{
		m_Header.arm11Kernel.descriptors[pos++] = le_word(m_StaticMapping[i]);
	}

	if (m_KernelFlags > 0 && pos < MAX_KERNEL_DESC)
	{
		m_Header.arm11Kernel.descriptors[pos++] = m_KernelFlags; 
	}

	if (m_HandleTableSize > 0 && pos < MAX_KERNEL_DESC)
	{
		m_Header.arm11Kernel.descriptors[pos++] = m_HandleTableSize; 
	}

	if (m_ReleaseKernelVersion > 0 && pos < MAX_KERNEL_DESC)
	{
		m_Header.arm11Kernel.descriptors[pos++] = m_ReleaseKernelVersion; 
	}

	// write dummy data to remaining descriptors
	for (; pos < MAX_KERNEL_DESC; pos++)
	{
		m_Header.arm11Kernel.descriptors[pos] = 0xffffffff;
	}

	return 0;
}
