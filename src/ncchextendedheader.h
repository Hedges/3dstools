#pragma once
#include "types.h"
#include <vector>
#include <string>

class ExtendedHeader
{
public:
	enum CtrModules
	{
		MODULE_SM = 0x10,
		MODULE_FS = 0x11,
		MODULE_PM = 0x12,
		MODULE_LOADER = 0x13,
		MODULE_PXI = 0x14,
		MODULE_AM = 0x15,
		MODULE_CAMERA = 0x16,
		MODULE_CONFIG = 0x17,
		MODULE_CODEC = 0x18,
		MODULE_DMNT = 0x19,
		MODULE_DSP = 0x1A,
		MODULE_GPIO = 0x1B,
		MODULE_GSP = 0x1C,
		MODULE_HID = 0x1D,
		MODULE_I2C = 0x1E,
		MODULE_MCU = 0x1F,
		MODULE_MIC = 0x20,
		MODULE_PDN = 0x21,
		MODULE_PTM = 0x22,
		MODULE_SPI = 0x23,
		MODULE_AC = 0x24,
		MODULE_CECD = 0x26,
		MODULE_CSND = 0x27,
		MODULE_DLP = 0x28,
		MODULE_HTTP = 0x29,
		MODULE_MP = 0x2A,
		MODULE_NDM = 0x2B,
		MODULE_NIM = 0x2C,
		MODULE_NWM = 0x2D,
		MODULE_SOCKET = 0x2E,
		MODULE_SSL = 0x2F,
		MODULE_PROC9 = 0x30,
		MODULE_PS = 0x31,
		MODULE_FRIENDS = 0x32,
		MODULE_IR = 0x33,
		MODULE_BOSS = 0x34,
		MODULE_NEWS = 0x35,
		MODULE_DEBUGGER = 0x36,
		MODULE_RO = 0x37,
		MODULE_ACT = 0x38,
		MODULE_NFC = 0x40,
		MODULE_MVD = 0x41,
		MODULE_QTM = 0x42
	};

	enum CpuSpeed
	{
		CLOCK_268MHz,
		CLOCK_804MHz
	};

	enum SystemMode
	{
		SYSMODE_PROD,
		SYSMODE_UNSUPPORTED,
		SYSMODE_DEV1,
		SYSMODE_DEV2,
		SYSMODE_DEV3,
		SYSMODE_DEV4
	};
	
	enum SystemModeExt
	{
		SYSMODE_SNAKE_LEGACY,
		SYSMODE_SNAKE_PROD,
		SYSMODE_SNAKE_DEV1,
		SYSMODE_SNAKE_DEV2
	};

	enum MemoryType
	{
		MEMTYPE_APPLICATION = 1,
		MEMTYPE_SYSTEM = 2,
		MEMTYPE_BASE = 3
	};

	enum ResourceLimitCategory
	{
		RESLIMIT_APPLICATION,
		RESLIMIT_SYS_APPLET,
		RESLIMIT_LIB_APPLET,
		RESLIMIT_OTHER
	};

	enum FSAccessRights
	{
		FSRIGHT_CATEGORY_SYSTEM_APPLICATION = BIT(0),
		FSRIGHT_CATEGORY_HARDWARE_CHECK = BIT(1),
		FSRIGHT_CATEGORY_FILE_SYSTEM_TOOL = BIT(2),
		FSRIGHT_DEBUG = BIT(3),
		FSRIGHT_TWL_CARD = BIT(4),
		FSRIGHT_TWL_NAND = BIT(5),
		FSRIGHT_BOSS = BIT(6),
		FSRIGHT_DIRECT_SDMC = BIT(7),
		FSRIGHT_CORE = BIT(8),
		FSRIGHT_CTR_NAND_RO = BIT(9),
		FSRIGHT_CTR_NAND_RW = BIT(10),
		FSRIGHT_CTR_NAND_RO_WRITE = BIT(11),
		FSRIGHT_CATEGORY_SYSTEM_SETTINGS = BIT(12),
		FSRIGHT_CARD_BOARD = BIT(13),
		FSRIGHT_EXPORT_IMPORT_IVS = BIT(14),
		FSRIGHT_DIRECT_SDMC_WRITE = BIT(15),
		FSRIGHT_SWITCH_CLEANUP = BIT(16),
		FSRIGHT_SAVE_DATA_MOVE = BIT(17),
		FSRIGHT_SHOP = BIT(18),
		FSRIGHT_SHELL = BIT(19),
		FSRIGHT_CATEGORY_HOME_MENU = BIT(20),
	};

	enum KernelFlags
	{
		KERNFLAG_PERMIT_DEBUG = BIT(0),
		KERNFLAG_FORCE_DEBUG = BIT(1),
		KERNFLAG_CAN_USE_NON_ALPHABET_AND_NUMBER = BIT(2),
		KERNFLAG_CAN_WRITE_SHARED_PAGE = BIT(3),
		KERNFLAG_CAN_USE_PRIVILEGE_PRIORITY = BIT(4),
		KERNFLAG_PERMIT_MAIN_FUNCTION_ARGUMENT = BIT(5),
		KERNFLAG_CAN_SHARE_DEVICE_MEMORY = BIT(6),
		KERNFLAG_RUNNABLE_ON_SLEEP = BIT(7),
		KERNFLAG_SPECIAL_MEMORY_LAYOUT = BIT(12),
		KERNFLAG_CAN_ACCESS_CORE2 = BIT(13),
	};

	enum IORights
	{
		IORIGHT_FS_MOUNT_NAND = BIT(0),
		IORIGHT_FS_MOUNT_NAND_RO_WRITE = BIT(1),
		IORIGHT_FS_MOUNT_TWLN = BIT(2),
		IORIGHT_FS_MOUNT_WNAND = BIT(3),
		IORIGHT_FS_MOUNT_CARD_SPI = BIT(4),
		IORIGHT_USE_SDIF3 = BIT(5),
		IORIGHT_CREATE_SEED = BIT(6),
		IORIGHT_USE_CARD_SPI = BIT(7),
		IORIGHT_SD_APPLICATION = BIT(8),
		IORIGHT_USE_DIRECT_SDMC = BIT(9),
	};

	struct sMemoryMapping
	{
		u32 start;
		u32 end;
		bool readOnly;
	};

	ExtendedHeader();
	~ExtendedHeader();

	int createExheader();
	// accessdesc needs to be signed
	int createAccessDesc(const u8 ncchRsaModulus[0x100], const u8 modulus[0x100], const u8 privExponent[0x100]);

	const u8* getExheader() const;
	u32 getExheaderSize() const;
	const u8* getExheaderHash() const;
	const u8* getAccessDesc() const;
	u32 getAccessDescSize() const;

	// Set Process Info
	void setProcessName(const char *name);
	void setIsCodeCompressed(bool isCodeCompressed);
	void setIsSdmcTitle(bool isSdmcTitle);
	void setRemasterVersion(u16 version);
	void setTextSegment(u32 address, u32 pageNum, u32 codeSize);
	void setRoDataSegment(u32 address, u32 pageNum, u32 codeSize);
	void setDataSegment(u32 address, u32 pageNum, u32 codeSize);
	void setStackSize(u32 stackSize);
	void setBssSize(u32 bssSize);
	int setDependencies(std::vector<u64>& dependencies);
	void setSaveSize(u32 size);
	void setJumpId(u64 id);

	// Set Arm11 Local Capabilities
	void setProgramId(u64 id);
	void setKernelId(u64 firmTitleId);
	void setEnableL2Cache(bool enable);
	void setCpuSpeed(CpuSpeed speed);
	void setSystemModeExt(SystemModeExt mode);
	int setIdealProcessor(u8 processor);
	int setProcessAffinityMask(u8 affinityMask);
	void setSystemMode(SystemMode mode);
	int setProcessPriority(int8_t priority);
	void setExtdataId(u64 id);
	int setSystemSaveIds(std::vector<u32>& ids);
	int setOtherUserSaveIds(std::vector<u32>& ids, bool UseOtherVariationSaveData);
	int setAccessibleSaveIds(std::vector<u32>& ids, bool UseOtherVariationSaveData);
	void setFsAccessRights(u64 rights);
	void setNotUseRomfs();
	int setServiceList(std::vector<std::string>& serviceList);
	void setMaxCpu(u16 maxCpu);
	void setResourceLimitCategory(ResourceLimitCategory category);

	// Set Arm11 Kernel Capabilities
	void setInterupts(std::vector<u8>& interuptList);
	void setSystemCalls(std::vector<u8>& svcList);
	void setReleaseKernelVersion(u8 major, u8 minor);
	void setHandleTableSize(u16 size);
	void setMemoryType(MemoryType type);
	void setKernelFlags(u32 flags);
	void setStaticMapping(std::vector<struct sMemoryMapping>& memMaps);
	void setIOMapping(std::vector<struct sMemoryMapping>& ioMaps);

	// Set Arm9 Access Control
	void setArm9IOControl(u32 ioRights, u8 descVersion);
private:
	static const u32 MAX_INTERUPT_NUM = 32;
	static const u32 MAX_INTERUPT_VALUE = 0x7F;
	static const u32 MAX_SVC_VALUE = 0x7D;
	static const u32 MAX_DEPENDENCY_NUM = 0x30;
	static const u32 MAX_KERNEL_DESC = 28;
	static const u32 MAX_SERVICE_NUM = 34;
	static const u32 MAX_RESOURCE_LIMITS = 16;
	static const u32 MAX_SYSTEM_SAVE_IDS = 2;

	enum FSAttributes
	{
		NOT_USE_ROMFS = BIT(56),
		USE_EXTENDED_SAVEDATA_ACCESS_CONTROL = BIT(57),
	};

	enum KernelCapabilityPrefix
	{
		INTERUPT_LIST = 0xe0000000,
		SVC_LIST = 0xf0000000,
		KERNEL_RELEASE_VERSION = 0xfc000000,
		HANDLE_TABLE_SIZE = 0xfe000000,
		KERNEL_FLAG = 0xff000000,
		MAPPING_STATIC = 0xff800000,
		MAPPING_IO = 0xffc00000,
	};

	struct sCodeSegmentInfo
	{
		u32 address;
		u32 pageNum;
		u32 codeSize;
	};

	struct sProcessInfo
	{
		char name[8];
		u8 reserved0[5];
		union
		{
			u8 flag;
			struct
			{
				u8 codeCompressed : 1;
				u8 sdmcTitle : 1;
			};
		};

		u16 remasterVersion;

		struct sCodeInfo
		{
			struct sCodeSegmentInfo text;
			u32 stackSize;
			struct sCodeSegmentInfo rodata;
			u8 reserved1[4];
			struct sCodeSegmentInfo data;
			u32 bssSize;
		} codeInfo;
		
		u64 dependencyList[MAX_DEPENDENCY_NUM];

		u32 saveSize;
		u8 reserved2[4];
		u64 jumpId;
		u8 reserved3[0x30];
	};

	struct sArm11LocalCapabilities
	{
		u64 programId;
		u32 firmTidLow;
		union
		{
			u8 flag[4];
			struct
			{
				u8 enableL2Cache : 1;
				u8 cpuSpeed : 1;
				u8: 6;

				u8 systemModeExt : 4;
				u8: 4;

				u8 idealProcessor : 2;
				u8 affinityMask : 2;
				u8 systemMode : 4;

				int8_t threadPriority;
			};
		};
		u16 resourceLimits[MAX_RESOURCE_LIMITS];

		u64 extdataId;
		u32 systemSaveId[MAX_SYSTEM_SAVE_IDS];
		u64 otherUserSaveIds;
		u64 fsRights;
		char serviceList[MAX_SERVICE_NUM][8];
		u8 reserved[0xf];
		u8 resourceLimitCategory;
	};

	struct sArm11KernelCapabilities
	{
		u32 descriptors[MAX_KERNEL_DESC];
		u8 reserved[0x10];
	};

	struct sArm9AccessControl
	{
		u32 ioRights;
		u8 reserved[0xB];
		u8 version;
	};

	struct sExtendedHeader
	{
		struct sProcessInfo processInfo;
		struct sArm11LocalCapabilities arm11Local;
		struct sArm11KernelCapabilities arm11Kernel;
		struct sArm9AccessControl arm9;
	};

	struct sAccessDescriptor
	{
		u8 signature[0x100];
		u8 ncchRsaModulus[0x100];
		struct sArm11LocalCapabilities arm11Local;
		struct sArm11KernelCapabilities arm11Kernel;
		struct sArm9AccessControl arm9;
	};

	struct sExtendedHeader m_Header;
	struct sAccessDescriptor m_AccessDesc;

	u8 m_ExheaderHash[0x20];

	std::vector<u32> m_Interupts;
	std::vector<u32> m_ServiceCalls;
	u32 m_ReleaseKernelVersion;
	u32 m_HandleTableSize;
	u32 m_KernelFlags;
	std::vector<u32> m_StaticMapping;
	std::vector<u32> m_IOMapping;

	int commitArm11KernelCapabilities();
};

