#pragma once
#include <vector>
#include <string>
#include "types.h"
#include "crypto.h"

class CxiExtendedHeader
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
		bool is_read_only;
	};

	CxiExtendedHeader();
	~CxiExtendedHeader();

	int CreateExheader(const u8 ncch_rsa_modulus[Crypto::kRsa2048Size], const u8 accessdesc_rsa_modulus[Crypto::kRsa2048Size], const u8 accessdesc_rsa_priv_exponent[Crypto::kRsa2048Size]);

	inline const u8* exheader_blob() const { return (const u8*)&header_; }
	inline u32 exheader_size() const { return sizeof(struct sExtendedHeader); }
	inline const u8* accessdesc_blob() const { return (const u8*)&access_descriptor_; }
	inline u32 accessdesc_size() const { return sizeof(struct sAccessDescriptor); }

	// Set Process Info
	void SetProcessName(const char* name);
	void SetIsCodeCompressed(bool is_code_compressed);
	void SetIsSdmcTitle(bool is_sdmc_title);
	void SetRemasterVersion(u16 version);
	void SetTextSegment(u32 address, u32 page_num, u32 size);
	void SetRoDataSegment(u32 address, u32 page_num, u32 size);
	void SetDataSegment(u32 address, u32 page_num, u32 size);
	void SetStackSize(u32 stack_size);
	void SetBssSize(u32 bss_size);
	int SetDependencyList(const std::vector<u64>& dependency_list);
	void SetSaveDataSize(u32 size);
	void SetJumpId(u64 id);

	// Set Arm11 Local Capabilities
	void SetProgramId(u64 id);
	void SetFirmwareTitleId(u64 id);
	void SetEnableL2Cache(bool enable);
	void SetCpuSpeed(CpuSpeed speed);
	void SetSystemModeExt(SystemModeExt mode);
	int SetIdealProcessor(u8 processor);
	int SetProcessAffinityMask(u8 affinity_mask);
	void SetSystemMode(SystemMode mode);
	int SetProcessPriority(int8_t priority);
	void SetExtdataId(u64 id);
	int SetSystemSaveIds(const std::vector<u32>& ids);
	int SetOtherUserSaveIds(const std::vector<u32>& ids, bool use_other_variation_save_data);
	int SetAccessibleSaveIds(const std::vector<u32>& ids, bool use_other_variation_save_data);
	void SetFsAccessRights(u64 rights);
	void SetUseRomfs(bool use_romfs);
	int SetServiceList(const std::vector<std::string>& service_list);
	void SetMaxCpu(u16 max_cpu);
	void SetResourceLimitCategory(ResourceLimitCategory category);

	// Set Arm11 Kernel Capabilities
	void SetAllowedInterupts(const std::vector<u8>& interupt_list);
	void SetAllowedSupervisorCalls(const std::vector<u8>& svc_list);
	void SetReleaseKernelVersion(u8 major, u8 minor);
	void SetHandleTableSize(u16 size);
	void SetMemoryType(MemoryType type);
	void SetKernelFlags(u32 flags);
	void SetStaticMapping(const std::vector<struct sMemoryMapping>& mapping_list);
	void SetIOMapping(const std::vector<struct sMemoryMapping>& mapping_list);

	// Set Arm9 Access Control
	void SetArm9IOControl(u32 io_rights, u8 desc_version);
private:
	static const u32 kMaxInteruptNum = 32;
	static const u32 kMaxInteruptValue = 0x7F;
	static const u32 kMaxSvcValue = 0x7D;
	static const u32 kMaxDependencyNum = 0x30;
	static const u32 kMaxKernelDescNum = 28;
	static const u32 kMaxServiceNum = 34;
	static const u32 kMaxResourceLimitNum = 16;
	static const u32 kMaxSystemSaveIdNum = 2;

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
		u32 page_num;
		u32 size;
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
				u8 is_code_compressed : 1;
				u8 is_sdmc_title : 1;
			};
		};

		u16 remaster_version;

		struct sCodeInfo
		{
			struct sCodeSegmentInfo text;
			u32 stack_size;
			struct sCodeSegmentInfo rodata;
			u8 reserved1[4];
			struct sCodeSegmentInfo data;
			u32 bss_size;
		} code_info;
		
		u64 dependency_list[kMaxDependencyNum];

		u32 save_data_size;
		u8 reserved2[4];
		u64 jump_id;
		u8 reserved3[0x30];
	};

	struct sArm11LocalCapabilities
	{
		u64 program_id;
		u32 firm_title_id_low;
		union
		{
			u8 flag[4];
			struct
			{
				u8 enable_l2_cache : 1;
				u8 cpu_speed : 1;
				u8: 6;

				u8 system_mode_ext : 4;
				u8: 4;

				u8 ideal_processor : 2;
				u8 affinity_mask : 2;
				u8 system_mode : 4;

				int8_t thread_priority;
			};
		};
		u16 resource_limit_descriptors[kMaxResourceLimitNum];

		u64 extdata_id;
		u32 system_save_ids[kMaxSystemSaveIdNum];
		u64 other_user_save_ids;
		u64 fs_rights;
		char service_list[kMaxServiceNum][8];
		u8 reserved[0xf];
		u8 resource_limit_category;
	};

	struct sArm11KernelCapabilities
	{
		u32 descriptors[kMaxKernelDescNum];
		u8 reserved[0x10];
	};

	struct sArm9AccessControl
	{
		u32 io_rights;
		u8 reserved[0xB];
		u8 version;
	};

	struct sExtendedHeader
	{
		struct sProcessInfo process_info;
		struct sArm11LocalCapabilities arm11_local;
		struct sArm11KernelCapabilities arm11_kernel;
		struct sArm9AccessControl arm9;
	};

	struct sAccessDescriptor
	{
		u8 signature[0x100];
		u8 ncch_rsa_modulus[0x100];
		struct sArm11LocalCapabilities arm11_local;
		struct sArm11KernelCapabilities arm11_kernel;
		struct sArm9AccessControl arm9;
	};

	struct sExtendedHeader header_;
	struct sAccessDescriptor access_descriptor_;

	std::vector<u32> allowed_interupts_;
	std::vector<u32> allowed_supervisor_calls_;
	u32 release_kernel_version_;
	u32 handle_table_size_;
	u32 kernel_flags_;
	std::vector<u32> static_mappings_;
	std::vector<u32> io_register_mappings_;

	int CommitArm11KernelCapabilities();
};

