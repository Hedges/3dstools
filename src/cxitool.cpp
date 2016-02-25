#include <cstring>
#include <algorithm>

#include "crypto.h"
#include "YamlReader.h"

#include "ByteBuffer.h"

#include "ncch_header.h"
#include "cxi_extended_header.h"
#include "exefs_code.h"
#include "exefs.h"
#include "ivfc.h"
#include "romfs.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

#ifdef WIN32
static inline char* FixMinGWPath(char* buf)
{
	if (*buf == '/')
	{
		buf[0] = buf[1];
		buf[1] = ':';
	}
	return buf;
}
#else
#define FixMinGWPath(_arg) (_arg)
#endif

struct sArgInfo
{
	const char *elf_file;
	const char *spec_file;
	const char *out_file;
	const char *icon_file;
	const char *banner_file;
	const char *romfs_dir;
	const char *unique_id;
	const char *product_code;
	const char *title;
};

class NcchBuilder
{
public:
	NcchBuilder()
	{
		config_.title_id = 0;
		config_.program_id = 0;
		config_.is_compressed_code = 0;
		config_.is_sdmc_title = 0;
		config_.remaster_version = 0;
		config_.stack_size = 0;
		config_.save_data_size = 0;
		config_.jump_id = 0;
		config_.firmware_title_id = 0;
		config_.enable_l2_cache = false;
		config_.cpu_speed = CxiExtendedHeader::CLOCK_268MHz;
		config_.system_mode_ext = CxiExtendedHeader::SYSMODE_SNAKE_LEGACY;
		config_.ideal_processor = 0;
		config_.affinity_mask = 0;
		config_.system_mode = CxiExtendedHeader::SYSMODE_PROD;
		config_.priority = 0;
		config_.use_extdata = false;
		config_.extdata_id = 0;
		config_.use_other_variation_save_data = false;
		config_.max_cpu = 0;
		config_.fs_rights = 0;
		config_.resource_limit_category = CxiExtendedHeader::RESLIMIT_APPLICATION;
		config_.release_kernel_version[0] = 0;
		config_.release_kernel_version[1] = 0;
		config_.handle_table_size = 0;
		config_.memory_type = CxiExtendedHeader::MEMTYPE_APPLICATION;
		config_.dependency_list.clear();
		config_.system_save_ids.clear();
		config_.other_user_save_ids.clear();
		config_.accessible_save_ids.clear();
		config_.services.clear();
		config_.interupts.clear();
		config_.svc_calls.clear();
		config_.static_mappings.clear();
		config_.io_mappings.clear();

		exefs_hashed_data_size_ = 0;
		romfs_hashed_data_size_ = 0;
		romfs_full_size_ = 0;

		memset(extended_header_hash_, 0, Crypto::kSha256HashLen);
		memset(logo_hash_, 0, Crypto::kSha256HashLen);
		memset(exefs_hash_, 0, Crypto::kSha256HashLen);
		memset(romfs_hash_, 0, Crypto::kSha256HashLen);
	}

	~NcchBuilder()
	{

	}

	int BuildNcch(const struct sArgInfo& args)
	{
		args_ = args;

		SetDefaults();

		safe_call(ParseSpecFile());
		safe_call(MakeExefs());
		safe_call(MakeRomfs());
		safe_call(MakeExheader());
		safe_call(MakeHeader());
		safe_call(WriteToFile());

		return 0;
	}

private:
	struct sConfig
	{
		char product_code[16];
		char maker_code[16];
		u64 title_id;
		u64 program_id;

		// process info
		char app_title[8];
		bool is_compressed_code;
		bool is_sdmc_title;
		u16 remaster_version;
		u32 stack_size;
		u32 save_data_size;
		u64 jump_id;
		std::vector<u64> dependency_list;

		
		// arm11 userland system
		
		u64 firmware_title_id;
		bool enable_l2_cache;
		CxiExtendedHeader::CpuSpeed cpu_speed;
		CxiExtendedHeader::SystemModeExt system_mode_ext;
		u8 ideal_processor;
		u8 affinity_mask;
		CxiExtendedHeader::SystemMode system_mode;
		int8_t priority;
		bool use_extdata;
		u64 extdata_id;
		std::vector<u32> system_save_ids;
		bool use_other_variation_save_data;
		std::vector<u32> other_user_save_ids;
		std::vector<u32> accessible_save_ids;
		std::vector<std::string> services;
		u64 fs_rights;
		u16 max_cpu;
		CxiExtendedHeader::ResourceLimitCategory resource_limit_category;

		// arm11 kern
		std::vector<u8> interupts;
		std::vector<u8> svc_calls;
		u8 release_kernel_version[2];
		u16 handle_table_size;
		CxiExtendedHeader::MemoryType memory_type;
		u32 kernel_flags;
		std::vector<struct CxiExtendedHeader::sMemoryMapping> static_mappings;
		std::vector<struct CxiExtendedHeader::sMemoryMapping> io_mappings;

		// arm9
		u32 arm9_rights;
		u8 desc_version;
	};

	struct sArgInfo args_;
	struct sConfig config_;

	struct Crypto::sRsa2048Key cxi_rsa_key_;
	struct Crypto::sRsa2048Key accessdesc_rsa_key_;

	NcchHeader header_;
	CxiExtendedHeader extended_header_;
	u8 extended_header_hash_[Crypto::kSha256HashLen];

	ByteBuffer logo_;
	u8 logo_hash_[Crypto::kSha256HashLen];
	
	ExefsCode exefs_code_;
	Exefs exefs_;
	u32 exefs_hashed_data_size_;
	u8 exefs_hash_[Crypto::kSha256HashLen];
	
	Ivfc ivfc_;
	Romfs romfs_;
	u64 romfs_full_size_;
	u32 romfs_hashed_data_size_;
	u8 romfs_hash_[Crypto::kSha256HashLen];


	void SetDefaults()
	{
		// title id
		if (args_.unique_id != NULL)
		{
			u32 uniqueId = strtoul(args_.unique_id, NULL, 0);

			config_.title_id = 0x0004000000000000 | ((uniqueId & 0xffffff) << 8);
		}
		else
		{
			config_.title_id = 0x000400000ff3ff00;
		}

		// product code
		if (args_.product_code != NULL)
		{
			strncpy(config_.product_code, args_.product_code, 16);
		}
		else
		{
			strncpy(config_.product_code, "CTR-P-CTAP", 16);
		}

		// exheader title
		if (args_.title != NULL)
		{
			strncpy(config_.app_title, args_.title, 8);
		}
		else
		{
			strncpy(config_.app_title, "CtrApp", 8);
		}

		strncpy(config_.maker_code, "01", 2);
		config_.program_id = config_.title_id;
		config_.jump_id = config_.title_id;

		config_.is_sdmc_title = true;
		config_.is_compressed_code = false;
		config_.remaster_version = 0;
		config_.stack_size = 0x4000;
		
		config_.firmware_title_id = 0x0004013800000002;
		config_.fs_rights = 0;
		config_.max_cpu = 0;
		config_.resource_limit_category = CxiExtendedHeader::RESLIMIT_APPLICATION;	
		
		config_.memory_type = CxiExtendedHeader::MEMTYPE_APPLICATION;

		// enable system calls 0x00-0x7D
		for (int i = 0; i < 0x7E; i++)
		{
			config_.svc_calls.push_back(i);
		}
		 
		config_.handle_table_size = 0x200;
		config_.kernel_flags = 0;
		// fw 2.0.0
		config_.release_kernel_version[0] = 2;
		config_.release_kernel_version[1] = 29;

		config_.arm9_rights = CxiExtendedHeader::IORIGHT_SD_APPLICATION;
		config_.desc_version = 2;

		// set rsa keys
		static const struct Crypto::sRsa2048Key DUMMY_RSA_KEY =
		{
			{ 0xAB, 0x7C, 0x3D, 0x15, 0xDF, 0xA1, 0xB0, 0x06, 0x7C, 0xC1, 0x47, 0xAA, 0x53, 0xD8, 0x86, 0x75, 0x42, 0x99, 0xE0, 0x18, 0x66, 0x03, 0x39, 0xD9, 0x79, 0xDA, 0x0A, 0x49, 0x2B, 0x64, 0x91, 0x45, 0x64, 0x90, 0x3D, 0x5F, 0x56, 0x0D, 0xD6, 0xD0, 0x37, 0xBF, 0x81, 0x1E, 0x92, 0xA8, 0xA5, 0x55, 0x09, 0xD9, 0xAE, 0x82, 0x43, 0x16, 0xD3, 0x68, 0x88, 0xBC, 0x4D, 0xCB, 0xC9, 0x2B, 0x0B, 0x47, 0xBD, 0xF8, 0xD9, 0x1A, 0x30, 0x80, 0x85, 0xA8, 0x30, 0x19, 0x77, 0x2E, 0xE9, 0x9F, 0x2D, 0xCA, 0xFC, 0x91, 0x82, 0xC8, 0x7F, 0xDA, 0xFE, 0xFA, 0xA9, 0x44, 0x87, 0x3E, 0xFF, 0x83, 0xA9, 0x4D, 0x80, 0xEC, 0xD5, 0xCB, 0x3E, 0xC8, 0xE8, 0xFF, 0x36, 0xF0, 0xF0, 0xD7, 0x84, 0x82, 0xE2, 0x09, 0x1A, 0x11, 0x76, 0xDF, 0x7A, 0x9B, 0x1C, 0x25, 0xB0, 0x6D, 0xE9, 0x8B, 0x54, 0x52, 0x55, 0x8F, 0x7F, 0x6F, 0xBF, 0xAF, 0xB8, 0xDD, 0xD4, 0xD4, 0xA1, 0x56, 0x8D, 0xF9, 0xF9, 0x98, 0x0E, 0x71, 0x93, 0xED, 0xB8, 0x99, 0xD3, 0xFA, 0x63, 0xF5, 0x6E, 0xAF, 0x9D, 0x49, 0xEA, 0xD7, 0xF7, 0xD9, 0x79, 0x7E, 0x51, 0x71, 0xE3, 0x4B, 0xEB, 0xA7, 0xCB, 0xD9, 0x5E, 0x89, 0x2B, 0x69, 0xBA, 0xEF, 0x98, 0x94, 0xA5, 0x74, 0x96, 0xAF, 0x4F, 0x9A, 0xDB, 0x93, 0x51, 0xE1, 0x99, 0x78, 0xCD, 0xEB, 0x15, 0xE1, 0x31, 0x32, 0xAC, 0x35, 0x9B, 0xD0, 0x4A, 0xDC, 0x87, 0x38, 0x5E, 0xA6, 0x42, 0x4A, 0xD2, 0x05, 0x51, 0x4F, 0x53, 0x9B, 0x8B, 0x3B, 0xE3, 0x03, 0xB9, 0x34, 0xFB, 0x56, 0xCC, 0x6E, 0x7B, 0x56, 0xEA, 0x38, 0x11, 0x44, 0xEE, 0xB0, 0x7B, 0x89, 0x35, 0x0B, 0x0F, 0x17, 0x2F, 0x5D, 0x4B, 0x30, 0x56, 0xF2, 0x06, 0x63, 0x4D, 0x85, 0x86, 0xB7, 0xFE, 0x85, 0xD4, 0xDF, 0xDE, 0xAF },
			{ 0x1E, 0x4A, 0xE7, 0x1B, 0x8B, 0x12, 0xAB, 0xDE, 0xA9, 0x81, 0x17, 0x20, 0xCE, 0x88, 0xEC, 0x4F, 0xA0, 0x81, 0x40, 0x25, 0xEF, 0x37, 0x58, 0xAB, 0xC3, 0x2B, 0xB2, 0x2F, 0x74, 0xBB, 0xE2, 0x31, 0xA8, 0xEF, 0x15, 0xF8, 0x56, 0x62, 0x41, 0x75, 0x2C, 0xB3, 0xE6, 0xA2, 0x38, 0xF4, 0x13, 0xA8, 0xAF, 0x01, 0xC6, 0x22, 0xFA, 0xA8, 0xF8, 0x95, 0x79, 0xBA, 0x11, 0xE0, 0x12, 0xDC, 0x48, 0xB4, 0xD6, 0xA9, 0x33, 0xE8, 0xBD, 0x72, 0xA6, 0xA9, 0xAC, 0x3D, 0x83, 0x61, 0x45, 0x21, 0xBA, 0x5C, 0x26, 0x3B, 0xAA, 0x27, 0xB2, 0xF6, 0x43, 0x9E, 0x91, 0xF2, 0x2A, 0x16, 0x05, 0xDB, 0x03, 0x38, 0x4E, 0xB3, 0x07, 0x9D, 0x4C, 0xAC, 0xFF, 0x03, 0xBE, 0x77, 0xD7, 0x83, 0xAA, 0xC3, 0xD8, 0x1C, 0x15, 0x7F, 0xCA, 0x48, 0xF6, 0x06, 0x9A, 0x75, 0x49, 0xF2, 0x50, 0x94, 0x2D, 0x44, 0x12, 0x1A, 0xEA, 0x04, 0x01, 0x41, 0xD9, 0x87, 0xF1, 0xC3, 0xDB, 0xBE, 0xD8, 0x69, 0xC1, 0x7C, 0x27, 0xF8, 0x52, 0x80, 0x7A, 0xD9, 0x53, 0x67, 0x93, 0x4D, 0x89, 0x56, 0x55, 0xB6, 0x3E, 0x60, 0x42, 0x05, 0x88, 0xDF, 0xCB, 0x17, 0x9D, 0x92, 0xAF, 0x4B, 0xB2, 0x30, 0xFD, 0xE6, 0x7D, 0x5E, 0x80, 0x5F, 0xFE, 0x0F, 0x62, 0x99, 0x40, 0x99, 0x1B, 0xF0, 0xE2, 0xAD, 0x6B, 0xDD, 0x4D, 0x64, 0xDF, 0x6D, 0x04, 0x62, 0xA9, 0xC0, 0xFD, 0x41, 0x0F, 0x84, 0xBB, 0x85, 0xB0, 0x10, 0xE0, 0x6F, 0xD2, 0xFF, 0x31, 0x5A, 0x0F, 0x47, 0xE4, 0xB5, 0x54, 0x95, 0x34, 0xC6, 0xEB, 0xF8, 0xE5, 0x15, 0x79, 0x56, 0xC2, 0x83, 0xF4, 0xEC, 0x18, 0xF4, 0x82, 0x00, 0x57, 0xB0, 0xF9, 0x64, 0x4A, 0x8B, 0xE7, 0x22, 0x36, 0x4F, 0xA9, 0x59, 0xD3, 0x5B, 0x01, 0x71, 0x5E, 0xE7, 0xFE, 0x1F, 0x4C, 0x18, 0x01, 0x61 }
		};

		memcpy(cxi_rsa_key_.modulus, DUMMY_RSA_KEY.modulus, Crypto::kRsa2048Size);
		memcpy(cxi_rsa_key_.priv_exponent, DUMMY_RSA_KEY.priv_exponent, Crypto::kRsa2048Size);
		memcpy(accessdesc_rsa_key_.modulus, DUMMY_RSA_KEY.modulus, Crypto::kRsa2048Size);
		memcpy(accessdesc_rsa_key_.priv_exponent, DUMMY_RSA_KEY.priv_exponent, Crypto::kRsa2048Size);
	}

	int EvaluateBooleanString(bool& dst, const std::string& str)
	{
		if (str == "true")
		{
			dst = true;
		}
		else if (str == "false")
		{
			dst = false;
		}
		else
		{ 
			fprintf(stderr, "[ERROR] Invalid boolean string! %s\n", str.c_str());
			return 1;
		}
		return 0;
	}

	int AddDependency(const std::string& dependency_str)
	{
		static const u64 SYSTEM_MODULE_TID = 0x0004013000000000;
		static const u8 NATIVE_FIRM_CORE = 0x02;
		static const u32 N3DS_MASK = 0x20000000;
		u64 dependency_title_id = 0;

		if (dependency_str == "sm")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_SM << 8);
		}
		else if (dependency_str == "fs")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_FS << 8);
		}
		else if (dependency_str == "pm")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_PM << 8);
		}
		else if (dependency_str == "loader")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_LOADER << 8);
		}
		else if (dependency_str == "pxi")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_PXI << 8);
		}
		else if (dependency_str == "am")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_AM << 8);
		}
		else if (dependency_str == "camera")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_CAMERA << 8);
		}
		else if (dependency_str == "cfg")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_CONFIG << 8);
		}
		else if (dependency_str == "codec")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_CODEC << 8);
		}
		else if (dependency_str == "dmnt")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_DMNT << 8);
		}
		else if (dependency_str == "dsp")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_DSP << 8);
		}
		else if (dependency_str == "gpio")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_GPIO << 8);
		}
		else if (dependency_str == "gsp")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_GSP << 8);
		}
		else if (dependency_str == "hid")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_HID << 8);
		}
		else if (dependency_str == "i2c")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_I2C << 8);
		}
		else if (dependency_str == "mcu")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_MCU << 8);
		}
		else if (dependency_str == "mic")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_MIC << 8);
		}
		else if (dependency_str == "pdn")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_PDN << 8);
		}
		else if (dependency_str == "ptm")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_PTM << 8);
		}
		else if (dependency_str == "spi")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_SPI << 8);
		}
		else if (dependency_str == "ac")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_AC << 8);
		}
		else if (dependency_str == "cecd")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_CECD << 8);
		}
		else if (dependency_str == "csnd")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_CSND << 8);
		}
		else if (dependency_str == "dlp")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_DLP << 8);
		}
		else if (dependency_str == "http")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_HTTP << 8);
		}
		else if (dependency_str == "mp")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_MP << 8);
		}
		else if (dependency_str == "ndm")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_NDM << 8);
		}
		else if (dependency_str == "nim")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_NIM << 8);
		}
		else if (dependency_str == "nwm")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_NWM << 8);
		}
		else if (dependency_str == "socket")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_SOCKET << 8);
		}
		else if (dependency_str == "ssl")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_SSL << 8);
		}
		else if (dependency_str == "ps")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_PS << 8);
		}
		else if (dependency_str == "friends")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_FRIENDS << 8);
		}
		else if (dependency_str == "ir")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_IR << 8);
		}
		else if (dependency_str == "boss")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_BOSS << 8);
		}
		else if (dependency_str == "news")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_NEWS << 8);
		}
		else if (dependency_str == "debugger")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_DEBUGGER << 8);
		}
		else if (dependency_str == "ro")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_RO << 8);
		}
		else if (dependency_str == "act")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_ACT << 8);
		}
		else if (dependency_str == "nfc")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_NFC << 8);
		}
		else if (dependency_str == "mvd")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_MVD << 8) | N3DS_MASK;
		}
		else if (dependency_str == "qtm")
		{
			dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (CxiExtendedHeader::MODULE_QTM << 8) | N3DS_MASK;
		}
		else if (dependency_str.substr(0, 2) == "0x")
		{
			u64 id = strtoull(dependency_str.c_str(), 0, 16);

			if (id == 0)
			{
				die("[ERROR] Invalid dependency id: 0x0");
			}

			// the id is a full title id
			if (id >> 32 == SYSTEM_MODULE_TID >> 32)
			{
				dependency_title_id = id;
			}

			// module unique ids are never larger than a byte, so if this is greater than 0, it is a title id low
			if (((id & 0xffffffffff0fffff) >> 8) > 0)
			{
				dependency_title_id = SYSTEM_MODULE_TID | (id & 0xffffffff);
			}
			// otherwise this is a unique id
			else
			{
				dependency_title_id = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | ((id & 0xffffff) << 8);
			}
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown dependency: %s\n", dependency_str.c_str());
			return 1;
		}

		config_.dependency_list.push_back(dependency_title_id);
		return 0;
	}

	int ParseSpecFileProccessConfig(YamlReader& spec)
	{
		u32 level;
		std::vector<std::string> tmp(1);

		// move into children of ProcessConfig
		spec.GetEvent();

		// get level
		level = spec.level();
		
		while (spec.GetEvent() && spec.level() >= level)
		{
			if (!spec.is_event_scalar())
			{
				continue;
			}

			if (spec.event_string() == "IdealProcessor")
			{
				safe_call(spec.SaveValue(tmp[0]));
				config_.ideal_processor = strtol(tmp[0].c_str(), NULL, 0);
			}
			else if (spec.event_string() == "AffinityMask")
			{
				safe_call(spec.SaveValue(tmp[0]));
				config_.affinity_mask = strtol(tmp[0].c_str(), NULL, 0);
			}
			else if (spec.event_string() == "AppMemory")
			{
				safe_call(spec.SaveValue(tmp[0]));
				if (tmp[0] == "64MB")
				{
					config_.system_mode = CxiExtendedHeader::SYSMODE_PROD;
				}
				else if (tmp[0] == "72MB")
				{
					config_.system_mode = CxiExtendedHeader::SYSMODE_DEV3;
				}
				else if (tmp[0] == "80MB")
				{
					config_.system_mode = CxiExtendedHeader::SYSMODE_DEV2;
				}
				else if (tmp[0] == "96MB")
				{
					config_.system_mode = CxiExtendedHeader::SYSMODE_DEV1;
				}
				else
				{
					fprintf(stderr, "[ERROR] Invalid AppMemory: %s\n", tmp[0].c_str());
					return 1;
				}
			}
			else if (spec.event_string() == "SnakeAppMemory")
			{
				safe_call(spec.SaveValue(tmp[0]));
				if (tmp[0] == "Legacy")
				{
					config_.system_mode_ext = CxiExtendedHeader::SYSMODE_SNAKE_LEGACY;
				}
				else if (tmp[0] == "124MB")
				{
					config_.system_mode_ext = CxiExtendedHeader::SYSMODE_SNAKE_PROD;
				}
				else if (tmp[0] == "178MB")
				{
					config_.system_mode_ext = CxiExtendedHeader::SYSMODE_SNAKE_DEV1;
				}
				else
				{
					fprintf(stderr, "[ERROR] Invalid SnakeAppMemory: %s\n", tmp[0].c_str());
					return 1;
				}
			}
			else if (spec.event_string() == "EnableL2Cache")
			{
				safe_call(spec.SaveValue(tmp[0]));
				safe_call(EvaluateBooleanString(config_.enable_l2_cache, tmp[0]));
			}
			else if (spec.event_string() == "Priority")
			{
				safe_call(spec.SaveValue(tmp[0]));
				config_.priority = strtol(tmp[0].c_str(), NULL, 0);
			}
			else if (spec.event_string() == "SnakeCpuSpeed")
			{
				safe_call(spec.SaveValue(tmp[0]));
				if (tmp[0] == "268MHz")
				{
					config_.cpu_speed = CxiExtendedHeader::CLOCK_268MHz;
				}
				else if (tmp[0] == "804MHz")
				{
					config_.cpu_speed = CxiExtendedHeader::CLOCK_804MHz;
				}
				else
				{
					fprintf(stderr, "[ERROR] Invalid SnakeCpuSpeed: %s\n", tmp[0].c_str());
					return 1;
				}
			}
			else if (spec.event_string() == "Dependency")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(AddDependency(tmp[i]));
				}
			}

			else
			{
				fprintf(stderr, "[ERROR] Unknown specfile key: ProcessConfig/%s\n", spec.event_string().c_str());
				return 1;
			}
		}

		return 0;
	}

	int SetSaveDataSize(std::string& size_str)
	{
		// tolower string
		std::transform(size_str.begin(), size_str.end(), size_str.begin(), ::tolower);

		u32 raw_size = strtoul(size_str.c_str(), NULL, 0);

		if (size_str.find("k") != std::string::npos && (size_str.substr((size_str.find("k"))) == "k" || size_str.substr((size_str.find("k"))) == "kb"))
		{
			raw_size *= 0x400;
		}
		else if (size_str.find("m") != std::string::npos && (size_str.substr((size_str.find("m"))) == "m" || size_str.substr((size_str.find("m"))) == "mb"))
		{
			raw_size *= 0x400 * 0x400;
		}
		else
		{
			fprintf(stderr, "[ERROR] Invalid SaveDataSize: %s\n", size_str.c_str());
			return 1;
		}

		// check size alignment
		if (raw_size % (64 * 0x400) != 0)
		{
			die("[ERROR] SaveDataSize must be aligned to 64K");
		}

		config_.save_data_size = raw_size;

		return 0;
	}

	int ParseSpecFileSaveData(YamlReader& spec)
	{
		u32 level;
		std::vector<std::string> tmp(1);

		// move into children of SaveData
		spec.GetEvent();

		// get level
		level = spec.level();

		while (spec.GetEvent() && spec.level() >= level)
		{
			if (!spec.is_event_scalar())
			{
				continue;
			}

			if (spec.event_string() == "SaveDataSize")
			{
				safe_call(spec.SaveValue(tmp[0]));
				safe_call(SetSaveDataSize(tmp[0]));
			}
			else if (spec.event_string() == "SystemSaveIds")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					config_.system_save_ids.push_back(strtoul(tmp[i].c_str(), NULL, 0) & 0xffffffff);
				}
			}
			else if (spec.event_string() == "UseExtdata")
			{
				safe_call(spec.SaveValue(tmp[0]));
				safe_call(EvaluateBooleanString(config_.use_extdata, tmp[0]));
			}
			else if (spec.event_string() == "ExtDataId")
			{
				safe_call(spec.SaveValue(tmp[0]));
				config_.extdata_id = strtoull(tmp[0].c_str(), NULL, 0);
			}
			else if (spec.event_string() == "UseOtherVariationSaveData")
			{
				safe_call(spec.SaveValue(tmp[0]));
				safe_call(EvaluateBooleanString(config_.use_other_variation_save_data, tmp[0]));
			}
			else if (spec.event_string() == "OtherUserSaveIds")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					config_.other_user_save_ids.push_back(strtoul(tmp[i].c_str(), NULL, 0) & 0xffffff);
				}
			}
			else if (spec.event_string() == "AccessibleSaveIds")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					config_.accessible_save_ids.push_back(strtoul(tmp[i].c_str(), NULL, 0) & 0xffffff);
				}
			}

			else
			{
				fprintf(stderr, "[ERROR] Unknown specfile key: SaveData/%s\n", spec.event_string().c_str());
				return 1;
			}
		}

		return 0;
	}

	int AddService(const std::string& service_str)
	{
		if (service_str.size() > 8)
		{
			fprintf(stderr, "[ERROR] Service name is too long: %s\n", service_str.c_str());
			return 1;
		}

		config_.services.push_back(service_str);

		return 0;
	}

	int AddIOMapping(const std::string& mapping_str)
	{
		std::string property;
		size_t pos1, pos2;
		struct CxiExtendedHeader::sMemoryMapping mapping;

		// get positions of '-' and ':'
		pos1 = mapping_str.find('-');
		pos2 = mapping_str.find(':');

		// check for invalid syntax
		// '-' shouldn't appear at the start
		// ':' shouldn't appear at all
		if (pos1 == 0 || pos2 != std::string::npos)
		{
			fprintf(stderr, "[ERROR] Invalid syntax in IORegisterMapping \"%s\"\n", mapping_str.c_str());
			return 1;
		}

		// npos means an end address wasn't specified, this is okay
		if (pos1 == std::string::npos)
		{
			mapping.start = strtoul(mapping_str.substr(0, pos2).c_str(), NULL, 16);
			mapping.end = 0;
		}
		// otherwise both start and end addresses should have been specified
		else
		{
			mapping.start = strtoul(mapping_str.substr(0, pos1).c_str(), NULL, 16);
			mapping.end = strtoul(mapping_str.substr(pos1 + 1).c_str(), NULL, 16);
		}

		if ((mapping.start & 0xfff) != 0x000)
		{
			fprintf(stderr, "[ERROR] %x in IORegisterMapping \"%s\" is not a valid start address\n", mapping.start, mapping_str.c_str());
			return 1;
		}

		if ((mapping.end & 0xfff) != 0xfff & mapping.end != 0)
		{
			fprintf(stderr, "[ERROR] %x in IORegisterMapping \"%s\" is not a valid end address\n", mapping.end, mapping_str.c_str());
			return 1;
		}

		config_.io_mappings.push_back(mapping);

		return 0;
	}

	int AddStaticMapping(const std::string& mapping_str)
	{
		std::string property("");
		size_t pos1, pos2;
		struct CxiExtendedHeader::sMemoryMapping mapping;

		// get positions of '-' and ':'
		pos1 = mapping_str.find('-');
		pos2 = mapping_str.find(':');
		
		if (pos2 != std::string::npos)
		{
			property = mapping_str.substr(pos2 + 1);
		}

		// check for invalid syntax
		// '-' or ':' shouldn't appear at the start
		// ':' shouldn't appear before '-'
		if (pos1 == 0 || pos2 == 0 || (pos2 < pos1 && pos1 != std::string::npos && pos2 != std::string::npos) || (pos2 != std::string::npos && property.empty()))
		{
			fprintf(stderr, "[ERROR] Invalid syntax in MemoryMapping \"%s\"\n", mapping_str.c_str());
			return 1;
		}

		// npos means an end address wasn't specified, this is okay
		if (pos1 == std::string::npos)
		{
			mapping.start = strtoul(mapping_str.substr(0, pos2).c_str(), NULL, 16);
			mapping.end = 0;
		}
		// otherwise both start and end addresses should have been specified
		else
		{
			mapping.start = strtoul(mapping_str.substr(0, pos1).c_str(), NULL, 16);
			mapping.end = strtoul(mapping_str.substr(pos1 + 1).c_str(), NULL, 16);
		}

		if ((mapping.start & 0xfff) != 0x000)
		{
			fprintf(stderr, "[ERROR] %x in MemoryMapping \"%s\" is not a valid start address\n", mapping.start, mapping_str.c_str());
			return 1;
		}

		if ((mapping.end & 0xfff) != 0xfff & mapping.end != 0)
		{
			fprintf(stderr, "[ERROR] %x in MemoryMapping \"%s\" is not a valid end address\n", mapping.end, mapping_str.c_str());
			return 1;
		}

		// the user has specified properties about the mapping
		if (property.size())
		{
			if (property == "r")
			{
				mapping.is_read_only = true;
			}
			else
			{
				fprintf(stderr, "[ERROR] %s in MemoryMapping \"%s\" is not a valid mapping property\n", property.c_str(), mapping_str.c_str());
				return 1;
			}
		}

		config_.static_mappings.push_back(mapping);

		return 0;
	}

	int AddFSAccessRight(const std::string& right_str)
	{
		if (right_str == "CategorySystemApplication")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CATEGORY_SYSTEM_APPLICATION;
		}
		else if (right_str == "CategoryHardwareCheck")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CATEGORY_HARDWARE_CHECK;
		}
		else if (right_str == "CategoryFileSystemTool")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CATEGORY_FILE_SYSTEM_TOOL;
		}
		else if (right_str == "Debug")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_DEBUG;
		}
		else if (right_str == "TwlCard" || right_str == "TwlCardBackup")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_TWL_CARD;
		}
		else if (right_str == "TwlNand" || right_str == "TwlNandData")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_TWL_NAND;
		}
		else if (right_str == "Boss")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_BOSS;
		}
		else if (right_str == "DirectSdmc" || right_str == "Sdmc")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_DIRECT_SDMC;
			config_.arm9_rights |= CxiExtendedHeader::IORIGHT_USE_DIRECT_SDMC;
		}
		else if (right_str == "Core")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CORE;
		}
		else if (right_str == "CtrNandRo" || right_str == "NandRo")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CTR_NAND_RO;
		}
		else if (right_str == "CtrNandRw" || right_str == "NandRw")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CTR_NAND_RW;
		}
		else if (right_str == "CtrNandRoWrite" || right_str == "NandRoWrite")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CTR_NAND_RO_WRITE;
		}
		else if (right_str == "CategorySystemSettings")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CATEGORY_SYSTEM_SETTINGS;
		}
		else if (right_str == "Cardboard" || right_str == "SystemTransfer")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CARD_BOARD;
		}
		else if (right_str == "ExportInportIvs")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_EXPORT_IMPORT_IVS;
		}
		else if (right_str == "DirectSdmcWrite" || right_str == "SdmcWriteOnly")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_DIRECT_SDMC_WRITE;
		}
		else if (right_str == "SwitchCleanup")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_SWITCH_CLEANUP;
		}
		else if (right_str == "SaveDataMove")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_SAVE_DATA_MOVE;
		}
		else if (right_str == "Shop")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_SHOP;
		}
		else if (right_str == "Shell")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_SHELL;
		}
		else if (right_str == "CategoryHomeMenu")
		{
			config_.fs_rights |= CxiExtendedHeader::FSRIGHT_CATEGORY_HOME_MENU;
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown FS Access right: %s\n", right_str.c_str());
			return 1;
		}
		
		return 0;
	}

	int AddKernelFlag(const std::string& flag_str)
	{
		if (flag_str == "PermitDebug")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_PERMIT_DEBUG;
		}
		else if (flag_str == "ForceDebug")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_FORCE_DEBUG;
		}
		else if (flag_str == "CanUseNonAlphaNum")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_CAN_USE_NON_ALPHABET_AND_NUMBER;
		}
		else if (flag_str == "CanWriteSharedPage")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_CAN_WRITE_SHARED_PAGE;
		}
		else if (flag_str == "CanUsePriviligedPriority")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_CAN_USE_PRIVILEGE_PRIORITY;
		}
		else if (flag_str == "PermitMainFunctionArgument")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_PERMIT_MAIN_FUNCTION_ARGUMENT;
		}
		else if (flag_str == "CanShareDeviceMemory")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_CAN_SHARE_DEVICE_MEMORY;
		}
		else if (flag_str == "RunnableOnSleep")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_RUNNABLE_ON_SLEEP;
		}
		else if (flag_str == "SpecialMemoryLayout")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_SPECIAL_MEMORY_LAYOUT;
		}
		else if (flag_str == "CanAccessCore2")
		{
			config_.kernel_flags |= CxiExtendedHeader::KERNFLAG_CAN_ACCESS_CORE2;
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown Kernel Flag: %s\n", flag_str.c_str());
			return 1;
		}

		return 0;
	}

	int AddArm9AccessRight(const std::string& right_str)
	{
		if (right_str == "MountNand")
		{
			config_.arm9_rights |= CxiExtendedHeader::IORIGHT_FS_MOUNT_NAND;
		}
		else if (right_str == "MountNandROWrite")
		{
			config_.arm9_rights |= CxiExtendedHeader::IORIGHT_FS_MOUNT_NAND_RO_WRITE;
		}
		else if (right_str == "MountTwlN")
		{
			config_.arm9_rights |= CxiExtendedHeader::IORIGHT_FS_MOUNT_TWLN;
		}
		else if (right_str == "MountWNand")
		{
			config_.arm9_rights |= CxiExtendedHeader::IORIGHT_FS_MOUNT_WNAND;
		}
		else if (right_str == "MountCardSpi")
		{
			config_.arm9_rights |= CxiExtendedHeader::IORIGHT_FS_MOUNT_CARD_SPI;
		}
		else if (right_str == "UseSDIF3")
		{
			config_.arm9_rights |= CxiExtendedHeader::IORIGHT_USE_SDIF3;
		}
		else if (right_str == "CreateSeed")
		{
			config_.arm9_rights |= CxiExtendedHeader::IORIGHT_CREATE_SEED;
		}
		else if (right_str == "UseCardSpi")
		{
			config_.arm9_rights |= CxiExtendedHeader::IORIGHT_USE_CARD_SPI;
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown Arm9 Access right: %s\n", right_str.c_str());
			return 1;
		}

		return 0;
	}

	int ParseSpecFileRights(YamlReader& spec)
	{
		u32 level;
		std::vector<std::string> tmp(1);

		// move into children of SaveData
		spec.GetEvent();

		// get level
		level = spec.level();

		while (spec.GetEvent() && spec.level() >= level)
		{
			if (!spec.is_event_scalar())
			{
				continue;
			}

			if (spec.event_string() == "Services")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(AddService(tmp[i]));
				}
			}
			else if (spec.event_string() == "IORegisterMapping")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(AddIOMapping(tmp[i]));
				}
			}
			else if (spec.event_string() == "MemoryMapping")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(AddStaticMapping(tmp[i]));
				}
			}
			else if (spec.event_string() == "FSAccess")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(AddFSAccessRight(tmp[i]));
				}
			}
			else if (spec.event_string() == "KernelFlags")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(AddKernelFlag(tmp[i]));
				}
			}
			else if (spec.event_string() == "Arm9Access")
			{
				safe_call(spec.SaveValueSequence(tmp));
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(AddArm9AccessRight(tmp[i]));
				}
			}

			else
			{
				fprintf(stderr, "[ERROR] Unknown specfile key: Rights/%s\n", spec.event_string().c_str());
				return 1;
			}
		}

		return 0;
	}

	int ParseSpecFile()
	{
		YamlReader spec;
		u32 level;

		
		safe_call(spec.LoadFile(args_.spec_file));

		level = spec.level();
		while (spec.GetEvent() && spec.level() == level)
		{
			if (!spec.is_event_scalar())
			{
				continue;
			}

			if (spec.event_string() == "ProcessConfig")
			{
				safe_call(ParseSpecFileProccessConfig(spec));
			}
			else if (spec.event_string() == "SaveData")
			{
				safe_call(ParseSpecFileSaveData(spec));
			}
			else if (spec.event_string() == "Rights")
			{
				safe_call(ParseSpecFileRights(spec));
			}
			else
			{
				fprintf(stderr, "[ERROR] Unknown specfile key: %s\n", spec.event_string().c_str());
				return 1;
			}
		}

		return spec.is_error()? 1 : 0;
	}

	int MakeExefsCode()
	{
		ByteBuffer elf;

		if (elf.OpenFile(args_.elf_file) != 0)
		{
			die("[ERROR] Cannot open ELF file!");
		}

		safe_call(exefs_code_.CreateCodeBlob(elf.data(), true));

		return 0;
	}

	int MakeNcchLogo()
	{
		static const byte_t kCxiLogo[] =
		{
			0x11, 0x9C, 0x21, 0x00, 0x00, 0x64, 0x61, 0x72, 0x63, 0xFF, 0xFE, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7C, 0x21, 0x00, 0x00, 0x83, 0x30, 0x09, 0x24, 0x03, 0x00, 0x00, 0x40, 0x20, 0x03, 0x30, 0x13, 0xAB, 0x30, 0x18, 0x0F, 0x20, 0x1D, 0x02, 0xA0, 0x0B, 0x06, 0x20, 0x2B, 0x30, 0x18, 0x5A, 0x05, 0x20, 0x35, 0x10, 0x20, 0x39, 0x30, 0x2B, 0xA4, 0x20, 0x20, 0x40, 0xEA, 0x30, 0x45, 0x20, 0x1C, 0x30, 0x0B, 0x70, 0x60, 0x23, 0x08, 0x20, 0x59, 0x7A, 0x85, 0x30, 0x5D, 0x09, 0x00, 0x00, 0x28, 0x20, 0x2C, 0xA2, 0x20, 0x69, 0x21, 0x80, 0x19, 0x20, 0x0B, 0x04, 0x00, 0x00, 0xC4, 0x60, 0x47, 0xA0, 0x30, 0x5F, 0xCE, 0x20, 0x81, 0xC0, 0x1D, 0x00, 0x00, 0x9C, 0xA5, 0x20, 0x89, 0x12, 0x20, 0x75, 0x60, 0x1E, 0x50, 0x0B, 0x56, 0x30, 0x81, 0x55, 0x1F, 0x50, 0x17, 0x9A, 0x20, 0x8D, 0xA0, 0x60, 0x0B, 0xDE, 0x20, 0x99, 0x2A, 0x40, 0x20, 0x50, 0x2F, 0x22, 0x20, 0x9C, 0xE0, 0x60, 0x0B, 0x00, 0x20, 0x00, 0x2E, 0x20, 0xCB, 0x62, 0x00, 0x6C, 0x00, 0x79, 0x20, 0x00, 0x74, 0x20, 0xD5, 0x4E, 0x00, 0x69, 0x00, 0x6E, 0xA0, 0x20, 0x09, 0x65, 0x20, 0x05, 0x64, 0x00, 0x6F, 0x00, 0x4C, 0xA2, 0x20, 0x03, 0x67, 0x20, 0x07, 0x5F, 0x00, 0x55, 0x20, 0x03, 0x30, 0xAA, 0x20, 0x01, 0x2E, 0x20, 0x2D, 0x63, 0x01, 0x20, 0x2F, 0x44, 0x00, 0x40, 0x2F, 0x74, 0xA3, 0x20, 0x5F, 0x6D, 0x20, 0x51, 0x00, 0x00, 0x68, 0x40, 0x75, 0x70, 0x5D, 0x57, 0x62, 0x20, 0x6B, 0x74, 0x20, 0x81, 0x6F, 0x20, 0x1D, 0x70, 0x61, 0x30, 0x29, 0xD7, 0xF0, 0x27, 0x30, 0x21, 0x70, 0xE0, 0x21, 0x61, 0x20, 0xB1, 0x50, 0x2B, 0x01, 0x10, 0x8D, 0x18, 0x5F, 0x00, 0x53, 0x20, 0xBD, 0x30, 0xDD, 0x65, 0x00, 0x4F, 0x2F, 0x00, 0x75, 0x20, 0xF3, 0x43, 0x80, 0xD1, 0x30, 0x47, 0x01, 0x31, 0x01, 0x00, 0x10, 0x43, 0x6F, 0x42, 0x01, 0x80, 0x43, 0x00, 0x90, 0x87, 0x41, 0x03, 0x20, 0x43, 0x01, 0x90, 0x87, 0x00, 0x90, 0xCB, 0x01, 0x90, 0x87, 0xE0, 0x00, 0x91, 0x0F, 0xF1, 0x53, 0x90, 0x02, 0x43, 0x4C, 0x59, 0x54, 0xFF, 0x2C, 0xFE, 0x14, 0x33, 0x21, 0x02, 0x33, 0x03, 0x33, 0x0F, 0x6C, 0x79, 0x31, 0x74, 0x31, 0x30, 0x11, 0x43, 0x3C, 0x00, 0xC8, 0x43, 0x23, 0x0D, 0x03, 0x43, 0x74, 0x78, 0x6C, 0x31, 0x24, 0x63, 0x50, 0x22, 0xFA, 0x00, 0x00, 0x68, 0x62, 0x6C, 0x6F, 0x67, 0x6F, 0x5F, 0x00, 0x74, 0x6F, 0x70, 0x2E, 0x62, 0x63, 0x6C, 0x69, 0x81, 0x32, 0x18, 0x00, 0x6D, 0x61, 0x74, 0x31, 0x60, 0x63, 0x74, 0x86, 0x33, 0x57, 0x48, 0x62, 0x4D, 0x61, 0x32, 0xC3, 0xB0, 0x70, 0xFF, 0x35, 0xFF, 0xFF, 0x30, 0x03, 0x00, 0x40, 0x02, 0x15, 0x43, 0xB2, 0x04, 0x30, 0x5E, 0x98, 0xA0, 0xA3, 0x80, 0x3F, 0x50, 0x03, 0x23, 0x93, 0x61, 0x6E, 0x31, 0x48, 0x4C, 0x33, 0xE8, 0x04, 0xFF, 0x20, 0x5B, 0x52, 0x6F, 0x6F, 0x07, 0x74, 0x50, 0x61, 0x6E, 0x65, 0xE0, 0x60, 0x00, 0x80, 0x0E, 0x70, 0x47, 0x86, 0x50, 0xCF, 0x70, 0x61, 0x73, 0x31, 0x33, 0xDB, 0x70, 0x53, 0x03, 0xB3, 0x80, 0x53, 0x30, 0x01, 0x70, 0x50, 0xA0, 0x9B, 0x20, 0x42, 0x30, 0x03, 0x80, 0x53, 0x0B, 0x69, 0x63, 0x31, 0x80, 0x34, 0x90, 0x07, 0x30, 0xA7, 0x00, 0x11, 0x03, 0xC7, 0x01, 0x50, 0xA7, 0x23, 0x08, 0x00, 0x80, 0x41, 0xF1, 0x2B, 0x71, 0x95, 0x91, 0x1B, 0x83, 0xF1, 0x27, 0x80, 0x3F, 0x70, 0x61, 0x65, 0x60, 0xDB, 0x50, 0x07, 0x0C, 0x67, 0x72, 0x70, 0x31, 0x35, 0x21, 0x51, 0x33, 0x47, 0x72, 0xCD, 0x24, 0xDB, 0x82, 0x03, 0x67, 0x72, 0x51, 0x07, 0x30, 0x23, 0x3C, 0x25, 0x45, 0x07, 0x47, 0x5F, 0x41, 0x5F, 0x30, 0xA1, 0x02, 0x25, 0x37, 0x00, 0x01, 0x17, 0xD7, 0xF1, 0xD7, 0x30, 0x5F, 0x2C, 0x40, 0x3B, 0x42, 0xC0, 0x3B, 0x35, 0x7C, 0x00, 0x90, 0x2B, 0x67, 0x43, 0x00, 0x20, 0x2B, 0xD1, 0x7F, 0x67, 0x72, 0x50, 0xC7, 0x00, 0xB1, 0xE1, 0x01, 0x12, 0xBF, 0x40, 0xA0, 0x00, 0xB2, 0xBF, 0x62, 0x6F, 0x74, 0x74, 0x6F, 0x6D, 0xF2, 0x62, 0xC2, 0x09, 0x52, 0xBF, 0x50, 0xCF, 0x07, 0x52, 0xBF, 0xF0, 0xC2, 0x00, 0xE2, 0xBF, 0x42, 0xC3, 0x10, 0x00, 0xF2, 0xBF, 0x10, 0x76, 0x70, 0x1E, 0xF0, 0xF0, 0x0F, 0x0F, 0x30, 0x03, 0x02, 0x70, 0x1F, 0x9B, 0x4E, 0x44, 0xD7, 0x00, 0x2C, 0x8F, 0x00, 0x2D, 0x7F, 0x7D, 0x9D, 0xEE, 0x00, 0x4D, 0x9D, 0x11, 0x90, 0x00, 0xEF, 0x4E, 0x84, 0x06, 0x00, 0xA1, 0x00, 0x4D, 0xBD, 0x2B, 0xEE, 0x00, 0x00, 0xDB, 0xF6, 0xC5, 0x60, 0x77, 0x8D, 0x00, 0x30, 0x67, 0x3D, 0x23, 0xD5, 0x3D, 0x27, 0x40, 0x67, 0xFE, 0x00, 0x4E, 0x1D, 0x2A, 0x7A, 0xBE, 0x00, 0x00, 0x50, 0xFF, 0x57, 0xE9, 0x80, 0x17, 0xC5, 0x00, 0x4E, 0x5D, 0xFF, 0xA0, 0x79, 0x00, 0x50, 0x1F, 0x5F, 0x63, 0x1E, 0xD0, 0x00, 0xCF, 0x00, 0x7B, 0x38, 0x4F, 0x84, 0x00, 0xD1, 0x5D, 0x03, 0xF1, 0xEF, 0xFF, 0x1F, 0xF0, 0xF0, 0xFF, 0x81, 0xEF, 0x81, 0xFF, 0x3F, 0x8E, 0x21, 0xC6, 0x20, 0x1A, 0xE0, 0x20, 0x20, 0x92, 0x0F, 0x92, 0x1F, 0xC0, 0xF7, 0x00, 0x00, 0xFD, 0x02, 0xFF, 0xFF, 0x6E, 0xFF, 0x11, 0x06, 0x4E, 0x7A, 0xFF, 0x00, 0xFD, 0x00, 0x00, 0xF7, 0xC0, 0x01, 0x05, 0x00, 0x00, 0x00, 0x5E, 0xFF, 0x11, 0xFF, 0xFF, 0xF6, 0x0B, 0x08, 0x7F, 0x60, 0x10, 0xCF, 0x61, 0x73, 0xFF, 0xFF, 0x10, 0x01, 0x60, 0xFF, 0xCF, 0xE6, 0xFF, 0x7F, 0x0B, 0x71, 0x87, 0x04, 0xFA, 0x2C, 0xFF, 0x90, 0x03, 0x2D, 0x95, 0x4F, 0xFF, 0x04, 0xFC, 0x2C, 0xFF, 0xFF, 0x03, 0x00, 0x01, 0xA5, 0xFF, 0x90, 0x04, 0x5F, 0xCF, 0x10, 0x00, 0xEF, 0x2E, 0xD7, 0xA0, 0xF6, 0x18, 0x00, 0x00, 0xFC, 0x80, 0x47, 0x2D, 0x69, 0xFC, 0x00, 0x00, 0x01, 0xF6, 0x90, 0xFF, 0x5E, 0xFF, 0x01, 0x03, 0x3D, 0x72, 0x02, 0xC3, 0x0D, 0x8F, 0x20, 0xFF, 0xDF, 0x20, 0x42, 0xFF, 0x08, 0x00, 0x6E, 0xFF, 0x02, 0x40, 0xB3, 0x20, 0xFF, 0xC6, 0x83, 0x80, 0x77, 0xFA, 0x3E, 0xFF, 0x40, 0x04, 0x50, 0x9F, 0x41, 0xFF, 0x40, 0x01, 0x2D, 0xE4, 0x3E, 0xFA, 0x40, 0xFF, 0xEF, 0xFE, 0x04, 0x01, 0x08, 0xF5, 0xF1, 0x0D, 0x22, 0xEB, 0xAF, 0xEF, 0x00, 0xF0, 0xF0, 0x5F, 0x1F, 0xF1, 0xF5, 0x0F, 0x0D, 0x09, 0xFE, 0xEF, 0x08, 0x01, 0x72, 0xFF, 0xFF, 0x04, 0x53, 0x02, 0x07, 0xA0, 0xF6, 0xFF, 0x5E, 0xFC, 0x30, 0x5C, 0x7D, 0xE7, 0x20, 0x0C, 0x10, 0xF6, 0x90, 0x6E, 0x20, 0x48, 0xFF, 0xC3, 0x00, 0xFF, 0x01, 0x20, 0xFF, 0x0D, 0x8F, 0x00, 0x00, 0xDF, 0x32, 0x59, 0xB8, 0x22, 0xF2, 0x02, 0x20, 0x0F, 0x32, 0xF8, 0x30, 0x7D, 0xFC, 0xF8, 0x04, 0x00, 0x07, 0xF4, 0xF0, 0x0A, 0x0E, 0xF1, 0xF4, 0xFF, 0x00, 0xFD, 0xF8, 0xEC, 0xF5, 0xE0, 0xC0, 0x90, 0x2F, 0x00, 0x9F, 0x50, 0x10, 0xFF, 0xFF, 0xAF, 0x5F, 0xA0, 0x10, 0x50, 0x1F, 0x0D, 0x2E, 0x8D, 0x04, 0xF3, 0xF7, 0x08, 0x0C, 0x0C, 0xFA, 0xFD, 0x0C, 0x2F, 0x90, 0x3E, 0x77, 0x1F, 0x8F, 0x03, 0xCF, 0x8F, 0xFF, 0xFD, 0x5F, 0x1F, 0x06, 0x03, 0xEF, 0x00, 0xE2, 0x6C, 0xF4, 0x00, 0xF0, 0x1F, 0x02, 0x73, 0xEA, 0x01, 0x10, 0x1D, 0x00, 0xD0, 0x37, 0xA4, 0x63, 0xC2, 0xDF, 0x00, 0x6E, 0x28, 0x00, 0xC3, 0x6C, 0x00, 0x73, 0xEA, 0x2B, 0x01, 0x60, 0xFF, 0x30, 0x69, 0x00, 0x3F, 0x89, 0xFE, 0xFC, 0x20, 0x79, 0x3F, 0xFF, 0x00, 0x70, 0x7D, 0x23, 0x1B, 0x4F, 0xF5, 0x00, 0x7D, 0xE7, 0xF8, 0x00, 0x40, 0x0D, 0x10, 0x14, 0xCE, 0x01, 0x43, 0x4C, 0x49, 0x4D, 0xFF, 0xFE, 0x46, 0x14, 0x2F, 0xFF, 0x02, 0x02, 0x28, 0x24, 0x6E, 0x35, 0xA2, 0x69, 0x10, 0x6D, 0x61, 0x67, 0x24, 0x79, 0x00, 0x80, 0x00, 0x40, 0xFF, 0x52, 0x7D, 0x30, 0x0C, 0x07, 0x8F, 0xFF, 0x57, 0x9F, 0x38, 0x79, 0x00, 0x58, 0x7D, 0x00, 0xF0, 0x1F, 0x40, 0xD8, 0xB6, 0x53, 0x74, 0xDF, 0x00, 0x88, 0x27, 0x57, 0x5F, 0xFF, 0x28, 0x69, 0x00, 0x3F, 0xFF, 0xEF, 0xDD, 0x28, 0x79, 0x3F, 0xFF, 0xB2, 0x63, 0xDC, 0xFF, 0xFF, 0x98, 0x7D, 0xC7, 0x00, 0x67, 0xFF, 0x7F, 0x9D, 0x4F, 0xFF, 0x47, 0x0F, 0x48, 0xE5, 0x89, 0x47, 0x30, 0xD9, 0x50, 0xDD, 0x2F, 0xFF, 0x17, 0xE8, 0x00, 0xBF, 0x00, 0x4F, 0xFF, 0x02, 0x00, 0x10, 0x37, 0x00, 0x68, 0x7F, 0x01, 0x50, 0x7F, 0xB1, 0x00, 0x14, 0x92, 0x2F, 0x84, 0xBE, 0x00, 0x3F, 0xFF, 0x0E, 0x00, 0x20, 0x69, 0x9D, 0xF9, 0x05, 0x24, 0x9C, 0x61, 0xEF, 0x38, 0x67, 0x20, 0x04, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x38, 0x7F, 0x83, 0x28, 0x7D, 0x10, 0x90, 0x0F, 0x0F, 0xE0, 0x29, 0x17, 0x72, 0x1F, 0x50, 0xE0, 0x20, 0x0F, 0x10, 0x38, 0x79, 0x1B, 0xFF, 0xFF, 0x02, 0x02, 0x00, 0xFF, 0xB1, 0xDF, 0xFF, 0x20, 0x40, 0x2C, 0x02, 0x01, 0x1B, 0xFD, 0x80, 0xFF, 0xFD, 0x20, 0xB1, 0x20, 0x38, 0x00, 0xDF, 0xDF, 0x08, 0x01, 0x09, 0xF0, 0xF0, 0x0E, 0xD5, 0x2A, 0xC9, 0x28, 0x69, 0x1A, 0x30, 0x27, 0x0E, 0x20, 0x0F, 0x01, 0x2A, 0xDD, 0x90, 0x88, 0x5F, 0xF5, 0x7F, 0x38, 0xF7, 0xFF, 0xFE, 0x1A, 0xFF, 0x3A, 0xF5, 0x02, 0x2A, 0xF5, 0x30, 0x29, 0x50, 0x1D, 0xF0, 0x29, 0x83, 0xF0, 0x30, 0xF0, 0x7F, 0x25, 0xDE, 0x3A, 0x31, 0xD1, 0xF9, 0xFF, 0x7F, 0x60, 0xFE, 0x30, 0x8B, 0x6A, 0x3D, 0xFE, 0xF8, 0x2F, 0xCF, 0xC0, 0x44, 0x00, 0x28, 0x60, 0x01, 0xFF, 0xF5, 0x30, 0xA2, 0x2E, 0xAF, 0x80, 0x6A, 0x55, 0x03, 0x00, 0x30, 0xFF, 0xFE, 0xFF, 0xCF, 0x90, 0x32, 0x19, 0xFF, 0x38, 0x3A, 0x6D, 0xAF, 0xBF, 0xFF, 0xFF, 0x21, 0x2F, 0x0F, 0x29, 0x0A, 0xFB, 0x00, 0x00, 0xF2, 0x20, 0x87, 0x40, 0x2F, 0x20, 0x0F, 0xAF, 0x0F, 0x00, 0x11, 0xF2, 0xFB, 0x03, 0xFF, 0xE8, 0xFF, 0xBF, 0x1E, 0x9F, 0x22, 0x6E, 0x4A, 0x91, 0x01, 0xAF, 0xCF, 0xFF, 0xFF, 0x3F, 0x0F, 0xEF, 0x20, 0x0F, 0x67, 0x2E, 0x21, 0xFF, 0x72, 0x27, 0xFF, 0x03, 0x5B, 0x82, 0x70, 0x7F, 0x86, 0x77, 0x80, 0x01, 0x60, 0x7F, 0xF7, 0xF2, 0x7F, 0xBF, 0xD0, 0x70, 0xFF, 0x21, 0xFF, 0x20, 0x20, 0x03, 0xB1, 0xF5, 0xBF, 0x2F, 0x21, 0x23, 0x80, 0x39, 0x9F, 0xF2, 0xFD, 0xFF, 0x0B, 0x06, 0xFF, 0xDF, 0x00, 0x02, 0x00, 0x2F, 0x6F, 0x70, 0xB0, 0xBF, 0xFF, 0x40, 0xF1, 0x20, 0xC3, 0x07, 0x02, 0xDF, 0x7F, 0x00, 0x00, 0x02, 0xFB, 0xF6, 0xFD, 0xFF, 0xF2, 0xD0, 0x20, 0xB1, 0x0C, 0x1E, 0x00, 0x00, 0x07, 0x72, 0x87, 0x03, 0x74, 0x7F, 0x29, 0x73, 0xD4, 0x7F, 0x10, 0xE5, 0x56, 0xFD, 0x38, 0xF8, 0x00, 0x84, 0xBF, 0x41, 0x4E, 0x74, 0xBF, 0x9C, 0x63, 0x1A, 0x05, 0x70, 0x61, 0x74, 0x31, 0x3C, 0x63, 0x60, 0x1C, 0x67, 0x7B, 0x60, 0xF1, 0x22, 0x27, 0x3A, 0x7E, 0x53, 0x63, 0x65, 0x6E, 0x65, 0x08, 0x4F, 0x75, 0x74, 0x43, 0x2F, 0xFF, 0x47, 0x5F, 0x43, 0x10, 0x5F, 0x30, 0x30, 0xDF, 0xFF, 0x70, 0x61, 0x69, 0x31, 0x4D, 0x4C, 0x8B, 0x5A, 0x02, 0x00, 0x35, 0x19, 0x30, 0x43, 0x40, 0x2F, 0xFF, 0x04, 0x48, 0x62, 0x4D, 0x61, 0x74, 0x00, 0x2F, 0xFF, 0x48, 0x62, 0x0D, 0x52, 0x6F, 0x6F, 0x74, 0xE0, 0x48, 0x02, 0xE0, 0x9F, 0x42, 0x40, 0x9F, 0x56, 0x42, 0x08, 0x80, 0x9F, 0x41, 0x41, 0x3F, 0x41, 0x10, 0x0C, 0x81, 0x3F, 0x05, 0x33, 0x1F, 0x77, 0x00, 0xA2, 0x13, 0x49, 0x99, 0x58, 0x3D, 0x71, 0x8A, 0x00, 0x3A, 0x75, 0x0A, 0xEF, 0xE4, 0xC9, 0xFC, 0xB1, 0x00, 0x00, 0x99, 0x02, 0x63, 0xA9, 0x9B, 0x74, 0xE0, 0x00, 0x38, 0xD3, 0x33, 0xC0, 0x52, 0x6A, 0x2C
		};

		safe_call(logo_.alloc(0x2000));
		memcpy(logo_.data(), kCxiLogo, sizeof(kCxiLogo));
		Crypto::Sha256(logo_.data_const(), logo_.size(), logo_hash_);

		return 0;
	}

	int MakeExefs()
	{
		ByteBuffer banner, icon;
		
		safe_call(MakeExefsCode());
		safe_call(MakeNcchLogo());

		if (exefs_code_.code_size() > 0)
		{
			safe_call(exefs_.SetExefsFile(".code", exefs_code_.code_blob(), exefs_code_.code_size()));
		}
		else
		{
			die("[ERROR] No code binary was created!");
		}

		if (args_.banner_file)
		{
			if (banner.OpenFile(args_.banner_file) != 0)
			{
				die("[ERROR] Cannot open banner file!");
			}
			safe_call(exefs_.SetExefsFile("banner", banner.data(), banner.size()));
		}

		if (args_.icon_file)
		{
			if (icon.OpenFile(args_.icon_file) != 0)
			{
				die("[ERROR] Cannot open icon file!");
			}
			safe_call(exefs_.SetExefsFile("icon", icon.data(), icon.size()));
		}

		if (logo_.size())
		{
			safe_call(exefs_.SetExefsFile("logo", logo_.data_const(), logo_.size()));
		}

		safe_call(exefs_.CreateExefs());

		exefs_hashed_data_size_ = 0x200;
		Crypto::Sha256(exefs_.data_blob(), exefs_hashed_data_size_, exefs_hash_);

		return 0;
	}

	int MakeRomfs()
	{
		if (args_.romfs_dir)
		{
			safe_call(romfs_.CreateRomfs(args_.romfs_dir));
			
			// if romfs wasn't created
			if (romfs_.data_size() == 0)
			{
				die("[ERROR] Romfs wasn't created!");
			}
			
			// setup ivfc hash tree
			// save total romfs blob size, and any other important related values
			safe_call(ivfc_.CreateIvfcHashTree(romfs_.data_blob(), romfs_.data_size()));
				
			romfs_full_size_ = ivfc_.header_size() + align(romfs_.data_size(), Ivfc::kBlockSize) + ivfc_.level0_size() + ivfc_.level1_size();
			romfs_hashed_data_size_ = align(ivfc_.used_header_size(), 0x200);
			Crypto::Sha256(ivfc_.header_blob(), romfs_hashed_data_size_, romfs_hash_);
		}

		return 0;
	}

	int MakeExheader()
	{
		extended_header_.SetProcessName(config_.app_title);
		extended_header_.SetIsCodeCompressed(config_.is_compressed_code);
		extended_header_.SetIsSdmcTitle(config_.is_sdmc_title);
		extended_header_.SetRemasterVersion(config_.remaster_version);
		extended_header_.SetTextSegment(exefs_code_.text_address(), exefs_code_.text_page_num(), exefs_code_.text_size());
		extended_header_.SetRoDataSegment(exefs_code_.rodata_address(), exefs_code_.rodata_page_num(), exefs_code_.rodata_size());
		extended_header_.SetDataSegment(exefs_code_.data_address(), exefs_code_.data_page_num(), exefs_code_.data_size());
		extended_header_.SetStackSize(config_.stack_size);
		extended_header_.SetBssSize(exefs_code_.bss_size());
		safe_call(extended_header_.SetDependencyList(config_.dependency_list));
		extended_header_.SetSaveDataSize(config_.save_data_size);
		extended_header_.SetJumpId(config_.jump_id);

		extended_header_.SetProgramId(config_.program_id);
		extended_header_.SetFirmwareTitleId(config_.firmware_title_id);
		extended_header_.SetEnableL2Cache(config_.enable_l2_cache);
		extended_header_.SetCpuSpeed(config_.cpu_speed);
		extended_header_.SetSystemModeExt(config_.system_mode_ext);
		safe_call(extended_header_.SetIdealProcessor(config_.ideal_processor));
		safe_call(extended_header_.SetProcessAffinityMask(config_.affinity_mask));
		extended_header_.SetSystemMode(config_.system_mode);
		safe_call(extended_header_.SetProcessPriority(config_.priority));

		// catch illegal combinations
		if ((config_.accessible_save_ids.size() > 0) & (config_.use_extdata || config_.extdata_id))
		{
			die("[ERROR] AccessibleSaveIds & Extdata cannot both be used.");
		}

		if ((config_.accessible_save_ids.size() > 0) & (config_.other_user_save_ids.size() > 0))
		{
			die("[ERROR] AccessibleSaveIds & OtherUserSaveIds cannot both be used.");
		}


		if ((config_.use_extdata || config_.extdata_id) || (config_.other_user_save_ids.size() > 0))
		{
			if (config_.extdata_id)
			{
				extended_header_.SetExtdataId(config_.extdata_id);
			}
			// if extdata_id isn't set, use the program uniqueid as the extdata_id
			else
			{
				extended_header_.SetExtdataId((config_.program_id >> 8) & 0xffffff);
			}
			safe_call(extended_header_.SetOtherUserSaveIds(config_.other_user_save_ids, config_.use_other_variation_save_data));
		}
		else if (config_.accessible_save_ids.size() > 0)
		{
			safe_call(extended_header_.SetAccessibleSaveIds(config_.accessible_save_ids, config_.use_other_variation_save_data));
		}
		else
		{
			safe_call(extended_header_.SetOtherUserSaveIds(config_.other_user_save_ids, config_.use_other_variation_save_data));
		}


		safe_call(extended_header_.SetSystemSaveIds(config_.system_save_ids));
		extended_header_.SetFsAccessRights(config_.fs_rights);
		extended_header_.SetUseRomfs(romfs_full_size_ > 0);

		safe_call(extended_header_.SetServiceList(config_.services));
		extended_header_.SetMaxCpu(config_.max_cpu);
		extended_header_.SetResourceLimitCategory(config_.resource_limit_category);

		extended_header_.SetAllowedInterupts(config_.interupts);
		extended_header_.SetAllowedSupervisorCalls(config_.svc_calls);
		extended_header_.SetReleaseKernelVersion(config_.release_kernel_version[0], config_.release_kernel_version[1]);
		extended_header_.SetHandleTableSize(config_.handle_table_size);
		extended_header_.SetMemoryType(config_.memory_type);
		extended_header_.SetKernelFlags(config_.kernel_flags);
		extended_header_.SetStaticMapping(config_.static_mappings);
		extended_header_.SetIOMapping(config_.io_mappings);

		extended_header_.SetArm9IOControl(config_.arm9_rights, config_.desc_version);

		safe_call(extended_header_.CreateExheader(cxi_rsa_key_.modulus, accessdesc_rsa_key_.modulus, accessdesc_rsa_key_.priv_exponent));

		Crypto::Sha256(extended_header_.exheader_blob(), extended_header_.exheader_size(), extended_header_hash_);

		return 0;
	}

	int MakeHeader()
	{
		header_.SetTitleId(config_.title_id);
		header_.SetProgramId(config_.program_id);
		header_.SetProductCode(config_.product_code);
		header_.SetMakerCode(config_.maker_code);
		header_.SetNoCrypto();
		header_.SetPlatform(NcchHeader::CTR);
		
		if (extended_header_.exheader_size())
		{
			header_.SetExheaderData(extended_header_.exheader_size(), extended_header_.accessdesc_size(), extended_header_hash_);
		}
		else
		{
			die("[ERROR] No Extended header was created!");
		}
		
		/*
		if (logo_.size())
		{
			header_.SetLogoData(logo_.size(), logo_hash_);
		}
		*/

		if (exefs_code_.module_id_size() > 0)
		{
			header_.SetPlainRegionData(exefs_code_.module_id_size());
		}
		
		if (exefs_.data_size() > 0)
		{
			header_.SetExefsData(exefs_.data_size(), exefs_hashed_data_size_, exefs_hash_);
		}
		else
		{
			die("[ERROR] No Exefs was created!");
		}

		if (romfs_full_size_ > 0)
		{
			header_.SetRomfsData(romfs_full_size_, romfs_hashed_data_size_, romfs_hash_);
			header_.SetNcchType(NcchHeader::APPLICATION, NcchHeader::EXECUTABLE);
		}
		else
		{
			header_.SetNcchType(NcchHeader::APPLICATION, NcchHeader::EXECUTABLE_WITHOUT_ROMFS);
		}

		safe_call(header_.CreateHeader(cxi_rsa_key_.modulus, cxi_rsa_key_.priv_exponent));

		return 0;
	}

	int WriteToFile()
	{
		// todo, ensure gaps between ncch sections are written with zeros and not just skipped over
		FILE *fp;

		if ((fp = fopen(args_.out_file, "wb")) == NULL)
		{
			die("[ERROR] Failed to create output file.");
		}

		// write header
		fseek(fp, 0, SEEK_SET);
		fwrite(header_.header_blob(), 1, header_.header_size(), fp);

		// write exheader
		if (header_.exheader_offset())
		{
			fseek(fp, header_.exheader_offset(), SEEK_SET);
			fwrite(extended_header_.exheader_blob(), 1, extended_header_.exheader_size(), fp);
			fwrite(extended_header_.accessdesc_blob(), 1, extended_header_.accessdesc_size(), fp);
		}

		// write logo
		if (header_.logo_offset())
		{
			fseek(fp, header_.logo_offset(), SEEK_SET);
			fwrite(logo_.data_const(), 1, logo_.size(), fp);
		}

		// write plain region
		if (header_.plain_region_offset())
		{
			fseek(fp, header_.plain_region_offset(), SEEK_SET);
			fwrite(exefs_code_.module_id_blob(), 1, exefs_code_.module_id_size(), fp);
		}
		
		// write exefs
		if (header_.exefs_offset())
		{
			fseek(fp, header_.exefs_offset(), SEEK_SET);
			fwrite(exefs_.data_blob(), 1, exefs_.data_size(), fp);
		}
		
		// write romfs
		if (header_.romfs_offset())
		{
			fseek(fp, header_.romfs_offset(), SEEK_SET);
			fwrite(ivfc_.header_blob(), 1, ivfc_.header_size(), fp);

			// write level2 a.k.a. romfs
			for (u32 i = 0; i < romfs_.data_size() / Ivfc::kBlockSize; i++)
			{
				fwrite(romfs_.data_blob() + i*Ivfc::kBlockSize, 1, Ivfc::kBlockSize, fp);
			}
			if (romfs_.data_size() % Ivfc::kBlockSize)
			{
				u8 block[Ivfc::kBlockSize] = { 0 };
				memcpy(block, romfs_.data_blob() + (romfs_.data_size() / Ivfc::kBlockSize)*Ivfc::kBlockSize, romfs_.data_size() % Ivfc::kBlockSize);
				fwrite(block, 1, Ivfc::kBlockSize, fp);
			}
			
			fwrite(ivfc_.level0_blob(), 1, ivfc_.level0_size(), fp);
			fwrite(ivfc_.level1_blob(), 1, ivfc_.level1_size(), fp);
		}

		fclose(fp);
		return 0;
	}
};

int usage(const char *prog_name)
{
	fprintf(stderr,
		"Usage:\n"
		"    %s input.elf spec.yaml output.cxi [options]\n\n"
		"Options:\n"
		"    --icon=input.smdh  : Embed homemenu icon\n"
		"    --banner=input.bnr : Embed homemenu banner\n"
		"    --romfs=dir        : Embed RomFS\n"
		"    --uniqueid=id      : Specify NCCH UniqueID\n"
		"    --productcode=str  : Specify NCCH ProductCode\n"
		"    --title=str        : Specify ExHeader name\n"
		, prog_name);
	return 1;
}

int ParseArgs(struct sArgInfo& info, int argc, char **argv)
{
	// clear struct
	memset((u8*)&info, 0, sizeof(struct sArgInfo));

	// return if minimum requirements not met
	if (argc < 4)
	{
		return usage(argv[0]);
	}

	info.elf_file = FixMinGWPath(argv[1]);
	info.spec_file = FixMinGWPath(argv[2]);
	info.out_file = FixMinGWPath(argv[3]);

	char *arg, *value;

	for (int i = 4; i < argc; i++)
	{
		arg = argv[i];
		if (strncmp(arg, "--", 2) != 0)
		{
			return usage(argv[0]);
		}
		
		// skip over "--" to get name of argument
		arg += 2;
		
		// get argument value
		value = strchr(arg, '=');

		// check there is actually an argument value
		if (value == NULL || value[1] == '\0')
		{
			return usage(argv[0]);
		}

		// skip over "=", overwriting it to null byte
		*value++ = '\0';

		if (strcmp(arg, "icon") == 0)
		{
			info.icon_file = FixMinGWPath(value);
		}
		else if (strcmp(arg, "banner") == 0)
		{
			info.banner_file = FixMinGWPath(value);
		}
		else if (strcmp(arg, "romfs") == 0)
		{
			info.romfs_dir = FixMinGWPath(value);
		}
		else if (strcmp(arg, "banner") == 0)
		{
			info.banner_file = FixMinGWPath(value);
		}
		else if (strcmp(arg, "uniqueid") == 0)
		{
			info.unique_id = value;
		}
		else if (strcmp(arg, "productcode") == 0)
		{
			info.product_code = value;
		}
		else if (strcmp(arg, "title") == 0)
		{
			info.title = value;
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown argument: %s\n", arg);
			return usage(argv[0]);
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct sArgInfo args;
	NcchBuilder cxi;

	safe_call(ParseArgs(args, argc, argv));
	safe_call(cxi.BuildNcch(args));

	return 0;
}