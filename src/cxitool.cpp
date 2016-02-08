#include <cstring>
#include <algorithm>

#include "crypto.h"
#include "YamlReader.h"

#include "ByteBuffer.h"

#include "ncchheader.h"
#include "ncchextendedheader.h"
#include "exefscode.h"
#include "exefs.h"
#include "romfs2.h"

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

static const byte_t CXI_LOGO[0x2000] =
{
	0x11, 0x9C, 0x21, 0x00, 0x00, 0x64, 0x61, 0x72, 0x63, 0xFF, 0xFE, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7C, 0x21, 0x00, 0x00, 0x83, 0x30, 0x09, 0x24, 0x03, 0x00, 0x00, 0x40, 0x20, 0x03, 0x30, 0x13, 0xAB, 0x30, 0x18, 0x0F, 0x20, 0x1D, 0x02, 0xA0, 0x0B, 0x06, 0x20, 0x2B, 0x30, 0x18, 0x5A, 0x05, 0x20, 0x35, 0x10, 0x20, 0x39, 0x30, 0x2B, 0xA4, 0x20, 0x20, 0x40, 0xEA, 0x30, 0x45, 0x20, 0x1C, 0x30, 0x0B, 0x70, 0x60, 0x23, 0x08, 0x20, 0x59, 0x7A, 0x85, 0x30, 0x5D, 0x09, 0x00, 0x00, 0x28, 0x20, 0x2C, 0xA2, 0x20, 0x69, 0x21, 0x80, 0x19, 0x20, 0x0B, 0x04, 0x00, 0x00, 0xC4, 0x60, 0x47, 0xA0, 0x30, 0x5F, 0xCE, 0x20, 0x81, 0xC0, 0x1D, 0x00, 0x00, 0x9C, 0xA5, 0x20, 0x89, 0x12, 0x20, 0x75, 0x60, 0x1E, 0x50, 0x0B, 0x56, 0x30, 0x81, 0x55, 0x1F, 0x50, 0x17, 0x9A, 0x20, 0x8D, 0xA0, 0x60, 0x0B, 0xDE, 0x20, 0x99, 0x2A, 0x40, 0x20, 0x50, 0x2F, 0x22, 0x20, 0x9C, 0xE0, 0x60, 0x0B, 0x00, 0x20, 0x00, 0x2E, 0x20, 0xCB, 0x62, 0x00, 0x6C, 0x00, 0x79, 0x20, 0x00, 0x74, 0x20, 0xD5, 0x4E, 0x00, 0x69, 0x00, 0x6E, 0xA0, 0x20, 0x09, 0x65, 0x20, 0x05, 0x64, 0x00, 0x6F, 0x00, 0x4C, 0xA2, 0x20, 0x03, 0x67, 0x20, 0x07, 0x5F, 0x00, 0x55, 0x20, 0x03, 0x30, 0xAA, 0x20, 0x01, 0x2E, 0x20, 0x2D, 0x63, 0x01, 0x20, 0x2F, 0x44, 0x00, 0x40, 0x2F, 0x74, 0xA3, 0x20, 0x5F, 0x6D, 0x20, 0x51, 0x00, 0x00, 0x68, 0x40, 0x75, 0x70, 0x5D, 0x57, 0x62, 0x20, 0x6B, 0x74, 0x20, 0x81, 0x6F, 0x20, 0x1D, 0x70, 0x61, 0x30, 0x29, 0xD7, 0xF0, 0x27, 0x30, 0x21, 0x70, 0xE0, 0x21, 0x61, 0x20, 0xB1, 0x50, 0x2B, 0x01, 0x10, 0x8D, 0x18, 0x5F, 0x00, 0x53, 0x20, 0xBD, 0x30, 0xDD, 0x65, 0x00, 0x4F, 0x2F, 0x00, 0x75, 0x20, 0xF3, 0x43, 0x80, 0xD1, 0x30, 0x47, 0x01, 0x31, 0x01, 0x00, 0x10, 0x43, 0x6F, 0x42, 0x01, 0x80, 0x43, 0x00, 0x90, 0x87, 0x41, 0x03, 0x20, 0x43, 0x01, 0x90, 0x87, 0x00, 0x90, 0xCB, 0x01, 0x90, 0x87, 0xE0, 0x00, 0x91, 0x0F, 0xF1, 0x53, 0x90, 0x02, 0x43, 0x4C, 0x59, 0x54, 0xFF, 0x2C, 0xFE, 0x14, 0x33, 0x21, 0x02, 0x33, 0x03, 0x33, 0x0F, 0x6C, 0x79, 0x31, 0x74, 0x31, 0x30, 0x11, 0x43, 0x3C, 0x00, 0xC8, 0x43, 0x23, 0x0D, 0x03, 0x43, 0x74, 0x78, 0x6C, 0x31, 0x24, 0x63, 0x50, 0x22, 0xFA, 0x00, 0x00, 0x68, 0x62, 0x6C, 0x6F, 0x67, 0x6F, 0x5F, 0x00, 0x74, 0x6F, 0x70, 0x2E, 0x62, 0x63, 0x6C, 0x69, 0x81, 0x32, 0x18, 0x00, 0x6D, 0x61, 0x74, 0x31, 0x60, 0x63, 0x74, 0x86, 0x33, 0x57, 0x48, 0x62, 0x4D, 0x61, 0x32, 0xC3, 0xB0, 0x70, 0xFF, 0x35, 0xFF, 0xFF, 0x30, 0x03, 0x00, 0x40, 0x02, 0x15, 0x43, 0xB2, 0x04, 0x30, 0x5E, 0x98, 0xA0, 0xA3, 0x80, 0x3F, 0x50, 0x03, 0x23, 0x93, 0x61, 0x6E, 0x31, 0x48, 0x4C, 0x33, 0xE8, 0x04, 0xFF, 0x20, 0x5B, 0x52, 0x6F, 0x6F, 0x07, 0x74, 0x50, 0x61, 0x6E, 0x65, 0xE0, 0x60, 0x00, 0x80, 0x0E, 0x70, 0x47, 0x86, 0x50, 0xCF, 0x70, 0x61, 0x73, 0x31, 0x33, 0xDB, 0x70, 0x53, 0x03, 0xB3, 0x80, 0x53, 0x30, 0x01, 0x70, 0x50, 0xA0, 0x9B, 0x20, 0x42, 0x30, 0x03, 0x80, 0x53, 0x0B, 0x69, 0x63, 0x31, 0x80, 0x34, 0x90, 0x07, 0x30, 0xA7, 0x00, 0x11, 0x03, 0xC7, 0x01, 0x50, 0xA7, 0x23, 0x08, 0x00, 0x80, 0x41, 0xF1, 0x2B, 0x71, 0x95, 0x91, 0x1B, 0x83, 0xF1, 0x27, 0x80, 0x3F, 0x70, 0x61, 0x65, 0x60, 0xDB, 0x50, 0x07, 0x0C, 0x67, 0x72, 0x70, 0x31, 0x35, 0x21, 0x51, 0x33, 0x47, 0x72, 0xCD, 0x24, 0xDB, 0x82, 0x03, 0x67, 0x72, 0x51, 0x07, 0x30, 0x23, 0x3C, 0x25, 0x45, 0x07, 0x47, 0x5F, 0x41, 0x5F, 0x30, 0xA1, 0x02, 0x25, 0x37, 0x00, 0x01, 0x17, 0xD7, 0xF1, 0xD7, 0x30, 0x5F, 0x2C, 0x40, 0x3B, 0x42, 0xC0, 0x3B, 0x35, 0x7C, 0x00, 0x90, 0x2B, 0x67, 0x43, 0x00, 0x20, 0x2B, 0xD1, 0x7F, 0x67, 0x72, 0x50, 0xC7, 0x00, 0xB1, 0xE1, 0x01, 0x12, 0xBF, 0x40, 0xA0, 0x00, 0xB2, 0xBF, 0x62, 0x6F, 0x74, 0x74, 0x6F, 0x6D, 0xF2, 0x62, 0xC2, 0x09, 0x52, 0xBF, 0x50, 0xCF, 0x07, 0x52, 0xBF, 0xF0, 0xC2, 0x00, 0xE2, 0xBF, 0x42, 0xC3, 0x10, 0x00, 0xF2, 0xBF, 0x10, 0x76, 0x70, 0x1E, 0xF0, 0xF0, 0x0F, 0x0F, 0x30, 0x03, 0x02, 0x70, 0x1F, 0x9B, 0x4E, 0x44, 0xD7, 0x00, 0x2C, 0x8F, 0x00, 0x2D, 0x7F, 0x7D, 0x9D, 0xEE, 0x00, 0x4D, 0x9D, 0x11, 0x90, 0x00, 0xEF, 0x4E, 0x84, 0x06, 0x00, 0xA1, 0x00, 0x4D, 0xBD, 0x2B, 0xEE, 0x00, 0x00, 0xDB, 0xF6, 0xC5, 0x60, 0x77, 0x8D, 0x00, 0x30, 0x67, 0x3D, 0x23, 0xD5, 0x3D, 0x27, 0x40, 0x67, 0xFE, 0x00, 0x4E, 0x1D, 0x2A, 0x7A, 0xBE, 0x00, 0x00, 0x50, 0xFF, 0x57, 0xE9, 0x80, 0x17, 0xC5, 0x00, 0x4E, 0x5D, 0xFF, 0xA0, 0x79, 0x00, 0x50, 0x1F, 0x5F, 0x63, 0x1E, 0xD0, 0x00, 0xCF, 0x00, 0x7B, 0x38, 0x4F, 0x84, 0x00, 0xD1, 0x5D, 0x03, 0xF1, 0xEF, 0xFF, 0x1F, 0xF0, 0xF0, 0xFF, 0x81, 0xEF, 0x81, 0xFF, 0x3F, 0x8E, 0x21, 0xC6, 0x20, 0x1A, 0xE0, 0x20, 0x20, 0x92, 0x0F, 0x92, 0x1F, 0xC0, 0xF7, 0x00, 0x00, 0xFD, 0x02, 0xFF, 0xFF, 0x6E, 0xFF, 0x11, 0x06, 0x4E, 0x7A, 0xFF, 0x00, 0xFD, 0x00, 0x00, 0xF7, 0xC0, 0x01, 0x05, 0x00, 0x00, 0x00, 0x5E, 0xFF, 0x11, 0xFF, 0xFF, 0xF6, 0x0B, 0x08, 0x7F, 0x60, 0x10, 0xCF, 0x61, 0x73, 0xFF, 0xFF, 0x10, 0x01, 0x60, 0xFF, 0xCF, 0xE6, 0xFF, 0x7F, 0x0B, 0x71, 0x87, 0x04, 0xFA, 0x2C, 0xFF, 0x90, 0x03, 0x2D, 0x95, 0x4F, 0xFF, 0x04, 0xFC, 0x2C, 0xFF, 0xFF, 0x03, 0x00, 0x01, 0xA5, 0xFF, 0x90, 0x04, 0x5F, 0xCF, 0x10, 0x00, 0xEF, 0x2E, 0xD7, 0xA0, 0xF6, 0x18, 0x00, 0x00, 0xFC, 0x80, 0x47, 0x2D, 0x69, 0xFC, 0x00, 0x00, 0x01, 0xF6, 0x90, 0xFF, 0x5E, 0xFF, 0x01, 0x03, 0x3D, 0x72, 0x02, 0xC3, 0x0D, 0x8F, 0x20, 0xFF, 0xDF, 0x20, 0x42, 0xFF, 0x08, 0x00, 0x6E, 0xFF, 0x02, 0x40, 0xB3, 0x20, 0xFF, 0xC6, 0x83, 0x80, 0x77, 0xFA, 0x3E, 0xFF, 0x40, 0x04, 0x50, 0x9F, 0x41, 0xFF, 0x40, 0x01, 0x2D, 0xE4, 0x3E, 0xFA, 0x40, 0xFF, 0xEF, 0xFE, 0x04, 0x01, 0x08, 0xF5, 0xF1, 0x0D, 0x22, 0xEB, 0xAF, 0xEF, 0x00, 0xF0, 0xF0, 0x5F, 0x1F, 0xF1, 0xF5, 0x0F, 0x0D, 0x09, 0xFE, 0xEF, 0x08, 0x01, 0x72, 0xFF, 0xFF, 0x04, 0x53, 0x02, 0x07, 0xA0, 0xF6, 0xFF, 0x5E, 0xFC, 0x30, 0x5C, 0x7D, 0xE7, 0x20, 0x0C, 0x10, 0xF6, 0x90, 0x6E, 0x20, 0x48, 0xFF, 0xC3, 0x00, 0xFF, 0x01, 0x20, 0xFF, 0x0D, 0x8F, 0x00, 0x00, 0xDF, 0x32, 0x59, 0xB8, 0x22, 0xF2, 0x02, 0x20, 0x0F, 0x32, 0xF8, 0x30, 0x7D, 0xFC, 0xF8, 0x04, 0x00, 0x07, 0xF4, 0xF0, 0x0A, 0x0E, 0xF1, 0xF4, 0xFF, 0x00, 0xFD, 0xF8, 0xEC, 0xF5, 0xE0, 0xC0, 0x90, 0x2F, 0x00, 0x9F, 0x50, 0x10, 0xFF, 0xFF, 0xAF, 0x5F, 0xA0, 0x10, 0x50, 0x1F, 0x0D, 0x2E, 0x8D, 0x04, 0xF3, 0xF7, 0x08, 0x0C, 0x0C, 0xFA, 0xFD, 0x0C, 0x2F, 0x90, 0x3E, 0x77, 0x1F, 0x8F, 0x03, 0xCF, 0x8F, 0xFF, 0xFD, 0x5F, 0x1F, 0x06, 0x03, 0xEF, 0x00, 0xE2, 0x6C, 0xF4, 0x00, 0xF0, 0x1F, 0x02, 0x73, 0xEA, 0x01, 0x10, 0x1D, 0x00, 0xD0, 0x37, 0xA4, 0x63, 0xC2, 0xDF, 0x00, 0x6E, 0x28, 0x00, 0xC3, 0x6C, 0x00, 0x73, 0xEA, 0x2B, 0x01, 0x60, 0xFF, 0x30, 0x69, 0x00, 0x3F, 0x89, 0xFE, 0xFC, 0x20, 0x79, 0x3F, 0xFF, 0x00, 0x70, 0x7D, 0x23, 0x1B, 0x4F, 0xF5, 0x00, 0x7D, 0xE7, 0xF8, 0x00, 0x40, 0x0D, 0x10, 0x14, 0xCE, 0x01, 0x43, 0x4C, 0x49, 0x4D, 0xFF, 0xFE, 0x46, 0x14, 0x2F, 0xFF, 0x02, 0x02, 0x28, 0x24, 0x6E, 0x35, 0xA2, 0x69, 0x10, 0x6D, 0x61, 0x67, 0x24, 0x79, 0x00, 0x80, 0x00, 0x40, 0xFF, 0x52, 0x7D, 0x30, 0x0C, 0x07, 0x8F, 0xFF, 0x57, 0x9F, 0x38, 0x79, 0x00, 0x58, 0x7D, 0x00, 0xF0, 0x1F, 0x40, 0xD8, 0xB6, 0x53, 0x74, 0xDF, 0x00, 0x88, 0x27, 0x57, 0x5F, 0xFF, 0x28, 0x69, 0x00, 0x3F, 0xFF, 0xEF, 0xDD, 0x28, 0x79, 0x3F, 0xFF, 0xB2, 0x63, 0xDC, 0xFF, 0xFF, 0x98, 0x7D, 0xC7, 0x00, 0x67, 0xFF, 0x7F, 0x9D, 0x4F, 0xFF, 0x47, 0x0F, 0x48, 0xE5, 0x89, 0x47, 0x30, 0xD9, 0x50, 0xDD, 0x2F, 0xFF, 0x17, 0xE8, 0x00, 0xBF, 0x00, 0x4F, 0xFF, 0x02, 0x00, 0x10, 0x37, 0x00, 0x68, 0x7F, 0x01, 0x50, 0x7F, 0xB1, 0x00, 0x14, 0x92, 0x2F, 0x84, 0xBE, 0x00, 0x3F, 0xFF, 0x0E, 0x00, 0x20, 0x69, 0x9D, 0xF9, 0x05, 0x24, 0x9C, 0x61, 0xEF, 0x38, 0x67, 0x20, 0x04, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x38, 0x7F, 0x83, 0x28, 0x7D, 0x10, 0x90, 0x0F, 0x0F, 0xE0, 0x29, 0x17, 0x72, 0x1F, 0x50, 0xE0, 0x20, 0x0F, 0x10, 0x38, 0x79, 0x1B, 0xFF, 0xFF, 0x02, 0x02, 0x00, 0xFF, 0xB1, 0xDF, 0xFF, 0x20, 0x40, 0x2C, 0x02, 0x01, 0x1B, 0xFD, 0x80, 0xFF, 0xFD, 0x20, 0xB1, 0x20, 0x38, 0x00, 0xDF, 0xDF, 0x08, 0x01, 0x09, 0xF0, 0xF0, 0x0E, 0xD5, 0x2A, 0xC9, 0x28, 0x69, 0x1A, 0x30, 0x27, 0x0E, 0x20, 0x0F, 0x01, 0x2A, 0xDD, 0x90, 0x88, 0x5F, 0xF5, 0x7F, 0x38, 0xF7, 0xFF, 0xFE, 0x1A, 0xFF, 0x3A, 0xF5, 0x02, 0x2A, 0xF5, 0x30, 0x29, 0x50, 0x1D, 0xF0, 0x29, 0x83, 0xF0, 0x30, 0xF0, 0x7F, 0x25, 0xDE, 0x3A, 0x31, 0xD1, 0xF9, 0xFF, 0x7F, 0x60, 0xFE, 0x30, 0x8B, 0x6A, 0x3D, 0xFE, 0xF8, 0x2F, 0xCF, 0xC0, 0x44, 0x00, 0x28, 0x60, 0x01, 0xFF, 0xF5, 0x30, 0xA2, 0x2E, 0xAF, 0x80, 0x6A, 0x55, 0x03, 0x00, 0x30, 0xFF, 0xFE, 0xFF, 0xCF, 0x90, 0x32, 0x19, 0xFF, 0x38, 0x3A, 0x6D, 0xAF, 0xBF, 0xFF, 0xFF, 0x21, 0x2F, 0x0F, 0x29, 0x0A, 0xFB, 0x00, 0x00, 0xF2, 0x20, 0x87, 0x40, 0x2F, 0x20, 0x0F, 0xAF, 0x0F, 0x00, 0x11, 0xF2, 0xFB, 0x03, 0xFF, 0xE8, 0xFF, 0xBF, 0x1E, 0x9F, 0x22, 0x6E, 0x4A, 0x91, 0x01, 0xAF, 0xCF, 0xFF, 0xFF, 0x3F, 0x0F, 0xEF, 0x20, 0x0F, 0x67, 0x2E, 0x21, 0xFF, 0x72, 0x27, 0xFF, 0x03, 0x5B, 0x82, 0x70, 0x7F, 0x86, 0x77, 0x80, 0x01, 0x60, 0x7F, 0xF7, 0xF2, 0x7F, 0xBF, 0xD0, 0x70, 0xFF, 0x21, 0xFF, 0x20, 0x20, 0x03, 0xB1, 0xF5, 0xBF, 0x2F, 0x21, 0x23, 0x80, 0x39, 0x9F, 0xF2, 0xFD, 0xFF, 0x0B, 0x06, 0xFF, 0xDF, 0x00, 0x02, 0x00, 0x2F, 0x6F, 0x70, 0xB0, 0xBF, 0xFF, 0x40, 0xF1, 0x20, 0xC3, 0x07, 0x02, 0xDF, 0x7F, 0x00, 0x00, 0x02, 0xFB, 0xF6, 0xFD, 0xFF, 0xF2, 0xD0, 0x20, 0xB1, 0x0C, 0x1E, 0x00, 0x00, 0x07, 0x72, 0x87, 0x03, 0x74, 0x7F, 0x29, 0x73, 0xD4, 0x7F, 0x10, 0xE5, 0x56, 0xFD, 0x38, 0xF8, 0x00, 0x84, 0xBF, 0x41, 0x4E, 0x74, 0xBF, 0x9C, 0x63, 0x1A, 0x05, 0x70, 0x61, 0x74, 0x31, 0x3C, 0x63, 0x60, 0x1C, 0x67, 0x7B, 0x60, 0xF1, 0x22, 0x27, 0x3A, 0x7E, 0x53, 0x63, 0x65, 0x6E, 0x65, 0x08, 0x4F, 0x75, 0x74, 0x43, 0x2F, 0xFF, 0x47, 0x5F, 0x43, 0x10, 0x5F, 0x30, 0x30, 0xDF, 0xFF, 0x70, 0x61, 0x69, 0x31, 0x4D, 0x4C, 0x8B, 0x5A, 0x02, 0x00, 0x35, 0x19, 0x30, 0x43, 0x40, 0x2F, 0xFF, 0x04, 0x48, 0x62, 0x4D, 0x61, 0x74, 0x00, 0x2F, 0xFF, 0x48, 0x62, 0x0D, 0x52, 0x6F, 0x6F, 0x74, 0xE0, 0x48, 0x02, 0xE0, 0x9F, 0x42, 0x40, 0x9F, 0x56, 0x42, 0x08, 0x80, 0x9F, 0x41, 0x41, 0x3F, 0x41, 0x10, 0x0C, 0x81, 0x3F, 0x05, 0x33, 0x1F, 0x77, 0x00, 0xA2, 0x13, 0x49, 0x99, 0x58, 0x3D, 0x71, 0x8A, 0x00, 0x3A, 0x75, 0x0A, 0xEF, 0xE4, 0xC9, 0xFC, 0xB1, 0x00, 0x00, 0x99, 0x02, 0x63, 0xA9, 0x9B, 0x74, 0xE0, 0x00, 0x38, 0xD3, 0x33, 0xC0, 0x52, 0x6A, 0x2C
};

struct sArgInfo
{
	const char *elfFile;
	const char *specFile;
	const char *outFile;
	const char *iconFile;
	const char *bannerFile;
	const char *romfsDir;
	const char *uniqueId;
	const char *productCode;
	const char *title;
};

class NcchBuilder
{
public:
	NcchBuilder()
	{
		m_Config.titleId = 0;
		m_Config.programId = 0;
		m_Config.compressedCode = 0;
		m_Config.sdmcTitle = 0;
		m_Config.remasterVersion = 0;
		m_Config.stackSize = 0;
		m_Config.saveSize = 0;
		m_Config.jumpId = 0;
		m_Config.kernelTitleId = 0;
		m_Config.enableL2Cache = false;
		m_Config.cpuSpeed = ExtendedHeader::CLOCK_268MHz;
		m_Config.systemModeExt = ExtendedHeader::SYSMODE_SNAKE_LEGACY;
		m_Config.idealProcessor = 0;
		m_Config.affinityMask = 0;
		m_Config.systemMode = ExtendedHeader::SYSMODE_PROD;
		m_Config.priority = 0;
		m_Config.useExtdata = false;
		m_Config.extdataId = 0;
		m_Config.useOtherVariationSaveData = false;
		m_Config.maxCpu = 0;
		m_Config.fsRights = 0;
		m_Config.resLimit = ExtendedHeader::RESLIMIT_APPLICATION;
		m_Config.releaseKernelVersion[0] = 0;
		m_Config.releaseKernelVersion[1] = 0;
		m_Config.handleTableSize = 0;
		m_Config.memType = ExtendedHeader::MEMTYPE_APPLICATION;
		m_Config.dependencies.clear();
		m_Config.systemSaveIds.clear();
		m_Config.otherUserSaveIds.clear();
		m_Config.accessibleSaveIds.clear();
		m_Config.services.clear();
		m_Config.interupts.clear();
		m_Config.svcCalls.clear();
		m_Config.staticMappings.clear();
		m_Config.ioMappings.clear();
	}

	~NcchBuilder()
	{

	}

	void setArgs(const struct sArgInfo& args)
	{
		m_Args = args;
	}

	int buildNcch(void)
	{
		setDefaults();
		try 
		{
			safe_call(parseSpecFile());
		}
		catch (YamlException& e)
		{
			fprintf(stderr, "[ERROR] %s.\n", e.what());
			return 1;
		}
		
		safe_call(getCodeBlob());
		safe_call(getExefsBlob());
		safe_call(getRomfsBlob());
		safe_call(getExheaderBlob());
		safe_call(getNcchHeaderBlob());
		safe_call(writeToFile());

		return 0;
	}

private:
	struct sConfig
	{
		char productCode[16];
		char makerCode[16];
		u64 titleId;
		u64 programId;

		// process info
		char appTitle[8];
		bool compressedCode;
		bool sdmcTitle;
		u16 remasterVersion;
		u32 stackSize;
		u32 saveSize;
		u64 jumpId;
		std::vector<u64> dependencies;

		
		// arm11 userland system
		
		u64 kernelTitleId;
		bool enableL2Cache;
		ExtendedHeader::CpuSpeed cpuSpeed;
		ExtendedHeader::SystemModeExt systemModeExt;
		u8 idealProcessor;
		u8 affinityMask;
		ExtendedHeader::SystemMode systemMode;
		int8_t priority;
		bool useExtdata;
		u64 extdataId;
		std::vector<u32> systemSaveIds;
		bool useOtherVariationSaveData;
		std::vector<u32> otherUserSaveIds;
		std::vector<u32> accessibleSaveIds;
		std::vector<std::string> services;
		u64 fsRights;
		u16 maxCpu;
		ExtendedHeader::ResourceLimitCategory resLimit;

		// arm11 kern
		std::vector<u8> interupts;
		std::vector<u8> svcCalls;
		u8 releaseKernelVersion[2];
		u16 handleTableSize;
		ExtendedHeader::MemoryType memType;
		u32 kernelFlags;
		std::vector<struct ExtendedHeader::sMemoryMapping> staticMappings;
		std::vector<struct ExtendedHeader::sMemoryMapping> ioMappings;

		// arm9
		u32 arm9Rights;
		u8 descVersion;
	};

	struct sArgInfo m_Args;
	struct sConfig m_Config;

	NcchHeader m_Header;
	ExtendedHeader m_Exheader;
	ExefsCode m_Code;
	Exefs m_Exefs;
	Romfs m_Romfs;

	void setDefaults()
	{
		m_Config.titleId = 0x000400000ff3ff00;
		strncpy(m_Config.productCode, "CTR-P-CTAP", 16);
		strncpy(m_Config.makerCode, "01", 2);
		strncpy(m_Config.appTitle, "CtrApp", 8);

		// process input from commandline
		if (m_Args.uniqueId != NULL)
		{
			u32 uniqueId = strtoul(m_Args.uniqueId, NULL, 0);

			m_Config.titleId = 0x0004000000000000 | ((uniqueId & 0xffffff) << 8);
		}
		if (m_Args.productCode != NULL)
		{
			strncpy(m_Config.productCode, m_Args.productCode, 16);
		}
		if (m_Args.title != NULL)
		{
			strncpy(m_Config.appTitle, m_Args.title, 8);
		}

		m_Config.programId = m_Config.titleId;
		m_Config.jumpId = m_Config.titleId;

		m_Config.sdmcTitle = true;
		m_Config.compressedCode = false;
		m_Config.remasterVersion = 0;
		m_Config.stackSize = 0x4000;
		
		m_Config.kernelTitleId = 0x0004013800000002;
		m_Config.fsRights = 0;
		m_Config.maxCpu = 0;
		m_Config.resLimit = ExtendedHeader::RESLIMIT_APPLICATION;
		
		
		m_Config.memType = ExtendedHeader::MEMTYPE_APPLICATION;

		// enable system calls 0x00-0x7D
		for (int i = 0; i < 0x7E; i++)
		{
			m_Config.svcCalls.push_back(i);
		}
		 
		m_Config.handleTableSize = 0x200;
		m_Config.kernelFlags = 0;
		// fw 2.0.0
		m_Config.releaseKernelVersion[0] = 2;
		m_Config.releaseKernelVersion[1] = 29;

		m_Config.arm9Rights = ExtendedHeader::IORIGHT_SD_APPLICATION;
		m_Config.descVersion = 2;
	}

	int evaluateBooleanString(bool& dst, std::string& str)
	{
		if (str == "true")
		{
			dst = true;
		}
		else if (dst == false)
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

	int addDependency(std::string& dependencyStr)
	{
		const u64 SYSTEM_MODULE_TID = 0x0004013000000000;
		const u8 NATIVE_FIRM_CORE = 0x02;
		u64 depTitleId = 0;

		if (dependencyStr == "sm")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_SM << 8);
		}
		else if (dependencyStr == "fs")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_FS << 8);
		}
		else if (dependencyStr == "pm")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_PM << 8);
		}
		else if (dependencyStr == "loader")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_LOADER << 8);
		}
		else if (dependencyStr == "pxi")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_PXI << 8);
		}
		else if (dependencyStr == "am")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_AM << 8);
		}
		else if (dependencyStr == "camera")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_CAMERA << 8);
		}
		else if (dependencyStr == "cfg")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_CONFIG << 8);
		}
		else if (dependencyStr == "codec")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_CODEC << 8);
		}
		else if (dependencyStr == "dmnt")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_DMNT << 8);
		}
		else if (dependencyStr == "dsp")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_DSP << 8);
		}
		else if (dependencyStr == "gpio")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_GPIO << 8);
		}
		else if (dependencyStr == "gsp")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_GSP << 8);
		}
		else if (dependencyStr == "hid")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_HID << 8);
		}
		else if (dependencyStr == "i2c")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_I2C << 8);
		}
		else if (dependencyStr == "mcu")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_MCU << 8);
		}
		else if (dependencyStr == "mic")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_MIC << 8);
		}
		else if (dependencyStr == "pdn")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_PDN << 8);
		}
		else if (dependencyStr == "ptm")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_PTM << 8);
		}
		else if (dependencyStr == "spi")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_SPI << 8);
		}
		else if (dependencyStr == "ac")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_AC << 8);
		}
		else if (dependencyStr == "cecd")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_CECD << 8);
		}
		else if (dependencyStr == "csnd")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_CSND << 8);
		}
		else if (dependencyStr == "dlp")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_DLP << 8);
		}
		else if (dependencyStr == "http")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_HTTP << 8);
		}
		else if (dependencyStr == "mp")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_MP << 8);
		}
		else if (dependencyStr == "ndm")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_NDM << 8);
		}
		else if (dependencyStr == "nim")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_NIM << 8);
		}
		else if (dependencyStr == "nwm")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_NWM << 8);
		}
		else if (dependencyStr == "socket")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_SOCKET << 8);
		}
		else if (dependencyStr == "ssl")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_SSL << 8);
		}
		else if (dependencyStr == "ps")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_PS << 8);
		}
		else if (dependencyStr == "friends")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_FRIENDS << 8);
		}
		else if (dependencyStr == "ir")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_IR << 8);
		}
		else if (dependencyStr == "boss")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_BOSS << 8);
		}
		else if (dependencyStr == "news")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_NEWS << 8);
		}
		else if (dependencyStr == "debugger")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_DEBUGGER << 8);
		}
		else if (dependencyStr == "ro")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_RO << 8);
		}
		else if (dependencyStr == "act")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_ACT << 8);
		}
		else if (dependencyStr == "nfc")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_NFC << 8);
		}
		else if (dependencyStr == "mvd")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_MVD << 8) | 0x20000000;
		}
		else if (dependencyStr == "qtm")
		{
			depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | (ExtendedHeader::MODULE_QTM << 8) | 0x20000000;
		}
		else if (dependencyStr.substr(0, 2) == "0x")
		{
			u64 depId = strtoull(dependencyStr.c_str(), 0, 16);

			if (depId == 0)
			{
				die("[ERROR] Invalid dependency id: 0x0");
			}

			// the id is a full title id
			if (depId >> 32 == SYSTEM_MODULE_TID >> 32)
			{
				depTitleId = depId;
			}

			// module unique ids are never larger than a byte, so if this is greater than 0, it is a title id low
			if (((depId & 0xffffffffff0fffff) >> 8) > 0)
			{
				depTitleId = SYSTEM_MODULE_TID | (depId & 0xffffffff);
			}
			// otherwise this is a unique id
			else
			{
				depTitleId = SYSTEM_MODULE_TID | NATIVE_FIRM_CORE | ((depId & 0xffffff) << 8);
			}
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown dependency: %s\n", dependencyStr.c_str());
			return 1;
		}

		m_Config.dependencies.push_back(depTitleId);
		return 0;
	}

	int parseSpecFileProccessConfig(YamlReader& spec)
	{
		u32 level;
		std::vector<std::string> tmp(1);

		// move into children of ProcessConfig
		spec.getEvent();

		// get level
		level = spec.getLevel();
		
		while (spec.getEvent() && spec.getLevel() >= level)
		{
			if (!spec.isEventScalar())
			{
				continue;
			}

			if (spec.getEventString() == "IdealProcessor")
			{
				spec.copyValue(tmp[0]);
				m_Config.idealProcessor = strtol(tmp[0].c_str(), NULL, 0);
			}
			else if (spec.getEventString() == "AffinityMask")
			{
				spec.copyValue(tmp[0]);
				m_Config.affinityMask = strtol(tmp[0].c_str(), NULL, 0);
			}
			else if (spec.getEventString() == "AppMemory")
			{
				spec.copyValue(tmp[0]);
				if (tmp[0] == "64MB")
				{
					m_Config.systemMode = ExtendedHeader::SYSMODE_PROD;
				}
				else if (tmp[0] == "72MB")
				{
					m_Config.systemMode = ExtendedHeader::SYSMODE_DEV3;
				}
				else if (tmp[0] == "80MB")
				{
					m_Config.systemMode = ExtendedHeader::SYSMODE_DEV2;
				}
				else if (tmp[0] == "96MB")
				{
					m_Config.systemMode = ExtendedHeader::SYSMODE_DEV1;
				}
				else
				{
					fprintf(stderr, "[ERROR] Invalid AppMemory: %s\n", tmp[0].c_str());
					return 1;
				}
			}
			else if (spec.getEventString() == "SnakeAppMemory")
			{
				spec.copyValue(tmp[0]);
				if (tmp[0] == "Legacy")
				{
					m_Config.systemModeExt = ExtendedHeader::SYSMODE_SNAKE_LEGACY;
				}
				else if (tmp[0] == "124MB")
				{
					m_Config.systemModeExt = ExtendedHeader::SYSMODE_SNAKE_PROD;
				}
				else if (tmp[0] == "178MB")
				{
					m_Config.systemModeExt = ExtendedHeader::SYSMODE_SNAKE_DEV1;
				}
				else
				{
					fprintf(stderr, "[ERROR] Invalid SnakeAppMemory: %s\n", tmp[0].c_str());
					return 1;
				}
			}
			else if (spec.getEventString() == "EnableL2Cache")
			{
				spec.copyValue(tmp[0]);
				safe_call(evaluateBooleanString(m_Config.enableL2Cache, tmp[0]));
			}
			else if (spec.getEventString() == "Priority")
			{
				spec.copyValue(tmp[0]);
				m_Config.priority = strtol(tmp[0].c_str(), NULL, 0);
			}
			else if (spec.getEventString() == "SnakeCpuSpeed")
			{
				spec.copyValue(tmp[0]);
				if (tmp[0] == "268MHz")
				{
					m_Config.cpuSpeed = ExtendedHeader::CLOCK_268MHz;
				}
				else if (tmp[0] == "804MHz")
				{
					m_Config.cpuSpeed = ExtendedHeader::CLOCK_804MHz;
				}
				else
				{
					fprintf(stderr, "[ERROR] Invalid SnakeCpuSpeed: %s\n", tmp[0].c_str());
					return 1;
				}
			}
			else if (spec.getEventString() == "Dependency")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(addDependency(tmp[i]));
				}
			}

			else
			{
				fprintf(stderr, "[ERROR] Unknown specfile key: ProcessConfig/%s\n", spec.getEventString().c_str());
				return 1;
			}
		}

		return 0;
	}

	int setSaveDataSize(std::string& sizeStr)
	{
		// tolower string
		std::transform(sizeStr.begin(), sizeStr.end(), sizeStr.begin(), ::tolower);

		u32 raw_size = strtoul(sizeStr.c_str(), NULL, 0);

		if (sizeStr.find("k") != std::string::npos && (sizeStr.substr((sizeStr.find("k"))) == "k" || sizeStr.substr((sizeStr.find("k"))) == "kb"))
		{
			raw_size *= 0x400;
		}
		else if (sizeStr.find("m") != std::string::npos && (sizeStr.substr((sizeStr.find("m"))) == "m" || sizeStr.substr((sizeStr.find("m"))) == "mb"))
		{
			raw_size *= 0x400 * 0x400;
		}
		else
		{
			fprintf(stderr, "[ERROR] Invalid SaveDataSize: %s\n", sizeStr.c_str());
			return 1;
		}

		// check size alignment
		if (raw_size % (64 * 0x400) != 0)
		{
			die("[ERROR] SaveDataSize must be aligned to 64K");
		}

		m_Config.saveSize = raw_size;

		return 0;
	}

	int parseSpecFileSaveData(YamlReader& spec)
	{
		u32 level;
		std::vector<std::string> tmp(1);

		// move into children of SaveData
		spec.getEvent();

		// get level
		level = spec.getLevel();

		while (spec.getEvent() && spec.getLevel() >= level)
		{
			if (!spec.isEventScalar())
			{
				continue;
			}

			if (spec.getEventString() == "SaveDataSize")
			{
				spec.copyValue(tmp[0]);
				safe_call(setSaveDataSize(tmp[0]));
			}
			else if (spec.getEventString() == "SystemSaveIds")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					m_Config.systemSaveIds.push_back(strtoul(tmp[i].c_str(), NULL, 0) & 0xffffffff);
				}
			}
			else if (spec.getEventString() == "UseExtdata")
			{
				spec.copyValue(tmp[0]);
				safe_call(evaluateBooleanString(m_Config.useExtdata, tmp[0]));
			}
			else if (spec.getEventString() == "ExtDataId")
			{
				spec.copyValue(tmp[0]);
				m_Config.extdataId = strtoull(tmp[0].c_str(), NULL, 0);
			}
			else if (spec.getEventString() == "UseOtherVariationSaveData")
			{
				spec.copyValue(tmp[0]);
				safe_call(evaluateBooleanString(m_Config.useOtherVariationSaveData, tmp[0]));
			}
			else if (spec.getEventString() == "OtherUserSaveIds")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					m_Config.otherUserSaveIds.push_back(strtoul(tmp[i].c_str(), NULL, 0) & 0xffffff);
				}
			}
			else if (spec.getEventString() == "AccessibleSaveIds")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					m_Config.accessibleSaveIds.push_back(strtoul(tmp[i].c_str(), NULL, 0) & 0xffffff);
				}
			}

			else
			{
				fprintf(stderr, "[ERROR] Unknown specfile key: SaveData/%s\n", spec.getEventString().c_str());
				return 1;
			}
		}

		return 0;
	}

	int addService(std::string& serviceStr)
	{
		if (serviceStr.size() > 8)
		{
			fprintf(stderr, "[ERROR] Service name is too long: %s\n", serviceStr.c_str());
			return 1;
		}

		m_Config.services.push_back(serviceStr);

		return 0;
	}

	int addIOMapping(std::string& mappingStr)
	{
		std::string property;
		size_t pos1, pos2;
		struct ExtendedHeader::sMemoryMapping mapping;

		// get positions of '-' and ':'
		pos1 = mappingStr.find('-');
		pos2 = mappingStr.find(':');

		// check for invalid syntax
		// '-' shouldn't appear at the start
		// ':' shouldn't appear at all
		if (pos1 == 0 || pos2 != std::string::npos)
		{
			fprintf(stderr, "[ERROR] Invalid syntax in IORegisterMapping \"%s\"\n", mappingStr.c_str());
			return 1;
		}

		// npos means an end address wasn't specified, this is okay
		if (pos1 == std::string::npos)
		{
			mapping.start = strtoul(mappingStr.substr(0, pos2).c_str(), NULL, 16);
			mapping.end = 0;
		}
		// otherwise both start and end addresses should have been specified
		else
		{
			mapping.start = strtoul(mappingStr.substr(0, pos1).c_str(), NULL, 16);
			mapping.end = strtoul(mappingStr.substr(pos1 + 1).c_str(), NULL, 16);
		}

		if ((mapping.start & 0xfff) != 0x000)
		{
			fprintf(stderr, "[ERROR] %x in IORegisterMapping \"%s\" is not a valid start address\n", mapping.start, mappingStr.c_str());
			return 1;
		}

		if ((mapping.end & 0xfff) != 0xfff & mapping.end != 0)
		{
			fprintf(stderr, "[ERROR] %x in IORegisterMapping \"%s\" is not a valid end address\n", mapping.end, mappingStr.c_str());
			return 1;
		}

		m_Config.ioMappings.push_back(mapping);

		return 0;
	}

	int addStaticMapping(std::string& mappingStr)
	{
		std::string property("");
		size_t pos1, pos2;
		struct ExtendedHeader::sMemoryMapping mapping;

		// get positions of '-' and ':'
		pos1 = mappingStr.find('-');
		pos2 = mappingStr.find(':');
		
		if (pos2 != std::string::npos)
		{
			property = mappingStr.substr(pos2 + 1);
		}

		// check for invalid syntax
		// '-' or ':' shouldn't appear at the start
		// ':' shouldn't appear before '-'
		if (pos1 == 0 || pos2 == 0 || (pos2 < pos1 && pos1 != std::string::npos && pos2 != std::string::npos) || (pos2 != std::string::npos && property.empty()))
		{
			fprintf(stderr, "[ERROR] Invalid syntax in MemoryMapping \"%s\"\n", mappingStr.c_str());
			return 1;
		}

		// npos means an end address wasn't specified, this is okay
		if (pos1 == std::string::npos)
		{
			mapping.start = strtoul(mappingStr.substr(0, pos2).c_str(), NULL, 16);
			mapping.end = 0;
		}
		// otherwise both start and end addresses should have been specified
		else
		{
			mapping.start = strtoul(mappingStr.substr(0, pos1).c_str(), NULL, 16);
			mapping.end = strtoul(mappingStr.substr(pos1 + 1).c_str(), NULL, 16);
		}

		if ((mapping.start & 0xfff) != 0x000)
		{
			fprintf(stderr, "[ERROR] %x in MemoryMapping \"%s\" is not a valid start address\n", mapping.start, mappingStr.c_str());
			return 1;
		}

		if ((mapping.end & 0xfff) != 0xfff & mapping.end != 0)
		{
			fprintf(stderr, "[ERROR] %x in MemoryMapping \"%s\" is not a valid end address\n", mapping.end, mappingStr.c_str());
			return 1;
		}

		// the user has specified properties about the mapping
		if (property.size())
		{
			if (property == "r")
			{
				mapping.readOnly = true;
			}
			else
			{
				fprintf(stderr, "[ERROR] %s in MemoryMapping \"%s\" is not a valid mapping property\n", property.c_str(), mappingStr.c_str());
				return 1;
			}
		}

		m_Config.staticMappings.push_back(mapping);

		return 0;
	}

	int addFSAccessRight(std::string& rightStr)
	{
		if (rightStr == "CategorySystemApplication")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CATEGORY_SYSTEM_APPLICATION;
		}
		else if (rightStr == "CategoryHardwareCheck")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CATEGORY_HARDWARE_CHECK;
		}
		else if (rightStr == "CategoryFileSystemTool")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CATEGORY_FILE_SYSTEM_TOOL;
		}
		else if (rightStr == "Debug")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_DEBUG;
		}
		else if (rightStr == "TwlCard" || rightStr == "TwlCardBackup")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_TWL_CARD;
		}
		else if (rightStr == "TwlNand" || rightStr == "TwlNandData")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_TWL_NAND;
		}
		else if (rightStr == "Boss")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_BOSS;
		}
		else if (rightStr == "DirectSdmc" || rightStr == "Sdmc")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_DIRECT_SDMC;
			m_Config.arm9Rights |= ExtendedHeader::IORIGHT_USE_DIRECT_SDMC;
		}
		else if (rightStr == "Core")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CORE;
		}
		else if (rightStr == "CtrNandRo" || rightStr == "NandRo")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CTR_NAND_RO;
		}
		else if (rightStr == "CtrNandRw" || rightStr == "NandRw")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CTR_NAND_RW;
		}
		else if (rightStr == "CtrNandRoWrite" || rightStr == "NandRoWrite")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CTR_NAND_RO_WRITE;
		}
		else if (rightStr == "CategorySystemSettings")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CATEGORY_SYSTEM_SETTINGS;
		}
		else if (rightStr == "Cardboard" || rightStr == "SystemTransfer")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CARD_BOARD;
		}
		else if (rightStr == "ExportInportIvs")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_EXPORT_IMPORT_IVS;
		}
		else if (rightStr == "DirectSdmcWrite" || rightStr == "SdmcWriteOnly")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_DIRECT_SDMC_WRITE;
		}
		else if (rightStr == "SwitchCleanup")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_SWITCH_CLEANUP;
		}
		else if (rightStr == "SaveDataMove")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_SAVE_DATA_MOVE;
		}
		else if (rightStr == "Shop")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_SHOP;
		}
		else if (rightStr == "Shell")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_SHELL;
		}
		else if (rightStr == "CategoryHomeMenu")
		{
			m_Config.fsRights |= ExtendedHeader::FSRIGHT_CATEGORY_HOME_MENU;
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown FS Access right: %s\n", rightStr.c_str());
			return 1;
		}
		
		return 0;
	}

	int addKernelFlag(std::string& flagStr)
	{
		if (flagStr == "PermitDebug")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_PERMIT_DEBUG;
		}
		else if (flagStr == "ForceDebug")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_FORCE_DEBUG;
		}
		else if (flagStr == "CanUseNonAlphaNum")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_CAN_USE_NON_ALPHABET_AND_NUMBER;
		}
		else if (flagStr == "CanWriteSharedPage")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_CAN_WRITE_SHARED_PAGE;
		}
		else if (flagStr == "CanUsePriviligedPriority")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_CAN_USE_PRIVILEGE_PRIORITY;
		}
		else if (flagStr == "PermitMainFunctionArgument")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_PERMIT_MAIN_FUNCTION_ARGUMENT;
		}
		else if (flagStr == "CanShareDeviceMemory")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_CAN_SHARE_DEVICE_MEMORY;
		}
		else if (flagStr == "RunnableOnSleep")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_RUNNABLE_ON_SLEEP;
		}
		else if (flagStr == "SpecialMemoryLayout")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_SPECIAL_MEMORY_LAYOUT;
		}
		else if (flagStr == "CanAccessCore2")
		{
			m_Config.kernelFlags |= ExtendedHeader::KERNFLAG_CAN_ACCESS_CORE2;
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown Kernel Flag: %s\n", flagStr.c_str());
			return 1;
		}

		return 0;
	}

	int addArm9AccessRight(std::string& rightStr)
	{
		if (rightStr == "MountNand")
		{
			m_Config.arm9Rights |= ExtendedHeader::IORIGHT_FS_MOUNT_NAND;
		}
		else if (rightStr == "MountNandROWrite")
		{
			m_Config.arm9Rights |= ExtendedHeader::IORIGHT_FS_MOUNT_NAND_RO_WRITE;
		}
		else if (rightStr == "MountTwlN")
		{
			m_Config.arm9Rights |= ExtendedHeader::IORIGHT_FS_MOUNT_TWLN;
		}
		else if (rightStr == "MountWNand")
		{
			m_Config.arm9Rights |= ExtendedHeader::IORIGHT_FS_MOUNT_WNAND;
		}
		else if (rightStr == "MountCardSpi")
		{
			m_Config.arm9Rights |= ExtendedHeader::IORIGHT_FS_MOUNT_CARD_SPI;
		}
		else if (rightStr == "UseSDIF3")
		{
			m_Config.arm9Rights |= ExtendedHeader::IORIGHT_USE_SDIF3;
		}
		else if (rightStr == "CreateSeed")
		{
			m_Config.arm9Rights |= ExtendedHeader::IORIGHT_CREATE_SEED;
		}
		else if (rightStr == "UseCardSpi")
		{
			m_Config.arm9Rights |= ExtendedHeader::IORIGHT_USE_CARD_SPI;
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown Arm9 Access right: %s\n", rightStr.c_str());
			return 1;
		}

		return 0;
	}

	int parseSpecFileRights(YamlReader& spec)
	{
		u32 level;
		std::vector<std::string> tmp(1);

		// move into children of SaveData
		spec.getEvent();

		// get level
		level = spec.getLevel();

		while (spec.getEvent() && spec.getLevel() >= level)
		{
			if (!spec.isEventScalar())
			{
				continue;
			}

			if (spec.getEventString() == "Services")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(addService(tmp[i]));
				}
			}
			else if (spec.getEventString() == "IORegisterMapping")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(addIOMapping(tmp[i]));
				}
			}
			else if (spec.getEventString() == "MemoryMapping")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(addStaticMapping(tmp[i]));
				}
			}
			else if (spec.getEventString() == "FSAccess")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(addFSAccessRight(tmp[i]));
				}
			}
			else if (spec.getEventString() == "KernelFlags")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(addKernelFlag(tmp[i]));
				}
			}
			else if (spec.getEventString() == "Arm9Access")
			{
				spec.copyValueSequence(tmp);
				for (int i = 0; i < tmp.size(); i++)
				{
					safe_call(addArm9AccessRight(tmp[i]));
				}
			}

			else
			{
				fprintf(stderr, "[ERROR] Unknown specfile key: Rights/%s\n", spec.getEventString().c_str());
				return 1;
			}
		}

		return 0;
	}

	int parseSpecFile()
	{
		YamlReader spec;
		u32 level;

		spec.loadFile(m_Args.specFile);

		level = spec.getLevel();
		while (spec.getEvent() && spec.getLevel() == level)
		{
			if (!spec.isEventScalar())
			{
				continue;
			}

			if (spec.getEventString() == "ProcessConfig")
			{
				safe_call(parseSpecFileProccessConfig(spec));
			}
			else if (spec.getEventString() == "SaveData")
			{
				safe_call(parseSpecFileSaveData(spec));
			}
			else if (spec.getEventString() == "Rights")
			{
				safe_call(parseSpecFileRights(spec));
			}
			else
			{
				fprintf(stderr, "[ERROR] Unknown specfile key: %s\n", spec.getEventString().c_str());
				return 1;
			}
		}

		return 0;
	}

	int getCodeBlob()
	{
		ByteBuffer elf;

		if (elf.openFile(m_Args.elfFile) != 0)
		{
			die("[ERROR] Cannot open ELF file!");
		}

		safe_call(m_Code.parseElf(elf.data()));

		m_Code.createCodeBlob(true);

		return 0;
	}

	int getExefsBlob()
	{
		ByteBuffer icon, banner;
		
		safe_call(m_Exefs.setExefsFile(m_Code.getCodeBlob(), m_Code.getCodeBlobSize(), ".code"));

		if (m_Args.bannerFile)
		{
			if (banner.openFile(m_Args.bannerFile) != 0)
			{
				die("[ERROR] Cannot open banner file!");
			}
			safe_call(m_Exefs.setExefsFile(banner.data(), banner.size(), "banner"));
		}

		if (m_Args.iconFile)
		{
			if (icon.openFile(m_Args.iconFile) != 0)
			{
				die("[ERROR] Cannot open icon file!");
			}
			safe_call(m_Exefs.setExefsFile(icon.data(), icon.size(), "icon"));
		}

		safe_call(m_Exefs.setExefsFile(CXI_LOGO, sizeof(CXI_LOGO), "logo"));

		/*
		if (m_Args.logoFile)
		{
			if (file.openFile(m_Args.bannerFile) != 0)
			{
				die("[ERROR] Cannot open logo file!");
			}
			safe_call(m_Exefs.setExefsFile(file.data(), file.size(), "logo"));
		}
		*/

		safe_call(m_Exefs.createExefs());

		return 0;
	}

	int getRomfsBlob()
	{
		if (m_Args.romfsDir)
		{
			safe_call(m_Romfs.createRomfs(m_Args.romfsDir));
		}

		return 0;
	}

	int getExheaderBlob()
	{
		m_Exheader.setProcessName(m_Config.appTitle);
		m_Exheader.setIsCodeCompressed(m_Config.compressedCode);
		m_Exheader.setIsSdmcTitle(m_Config.sdmcTitle);
		m_Exheader.setRemasterVersion(m_Config.remasterVersion);
		m_Exheader.setTextSegment(m_Code.getTextAddress(), m_Code.getTextPageNum(), m_Code.getTextSize());
		m_Exheader.setRoDataSegment(m_Code.getRodataAddress(), m_Code.getRodataPageNum(), m_Code.getRodataSize());
		m_Exheader.setDataSegment(m_Code.getDataAddress(), m_Code.getDataPageNum(), m_Code.getDataSize());
		m_Exheader.setStackSize(m_Config.stackSize);
		m_Exheader.setBssSize(m_Code.getBssSize());
		safe_call(m_Exheader.setDependencies(m_Config.dependencies));
		m_Exheader.setSaveSize(m_Config.saveSize);
		m_Exheader.setJumpId(m_Config.jumpId);

		m_Exheader.setProgramId(m_Config.programId);
		m_Exheader.setKernelId(m_Config.kernelTitleId);
		m_Exheader.setEnableL2Cache(m_Config.enableL2Cache);
		m_Exheader.setCpuSpeed(m_Config.cpuSpeed);
		m_Exheader.setSystemModeExt(m_Config.systemModeExt);
		safe_call(m_Exheader.setIdealProcessor(m_Config.idealProcessor));
		safe_call(m_Exheader.setProcessAffinityMask(m_Config.affinityMask));
		m_Exheader.setSystemMode(m_Config.systemMode);
		safe_call(m_Exheader.setProcessPriority(m_Config.priority));

		// catch illegal combinations
		if ((m_Config.accessibleSaveIds.size() > 0) & (m_Config.useExtdata || m_Config.extdataId))
		{
			die("[ERROR] AccessibleSaveIds & Extdata cannot both be used.");
		}

		if ((m_Config.accessibleSaveIds.size() > 0) & (m_Config.otherUserSaveIds.size() > 0))
		{
			die("[ERROR] AccessibleSaveIds & OtherUserSaveIds cannot both be used.");
		}


		if ((m_Config.useExtdata || m_Config.extdataId) || (m_Config.otherUserSaveIds.size() > 0))
		{
			if (m_Config.extdataId)
			{
				m_Exheader.setExtdataId(m_Config.extdataId);
			}
			// if extdataId isn't set, use the program uniqueid as the extdataId
			else
			{
				m_Exheader.setExtdataId((m_Config.programId >> 8) & 0xffffff);
			}
			safe_call(m_Exheader.setOtherUserSaveIds(m_Config.otherUserSaveIds, m_Config.useOtherVariationSaveData));
		}
		else if (m_Config.accessibleSaveIds.size() > 0)
		{
			safe_call(m_Exheader.setAccessibleSaveIds(m_Config.accessibleSaveIds, m_Config.useOtherVariationSaveData));
		}
		else
		{
			safe_call(m_Exheader.setOtherUserSaveIds(m_Config.otherUserSaveIds, m_Config.useOtherVariationSaveData));
		}


		safe_call(m_Exheader.setSystemSaveIds(m_Config.systemSaveIds));
		m_Exheader.setFsAccessRights(m_Config.fsRights);
		if (m_Romfs.getTotalSize() == 0)
		{
			m_Exheader.setNotUseRomfs();
		}
		safe_call(m_Exheader.setServiceList(m_Config.services));
		m_Exheader.setMaxCpu(m_Config.maxCpu);
		m_Exheader.setResourceLimitCategory(m_Config.resLimit);

		m_Exheader.setInterupts(m_Config.interupts);
		m_Exheader.setSystemCalls(m_Config.svcCalls);
		m_Exheader.setReleaseKernelVersion(m_Config.releaseKernelVersion[0], m_Config.releaseKernelVersion[1]);
		m_Exheader.setHandleTableSize(m_Config.handleTableSize);
		m_Exheader.setMemoryType(m_Config.memType);
		m_Exheader.setKernelFlags(m_Config.kernelFlags);
		m_Exheader.setStaticMapping(m_Config.staticMappings);
		m_Exheader.setIOMapping(m_Config.ioMappings);

		m_Exheader.setArm9IOControl(m_Config.arm9Rights, m_Config.descVersion);

		safe_call(m_Exheader.createExheader());
		safe_call(m_Exheader.createAccessDesc(NULL, NULL, NULL));

		return 0;
	}

	int getNcchHeaderBlob()
	{
		byte_t hash[0x20];

		m_Header.setTitleId(m_Config.titleId);
		m_Header.setProgramId(m_Config.programId);
		m_Header.setProductCode(m_Config.productCode);
		m_Header.setMakerCode(m_Config.makerCode);
		m_Header.setNoCrypto();
		m_Header.setPlatform(NcchHeader::CTR);
		if (m_Romfs.getTotalSize() > 0)
		{
			m_Header.setNcchType(NcchHeader::APPLICATION, NcchHeader::EXECUTABLE);
			m_Header.setRomfsData(m_Romfs.getTotalSize(), m_Romfs.getHashedDataSize(), m_Romfs.getHash());
		}
		else
		{
			m_Header.setNcchType(NcchHeader::APPLICATION, NcchHeader::EXECUTABLE_WITHOUT_ROMFS);
		}
		
		m_Header.setExheaderData(m_Exheader.getExheaderSize(), m_Exheader.getAccessDescSize(), m_Exheader.getExheaderHash());
		
		///* include logo in ncch header?
		
		hashSha256(CXI_LOGO, sizeof(CXI_LOGO), hash);
		m_Header.setLogoData(sizeof(CXI_LOGO), hash);
		//*/

		m_Header.setPlainRegionData(m_Code.getModuleIdBlobSize());
		m_Header.setExefsData(m_Exefs.getDataSize(), m_Exefs.getHashedDataSize(), m_Exefs.getHash());
		

		safe_call(m_Header.createHeader(NULL, NULL));

		return 0;
	}

	int writeToFile()
	{
		FILE *fp;

		if ((fp = fopen(m_Args.outFile, "wb")) == NULL)
		{
			die("[ERROR] Failed to create output file.");
		}

		// write header
		fseek(fp, 0, SEEK_SET);
		fwrite(m_Header.getHeader(), 1, m_Header.getHeaderSize(), fp);

		// write exheader
		if (m_Header.getExheaderOffset())
		{
			fseek(fp, m_Header.getExheaderOffset(), SEEK_SET);
			fwrite(m_Exheader.getExheader(), 1, m_Exheader.getExheaderSize(), fp);
			fwrite(m_Exheader.getAccessDesc(), 1, m_Exheader.getAccessDescSize(), fp);
		}

		// write logo
		if (m_Header.getLogoOffset())
		{
			fseek(fp, m_Header.getLogoOffset(), SEEK_SET);
			fwrite(CXI_LOGO, 1, sizeof(CXI_LOGO), fp);
		}

		// write plain region
		if (m_Header.getPlainRegionOffset())
		{
			fseek(fp, m_Header.getPlainRegionOffset(), SEEK_SET);
			fwrite(m_Code.getModuleIdBlob(), 1, m_Code.getModuleIdBlobSize(), fp);
		}
		
		// write exefs
		if (m_Header.getExefsOffset())
		{
			fseek(fp, m_Header.getExefsOffset(), SEEK_SET);
			fwrite(m_Exefs.getData(), 1, m_Exefs.getDataSize(), fp);
		}
		
		// write romfs
		if (m_Header.getRomfsOffset())
		{
			fseek(fp, m_Header.getRomfsOffset(), SEEK_SET);
			fwrite(m_Romfs.getIvfcHeader(), 1, m_Romfs.getIvfcHeaderSize(), fp);
			fwrite(m_Romfs.getIvfcLevel(2), 1, m_Romfs.getIvfcLevelSize(2), fp);
			fwrite(m_Romfs.getIvfcLevel(0), 1, m_Romfs.getIvfcLevelSize(0), fp);
			fwrite(m_Romfs.getIvfcLevel(1), 1, m_Romfs.getIvfcLevelSize(1), fp);
		}

		fclose(fp);
		return 0;
	}
};



void header()
{
	fprintf(stderr,
		"CXITOOL v0.1 (C) Jakcron 2016\n"
		"Built: %s %s\n\n"
		, __TIME__, __DATE__);
}

int usage(const char *progName)
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
		, progName);
	return 1;
}

int parseArgs(struct sArgInfo& info, int argc, char **argv)
{
	// clear struct
	memset((u8*)&info, 0, sizeof(struct sArgInfo));

	// return if minimum requirements not met
	if (argc < 4)
	{
		return usage(argv[0]);
	}

	info.elfFile = FixMinGWPath(argv[1]);
	info.specFile = FixMinGWPath(argv[2]);
	info.outFile = FixMinGWPath(argv[3]);

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
			info.iconFile = FixMinGWPath(value);
		}
		else if (strcmp(arg, "banner") == 0)
		{
			info.bannerFile = FixMinGWPath(value);
		}
		else if (strcmp(arg, "romfs") == 0)
		{
			info.romfsDir = FixMinGWPath(value);
		}
		else if (strcmp(arg, "banner") == 0)
		{
			info.bannerFile = FixMinGWPath(value);
		}
		else if (strcmp(arg, "uniqueid") == 0)
		{
			info.uniqueId = value;
		}
		else if (strcmp(arg, "productcode") == 0)
		{
			info.productCode = value;
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

	safe_call(parseArgs(args, argc, argv));

	cxi.setArgs(args);
	safe_call(cxi.buildNcch());

	return 0;
}