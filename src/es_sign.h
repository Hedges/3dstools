#pragma once
#include "crypto.h"

class EsSign
{
public:
	enum EsSignType
	{
		ES_SIGN_RSA4096_SHA1 = 0x00010000,
		ES_SIGN_RSA2048_SHA1 = 0x00010001,
		ES_SIGN_ECC_SHA1 = 0x00010002,
		ES_SIGN_RSA4096_SHA256 = 0x00010003,
		ES_SIGN_RSA2048_SHA256 = 0x00010004,
		ES_SIGN_ECC_SHA256 = 0x00010005,
	};

	static const int kRsa4096SignLen = 0x240;
	static const int kRsa2048SignLen = 0x140;
	static const int kEccSignLen = 0x80;

	static int RsaSign(EsSignType type, const u8* hash, const u8* modulus, const u8* priv_exp, u8* signature);
	static int RsaVerify(const u8* hash, const u8* modulus, const u8* signature);

private:
};