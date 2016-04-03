#include <cstdio>
#include <cstring>
#include "polarssl/rsa.h"
#include "es_sign.h"

int EsSign::RsaSign(EsSignType type, const u8* hash, const u8* modulus, const u8* priv_exp, u8* signature)
{
	int ret;
	rsa_context rsa;
	int hash_id = 0;
	int hash_len = 0;

	rsa_init(&rsa, RSA_PKCS_V15, hash_id);

	if (hash == NULL || modulus == NULL || priv_exp == NULL || signature == NULL) return 1;


	switch (type)
	{
		case(ES_SIGN_RSA4096_SHA1) :
		case(ES_SIGN_RSA4096_SHA256) :
		{
			rsa.len = Crypto::kRsa4096Size;
			hash_id = (type == ES_SIGN_RSA4096_SHA1) ? SIG_RSA_SHA1 : SIG_RSA_SHA256;
			hash_len = (type == ES_SIGN_RSA4096_SHA1) ? Crypto::kSha1HashLen : Crypto::kSha256HashLen;
			memset(signature, 0, sizeof(kRsa4096SignLen));
			break;
		}
		case(ES_SIGN_RSA2048_SHA1) :
		case(ES_SIGN_RSA2048_SHA256) :
		{
			rsa.len = Crypto::kRsa2048Size;
			hash_id = (type == ES_SIGN_RSA2048_SHA1) ? SIG_RSA_SHA1 : SIG_RSA_SHA256;
			hash_len = (type == ES_SIGN_RSA2048_SHA1) ? Crypto::kSha1HashLen : Crypto::kSha256HashLen;
			memset(signature, 0, sizeof(kRsa2048SignLen));
			break;
		}
		default:
			return 1;
	}

	mpi_read_binary(&rsa.D, priv_exp, rsa.len);
	mpi_read_binary(&rsa.N, modulus, rsa.len);

	// set signature id
	*((u32*)(signature)) = be_word(type);
	ret = rsa_rsassa_pkcs1_v15_sign(&rsa, RSA_PRIVATE, hash_id, hash_len, hash, (signature + 4));
	
	rsa_free(&rsa);

	return ret;
}

int EsSign::RsaVerify(const u8* hash, const u8* modulus, const u8* signature)
{
	static const u8 public_exponent[3] = { 0x01, 0x00, 0x01 };

	int ret;
	EsSignType type;
	rsa_context rsa;
	int hash_id = 0;
	int hash_len = 0;

	rsa_init(&rsa, RSA_PKCS_V15, hash_id);

	if (hash == NULL || modulus == NULL || signature == NULL) return 1;

	// get signature type
	type = (EsSignType)be_word(*((u32*)(signature)));

	switch (type)
	{
	case(ES_SIGN_RSA4096_SHA1) :
	case(ES_SIGN_RSA4096_SHA256) :
	{
		rsa.len = Crypto::kRsa4096Size;
		hash_id = (type == ES_SIGN_RSA4096_SHA1) ? SIG_RSA_SHA1 : SIG_RSA_SHA256;
		hash_len = (type == ES_SIGN_RSA4096_SHA1) ? Crypto::kSha1HashLen : Crypto::kSha256HashLen;
		break;
	}
	case(ES_SIGN_RSA2048_SHA1) :
	case(ES_SIGN_RSA2048_SHA256) :
	{
		rsa.len = Crypto::kRsa2048Size;
		hash_id = (type == ES_SIGN_RSA2048_SHA1) ? SIG_RSA_SHA1 : SIG_RSA_SHA256;
		hash_len = (type == ES_SIGN_RSA2048_SHA1) ? Crypto::kSha1HashLen : Crypto::kSha256HashLen;
		break;
	}
	default:
		return 1;
	}

	mpi_read_binary(&rsa.E, public_exponent, sizeof(public_exponent));
	mpi_read_binary(&rsa.N, modulus, rsa.len);

	ret = rsa_rsassa_pkcs1_v15_verify(&rsa, RSA_PRIVATE, hash_id, hash_len, hash, signature + 4);

	rsa_free(&rsa);

	return ret;
}
