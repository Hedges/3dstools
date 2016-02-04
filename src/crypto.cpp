#include "crypto.h"
#include "polarssl/aes.h"
#include "polarssl/sha1.h"
#include "polarssl/sha2.h"
#include "polarssl/rsa.h"

void hashSha1(const u8 * in, u32 size, u8 hash[20])
{
	sha1(in, size, hash);
}

void hashSha256(const u8 * in, u32 size, u8 hash[32])
{
	sha2(in, size, hash, false);
}

void aesCtr(const u8 * in, u8 * out, u32 size, const u8 key[0x10], u8 ctr[0x10])
{
	aes_context ctx;
	u8 block[16] = { 0 };
	size_t counterOffset = 0;

	aes_setkey_enc(&ctx, key, 128);
	aes_crypt_ctr(&ctx, size, &counterOffset, ctr, block, in, out);
}

void aesCbcDecrypt(const u8 * in, u8 * out, u32 size, const u8 key[0x10], u8 iv[0x10])
{
	aes_context ctx;
	aes_setkey_dec(&ctx, key, 128);
	aes_crypt_cbc(&ctx, AES_DECRYPT, size, iv, in, out);
}

void aesCbcEncrypt(const u8 * in, u8 * out, u32 size, const u8 key[0x10], u8 iv[0x10])
{
	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_crypt_cbc(&ctx, AES_ENCRYPT, size, iv, in, out);
}

int signRsa2048Sha256(u8 sign[0x100], const u8 hash[0x20], const u8 modulus[0x100], const u8 privExp[0x100])
{
	int ret;
	rsa_context ctx;
	rsa_init(&ctx, RSA_PKCS_V15, 0);

	mpi_read_binary(&ctx.D, privExp, 0x100);
	mpi_read_binary(&ctx.N, modulus, 0x100);

	ret = rsa_rsassa_pkcs1_v15_sign(&ctx, RSA_PRIVATE, SIG_RSA_SHA256, 0x20, hash, sign);

	rsa_free(&ctx);
	
	return ret;
}

int verifyRsa2048Sha256(const u8 sign[0x100], const u8 hash[0x20], const u8 modulus[0x100])
{
	static const u8 pubExp[3] = { 0x01, 0x00, 0x01 };

	int ret;
	rsa_context ctx;
	rsa_init(&ctx, RSA_PKCS_V15, 0);

	mpi_read_binary(&ctx.E, pubExp, 0x3);
	mpi_read_binary(&ctx.N, modulus, 0x100);

	ret = rsa_rsassa_pkcs1_v15_verify(&ctx, RSA_PUBLIC, SIG_RSA_SHA256, 0x20, hash, sign);
	
	rsa_free(&ctx);

	return ret;
}
