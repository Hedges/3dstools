#pragma once
#include "types.h"

void hashSha1(const u8 *in, u32 size, u8 hash[20]);
void hashSha256(const u8 *in, u32 size, u8 hash[32]);

void aesCtr(const u8 *in, u8 *out, u32 size, const u8 key[0x10], u8 ctr[0x10]);
void aesCbcDecrypt(const u8 *in, u8 *out, u32 size, const u8 key[0x10], u8 iv[0x10]);
void aesCbcEncrypt(const u8 *in, u8 *out, u32 size, const u8 key[0x10], u8 iv[0x10]);

int signRsa2048Sha256(u8 signOut[0x100], const u8 hashIn[0x20], const u8 modulus[0x100], const u8 privExp[0x100]);
int verifyRsa2048Sha256(const u8 signIn[0x100], const u8 hashIn[0x20], const u8 modulus[0x100]);