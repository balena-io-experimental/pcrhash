#ifndef SHA256_H
#define SHA256_H

#include "uefi.h"

#define SHA256_DIGEST_SIZE 32

struct sha256_context {
	uint32_t total[2];
	uint32_t state[8];
	uint8_t buffer[64];
};

void sha256_starts(struct sha256_context *ctx);
void sha256_update(struct sha256_context *ctx, uint8_t *input, uint32_t length);
void sha256_finish(struct sha256_context *ctx, uint8_t digest[32]);

EFI_STATUS
sha256_get_pecoff_digest_mem(void *buffer, UINTN DataSize,
			     UINT8 hash[SHA256_DIGEST_SIZE]);

#endif
