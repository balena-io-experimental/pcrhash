#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <uchar.h>
#include <unistd.h>

#include "uefi.h"
#include "pecoff.h"
#include "sha256.h"

int parse_guid(struct EFI_GUID *g, const char *s)
{
	const size_t expected_vars = 11;
	unsigned int p[expected_vars];

	if (sscanf(s, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			  &p[0],
			  &p[1], &p[2],
			  &p[3], &p[4], &p[5], &p[6],
			  &p[7], &p[8], &p[9], &p[10]) == expected_vars) {
		g->Data1 = p[0];
		g->Data2 = p[1]; g->Data3 = p[2];
		g->Data4[0] = p[3]; g->Data4[1] = p[4]; g->Data4[2] = p[5]; g->Data4[3] = p[6];
		g->Data4[4] = p[7]; g->Data4[5] = p[8]; g->Data4[6] = p[9], g->Data4[7] = p[10];
		return 0;
	}

	return -EINVAL;
}

int measure_efivar (const char *efivar_path)
{
	const int exists = access(efivar_path, F_OK) == 0;
	const size_t tmpsz = 0x400;
	char tmp[tmpsz];
	memset(tmp, 0, tmpsz);
	assert(strlen(efivar_path) <= tmpsz);
	strncpy(tmp, efivar_path, strlen(efivar_path));
	char *efivar = basename(tmp);
	int err;

	const char *name = strtok(efivar, "-"),
		   *guid_str = name+strlen(name)+1;
	struct EFI_GUID VendorGuid;
	if ((err = parse_guid(&VendorGuid, guid_str)) != 0) {
		fprintf(stderr, "Invalid or malformed GUID: %s\n", guid_str);
		return err;
	}

	// detect when stdin is a pipe so we can read VarData from there
	struct stat sb;
	int pipe_input = 0;
	if (fstat(STDIN_FILENO, &sb) == 0)
		pipe_input = S_ISFIFO(sb.st_mode);

	const size_t VarDataBufSize = 0x4000;
	int8_t VarDataBuf[VarDataBufSize];

	FILE *efivar_filp = NULL;
	size_t VarSize = 0;
	int8_t *VarData = VarDataBuf;
	if (pipe_input) {
		while (1) {
			if (VarSize == VarDataBufSize)
				return -ENOBUFS;
			size_t bytes = fread(
				VarDataBuf, 1, VarDataBufSize - VarSize, stdin);
			if (!bytes) break;
			VarSize += bytes;
		}
	} else if (exists) {
		efivar_filp = fopen(efivar_path, "rb");
		// remove first four bytes, which are EFI variable attributes
		VarSize = fread(VarDataBuf, 1, VarDataBufSize, efivar_filp) - 4;
		VarData = VarDataBuf+4;
		fclose(efivar_filp);
	}

	const size_t VarNameSize = 0x40;
	char16_t VarName[VarNameSize];
	size_t VarNameLength = strlen(name);
	for (size_t i = 0; i < VarNameLength; i++)
		VarName[i] = name[i];

	// UEFI spec mandates a minimum supported size of 32k for efivars,
	// double should be fine
	const size_t VarLogBufSize = 0x10000;
	char VarLogBuf[VarLogBufSize];

	uint32_t VarLogSize = sizeof(struct UEFI_VARIABLE_DATA)
		+ VarNameLength * sizeof(char16_t)
		+ VarSize
		- sizeof(char16_t)
		- sizeof(int8_t);

	assert(VarLogSize <= VarLogBufSize);

	struct UEFI_VARIABLE_DATA *VarLog = (struct UEFI_VARIABLE_DATA *)VarLogBuf;
	memcpy(&VarLog->VariableName, &VendorGuid, sizeof(VarLog->VariableName));
	VarLog->UnicodeNameLength = VarNameLength;
	VarLog->VariableDataLength = VarSize;
	memcpy(VarLog->UnicodeName, VarName, VarNameLength * sizeof(*VarName));
	memcpy((char16_t *)VarLog->UnicodeName + VarNameLength, VarData, VarSize);

	size_t written = write(STDOUT_FILENO, VarLog, VarLogSize);
	if (written != VarLogSize)
		return 1;

	return 0;
}

struct EFI_GUID MOK_OWNER = {
	0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23} };

int hash_efibin(const char *efibin_path)
{
	void *efifile;
	struct stat st;
	int fdefifile;
	const size_t sigsz = sizeof(struct EFI_GUID) + SHA256_DIGEST_SIZE;
	UINT8 sig[sigsz];
	UINT8 *hash = sig+sizeof(struct EFI_GUID);
	EFI_STATUS status;

	memset(sig, 0, sigsz);
	memcpy(sig, &MOK_OWNER, sizeof(struct EFI_GUID));

	if ((fdefifile = open(efibin_path, O_RDONLY)) == -1) {
		fprintf(stderr, "failed to open file %s\n", efibin_path);
		exit (1);
	}

	fstat(fdefifile, &st);
	efifile = malloc(ALIGN_VALUE(st.st_size, 4096));
	memset(efifile, 0, ALIGN_VALUE(st.st_size, 4096));
	read(fdefifile, efifile, st.st_size);
	close(fdefifile);

	if ((status = sha256_get_pecoff_digest_mem(efifile, st.st_size, hash))
			!= EFI_SUCCESS) {
		fprintf(stderr, "failed to get hash of %s: %d\n", efibin_path, status);
		exit(1);
	}

	size_t written = write(STDOUT_FILENO, sig, sigsz);
	if (written != SHA256_DIGEST_SIZE)
		return 1;

	return 0;
}
