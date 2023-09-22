#define _GNU_SOURCE

#include <stdlib.h>
#include <stdint.h>
#include <uchar.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>

#define MIN(a, b) (a < b) ? a : b

struct __attribute__((packed)) EFI_GUID {
	uint32_t	Data1;
	uint16_t	Data2;
	uint16_t	Data3;
	uint8_t		Data4[8];
};

struct __attribute__((packed)) UEFI_VARIABLE_DATA {
	struct EFI_GUID	VariableName;
	uint64_t	UnicodeNameLength;
	uint64_t	VariableDataLength;
	char16_t	UnicodeName[1];
	int8_t		VariableData[1];
};

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

void print_usage(char **argv)
{
	printf("usage: %s efivar_path\n", argv[0]);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		print_usage(argv);
		exit(0);
	}

	char *efivar_path = argv[1];
	const int exists = access(efivar_path, F_OK) == 0;
	const size_t tmpsz = 0x400;
	char tmp[tmpsz];
	memset(tmp, 0, tmpsz);
	assert(strlen(efivar_path) <= tmpsz);
	strncpy(tmp, efivar_path, strlen(efivar_path));
	char *efivar = basename(tmp);
	int errno;

	const char *name = strtok(efivar, "-"),
		   *guid_str = name+strlen(name)+1;
	struct EFI_GUID VendorGuid;
	if (errno = (parse_guid(&VendorGuid, guid_str) != 0)) {
		fprintf(stderr, "Invalid or malformed GUID: %s\n", guid_str);
		return errno;
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
