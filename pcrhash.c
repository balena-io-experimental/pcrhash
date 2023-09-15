#define _GNU_SOURCE

#include <stdlib.h>
#include <stdint.h>
#include <uchar.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

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
	const size_t tmpsz = 0x400;
	char tmp[tmpsz];
	memset(tmp, 0, tmpsz);
	assert(strlen(efivar_path) <= tmpsz);
	strncpy(tmp, efivar_path, strlen(efivar_path));
	char *efivar = basename(tmp);

	const char *name = strtok(efivar, "-");
	struct EFI_GUID VendorGuid = {
		.Data1 = strtoul(strtok(NULL, "-"), NULL, 0x10),
		.Data2 = strtoul(strtok(NULL, "-"),  NULL, 0x10),
		.Data3 = strtoul(strtok(NULL, "-"),  NULL, 0x10),
		.Data4 = {},
	};

	char octet[2] = {};
	char *rem, *d = VendorGuid.Data4;
	while (rem = strtok(NULL, "-")) {
		for (char *c = rem; *c; c+=2) {
			strncpy(octet, c, 2);
			*d++ = strtoul(octet, NULL, 0x10);
		}
	}

	const size_t VarDataBufSize = 0x4000;
	int8_t VarDataBuf[VarDataBufSize];
	FILE *efivar_filp = fopen(efivar_path, "rb");
	// remove first four bytes, which are EFI variable attributes
	const size_t VarSize = fread(VarDataBuf, 1, VarDataBufSize, efivar_filp) - 4;
	const int8_t *VarData = VarDataBuf+4;
	fclose(efivar_filp);

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

	write(STDOUT_FILENO, VarLog, VarLogSize);
	return 0;
}
