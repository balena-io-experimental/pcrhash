#include <stdint.h>
#include <uchar.h>

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

int parse_guid(struct EFI_GUID *g, const char *s);
int measure_efivar(const char *efivar_path);

#endif
