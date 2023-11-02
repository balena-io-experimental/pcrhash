#ifndef PECOFF_H
#define PECOFF_H

#include <stddef.h>

#define ALIGN_VALUE(Value, Alignment) ((Value) + (((Alignment) - (Value)) & ((Alignment) - 1)))
#define EFI_IMAGE_SIZEOF_SHORT_NAME 8

#define SIGNATURE_16(A, B)	((A) | (B << 8))
#define SIGNATURE_32(A, B, C, D)  (SIGNATURE_16 (A, B) | (SIGNATURE_16 (C, D) << 16))

#define EFI_IMAGE_DOS_SIGNATURE     SIGNATURE_16('M', 'Z')
#define EFI_IMAGE_NT_SIGNATURE      SIGNATURE_32('P', 'E', '\0', '\0')

#define EFI_IMAGE_FILE_RELOCS_STRIPPED      (1 << 0)     ///< 0x0001  Relocation info stripped from file.

#define EFI_IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC 5

struct EFI_IMAGE_DOS_HEADER {
	UINT16 e_magic;
	UINT16 e_cblp;
	UINT16 e_cp;
	UINT16 e_crlc;
	UINT16 e_cparhdr;
	UINT16 e_minalloc;
	UINT16 e_maxalloc;
	UINT16 e_ss;
	UINT16 e_sp;
	UINT16 e_csum;
	UINT16 e_ip;
	UINT16 e_cs;
	UINT16 e_lfarlc;
	UINT16 e_ovno;
	UINT16 e_res[4];
	UINT16 e_oemid;
	UINT16 e_oeminfo;
	UINT16 e_res2[10];
	UINT16 e_lfanew;
};

struct EFI_IMAGE_SECTION_HEADER {
	UINT8 Name[EFI_IMAGE_SIZEOF_SHORT_NAME];
	union {
		UINT32 PhysicalAddress;
		UINT32 VirtualSize;
	} Misc;
	UINT32 VirtualAddress;
	UINT32 SizeOfRawData;
	UINT32 PointerToRawData;
	UINT32 PointerToRelocations;
	UINT32 PointerToLinenumbers;
	UINT16 NumberOfRelocations;
	UINT16 NumberOfLinenumbers;
	UINT32 Characteristics;
};

struct EFI_IMAGE_DATA_DIRECTORY {
	UINT32 VirtualAddress;
	UINT32 Size;
};

#define EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES 16

#define EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b

struct EFI_IMAGE_OPTIONAL_HEADER32 {
	UINT16 Magic;
	UINT8 MajorLinkerVersion;
	UINT8 MinorLinkerVersion;
	UINT32 SizeOfCode;
	UINT32 SizeOfInitializedData;
	UINT32 SizeOfUninitializedData;
	UINT32 AddressOfEntryPoint;
	UINT32 BaseOfCode;
	UINT32 BaseOfData;

	UINT32 ImageBase;
	UINT32 SectionAlignment;
	UINT32 FileAlignment;
	UINT16 MajorOperatingSystemVersion;
	UINT16 MinorOperatingSystemVersion;
	UINT16 MajorImageVersion;
	UINT16 MinorImageVersion;
	UINT16 MajorSubsystemVersion;
	UINT16 MinorSubsystemVersion;
	UINT32 Win32VersionValue;
	UINT32 SizeOfImage;
	UINT32 SizeOfHeaders;
	UINT32 CheckSum;
	UINT16 Subsystem;
	UINT16 DllCharacteristics;
	UINT32 SizeOfStackReserve;
	UINT32 SizeOfStackCommit;
	UINT32 SizeOfHeapReserve;
	UINT32 SizeOfHeapCommit;
	UINT32 LoaderFlags;
	UINT32 NumberOfRvaAndSizes;
	struct EFI_IMAGE_DATA_DIRECTORY DataDirectory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
};

#define EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

struct EFI_IMAGE_OPTIONAL_HEADER64 {
	UINT16 Magic;
	UINT8 MajorLinkerVersion;
	UINT8 MinorLinkerVersion;
	UINT32 SizeOfCode;
	UINT32 SizeOfInitializedData;
	UINT32 SizeOfUninitializedData;
	UINT32 AddressOfEntryPoint;
	UINT32 BaseOfCode;

	UINT64 ImageBase;
	UINT32 SectionAlignment;
	UINT32 FileAlignment;
	UINT16 MajorOperatingSystemVersion;
	UINT16 MinorOperatingSystemVersion;
	UINT16 MajorImageVersion;
	UINT16 MinorImageVersion;
	UINT16 MajorSubsystemVersion;
	UINT16 MinorSubsystemVersion;
	UINT32 Win32VersionValue;
	UINT32 SizeOfImage;
	UINT32 SizeOfHeaders;
	UINT32 CheckSum;
	UINT16 Subsystem;
	UINT16 DllCharacteristics;
	UINT64 SizeOfStackReserve;
	UINT64 SizeOfStackCommit;
	UINT64 SizeOfHeapReserve;
	UINT64 SizeOfHeapCommit;
	UINT32 LoaderFlags;
	UINT32 NumberOfRvaAndSizes;
	struct EFI_IMAGE_DATA_DIRECTORY DataDirectory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
};

struct EFI_IMAGE_FILE_HEADER {
	UINT16 Machine;
	UINT16 NumberOfSections;
	UINT32 TimeDateStamp;
	UINT32 PointerToSymbolTable;
	UINT32 NumberOfSymbols;
	UINT16 SizeOfOptionalHeader;
	UINT16 Characteristics;
};

struct EFI_IMAGE_NT_HEADERS32 {
	UINT32 Signature;
	struct EFI_IMAGE_FILE_HEADER FileHeader;
	struct EFI_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct EFI_IMAGE_NT_HEADERS64 {
	UINT32 Signature;
	struct EFI_IMAGE_FILE_HEADER FileHeader;
	struct EFI_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct EFI_TE_IMAGE_HEADER {
	UINT16 Signature;
	UINT16 Machine;
	UINT8 NumberOfSections;
	UINT8 Subsystem;
	UINT16 StrippedSize;
	UINT32 AddressOfEntryPoint;
	UINT32 BaseOfCode;
	UINT64 ImageBase;
	struct EFI_IMAGE_DATA_DIRECTORY DataDirectory[2];
};

union EFI_IMAGE_OPTIONAL_HEADER_UNION {
	struct EFI_IMAGE_NT_HEADERS32 Pe32;
	struct EFI_IMAGE_NT_HEADERS64 Pe32Plus;
	struct EFI_TE_IMAGE_HEADER Te;
};

struct PE_COFF_LOADER_IMAGE_CONTEXT {
	UINT64 ImageAddress;
	UINT64 ImageSize;
	UINT64 EntryPoint;
	UINTN SizeOfHeaders;
	UINT16 ImageType;
	UINT16 NumberOfSections;
	UINT32 FileAlignment;
	struct EFI_IMAGE_SECTION_HEADER *FirstSection;
	struct EFI_IMAGE_DATA_DIRECTORY *RelocDir;
	struct EFI_IMAGE_DATA_DIRECTORY *SecDir;
	UINT64 NumberOfRvaAndSizes;
	union EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr;
};

EFI_STATUS
pecoff_read_header(struct PE_COFF_LOADER_IMAGE_CONTEXT *context, void *data);

static inline void*
pecoff_image_address(void *image, int size, unsigned int address)
{
	if (address > size)
		return NULL;

	return (uint8_t *)image + address;
}

#endif
