/* pe.h*/
#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>

#define SIGNATURE_SIZE                   4
#define COFF_HEADER_SIZE                 20
#define SECTION_HEADER_SIZE              40
#define DOS_MIN_HEADER_SIZE              64
#define NUMBER_OF_SECTIONS_LIMIT         96

#define E_LFANEW                         0x3C

#define SIGNATURE                        0x00004550
#define FH_SIGNATURE                     0
#define FH_MACHINE                       4
#define FH_NUMBER_OF_SECTIONS            6
#define FH_TIME_DATE_STAMP               8
#define FH_POINTER_TO_SYMBOL_TABLE       12
#define FH_NUMBER_OF_SYMBOLS             16
#define FH_SIZE_OF_OPTIONAL_HEADER       20
#define FH_CHARACTERISTICS               22
#define HEADER64_MAGIC                   0x20B
#define HEADER32_MAGIC                   0x10B
#define ROM_MAGIC                        0x107



typedef struct{
    uint8_t e_magic[2];
    uint32_t e_lfanew;
}MIN_IMAGE_DOS_HEADER;
extern MIN_IMAGE_DOS_HEADER dos;

#pragma pack(push,1)
typedef struct{
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_COFF_HEADER;
#pragma pack(pop)
extern IMAGE_COFF_HEADER coff;

typedef enum {
    Header_Unknown,
    Header_32Bit,
    Header_64Bit,
    Header_ROM,
    Header_COFF
} header_t;

typedef enum {
    File_Unknown,
    File_EXE,
    File_COFF
} file_t;

typedef enum{
    correct = 0,
    wrong_input,
    too_small,
    read_error,
    wrong_mz,
    allocation_error,
    wrong_elfanew,
    wrong_pe,
    wrong_machine,
    wrong_num_of_sections,
    open_file_error,
    wrong_section_num
}exit_t;


#pragma pack(push,1)
typedef struct {

  uint32_t  VirtualAddress;
  uint32_t  Size;
} IMAGE_DATA_DIRECTORY;

typedef struct{
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DLLCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
}IMAGE_OPTIONAL_HEADER64;
extern IMAGE_OPTIONAL_HEADER64 header64;

typedef struct{
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DLLCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;
extern IMAGE_OPTIONAL_HEADER32 header32;

typedef struct{
    uint8_t Name[8];
    union{
	uint32_t PhysicalAddress;
	uint32_t VirtualSize;
    }Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
}IMAGE_SECTION_HEADER;
#pragma pack(pop)

exit_t get_image_dos_header(FILE* f, uint64_t file_size);
void print_dos_header(void);
exit_t get_coff_header(FILE *f, bool is_exe, file_t* file_type);
exit_t get_optional_header(FILE *f, header_t *header_type);
exit_t print_coff_header(void);
void print_optional_header(header_t header_type);
bool check_machine(uint16_t machineType);
exit_t get_all_section_headers(FILE *f, header_t header_type, IMAGE_SECTION_HEADER *sections);
void print_all_section_headers(IMAGE_SECTION_HEADER *sections);
void check_characteristics(void);
void check_section_flags(uint32_t section_characteristics);
