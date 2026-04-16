/* pe.h*/
#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>

#define E_LFANEW                         0x3C
#define PE_ADDR                          0x80

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
}IMAGE_DOS_HEADER;
extern IMAGE_DOS_HEADER dos;

typedef struct{
    uint8_t Signature[4];
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_PE_HEADER;
extern IMAGE_PE_HEADER pe;

typedef enum {
    Type_32Bit = 0,
    Type_64Bit = 1,
    Type_Rom = 2,
    Type_Unknown = 3,
}Header_type;

#pragma pack(push,1)
typedef struct IMAGE_DATA_DIRECTORY {
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

void GET_IMAGE_DOS_HEADER(uint8_t buffer[]);
void PE_HEADER(uint8_t buffer[], FILE *f);
Header_type get_optional_header(FILE *f);
void PRINT_PE_HEADER(void);
void print_optional_header(Header_type header_type);
void checkMachine(uint16_t machineType);
void get_all_section_headers(FILE *f, Header_type header_type, IMAGE_SECTION_HEADER *sections);
void print_all_section_headers(IMAGE_SECTION_HEADER *sections);
