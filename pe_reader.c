#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define E_LFANEW                         0x3C
#define PE_ADDR                          0x80

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
unsigned int readLong = 0;
unsigned short int readWord = 0;

typedef struct{
    unsigned char e_magic[2];
    unsigned int e_lfanew;
}IMAGE_DOS_HEADER;
IMAGE_DOS_HEADER dos;

void checkMachine(unsigned short int machineType);

void GET_IMAGE_DOS_HEADER(unsigned char buffer[]){
    dos.e_magic[0] = buffer[0];
    dos.e_magic[1] = buffer[1];
    
    memcpy(&dos.e_lfanew, &buffer[E_LFANEW], sizeof(readLong));
    printf("WORD  e_magic: %c%c\n", dos.e_magic[0], dos.e_magic[1]);
    printf("DWORD e_lfanew: %u\n\n", dos.e_lfanew);
    return;
}

typedef struct{
    unsigned char Signature[4];
    unsigned short int Machine;
    unsigned short int NumberOfSections;
    unsigned int TimeDateStamp;
    unsigned int PointerToSymbolTable;
    unsigned int NumberOfSymbols;
    unsigned short int SizeOfOptionalHeader;
    unsigned short int Characteristics;
} IMAGE_PE_HEADER;
IMAGE_PE_HEADER pe;

void PE_HEADER(unsigned char buffer[], FILE *f){
    
    fseek(f, dos.e_lfanew, SEEK_SET);
    if (fread(buffer, 1, 64, f) != 64) {
	printf("Read error\n");
	return;
    }
    memcpy(&pe.Signature,            &buffer[0], 4);
    memcpy(&pe.Machine,              &buffer[FH_MACHINE],sizeof(readWord));
    memcpy(&pe.NumberOfSections,     &buffer[FH_NUMBER_OF_SECTIONS],sizeof(readWord));
    memcpy(&pe.TimeDateStamp,        &buffer[FH_TIME_DATE_STAMP],sizeof(readLong));
    memcpy(&pe.PointerToSymbolTable, &buffer[FH_POINTER_TO_SYMBOL_TABLE],sizeof(readLong));
    memcpy(&pe.NumberOfSymbols,      &buffer[FH_NUMBER_OF_SYMBOLS],sizeof(readLong));
    memcpy(&pe.SizeOfOptionalHeader, &buffer[FH_SIZE_OF_OPTIONAL_HEADER],sizeof(readWord));
    memcpy(&pe.Characteristics, &buffer[FH_CHARACTERISTICS],sizeof(readWord));
    return;
}
void PRINT_PE_HEADER(unsigned char buffer[]){
    printf("=== PE-HEADER ===\n");
    printf("SIGNATURE %c%c\\%x\\%x\n",pe.Signature[0],pe.Signature[1],pe.Signature[2],pe.Signature[3]);
    checkMachine(pe.Machine);
    printf("WORD  NumberOfSections: %u\n", pe.NumberOfSections);
    printf("DWORD TimeDateStamp: %u\n", pe.TimeDateStamp);
    printf("DWORD PointerToSymbolTable: %u\n", pe.PointerToSymbolTable);
    printf("DWORD NumberOfSymbols: %u\n", pe.NumberOfSymbols);
    printf("WORD  SizeOfOptionalHeader: %u\n", pe.SizeOfOptionalHeader);
    printf("WORD  Characteristics: %u\n", pe.Characteristics);
    
    return;
}

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
}Header64;
Header64 header64;

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
} Header32;
Header32 header32;
#pragma pack(pop)

void get_optional_header(FILE *f){
    unsigned char buffer[sizeof(Header64)];
    uint32_t headerStart = dos.e_lfanew+sizeof(IMAGE_PE_HEADER);
    
    fseek(f, headerStart , SEEK_SET);
    if (fread(buffer, 1, sizeof(header64.Magic), f) != sizeof(header64.Magic)) {
	printf("Read error\n");
	return;
    }
    uint16_t headerType = 0;
    fseek(f, headerStart , SEEK_SET);
    memcpy(&headerType, &buffer[0], sizeof(header64.Magic));
    if(headerType == HEADER32_MAGIC){
	if (fread(&header32, 1, sizeof(header32), f) != sizeof(header32))
	    printf("Read error\n");
    }
    else if(headerType == HEADER64_MAGIC){
	if (fread(&header64, 1, sizeof(header64), f) != sizeof(header64))
	    printf("Read error\n");
    }
    else if(headerType == ROM_MAGIC)
	printf("\nIts ROM Type");
		
    return;
}
void print_optional_header(){
    printf("=== OPTIONAL HEADER ===\n");
    printf("WORD MAGIC: %u\n", header32.Magic);
    printf("BYTE MajorLinkerVersion: %u\n", header32.MajorLinkerVersion);
    printf("BYTE MinorLinkerVersion: %u\n", header32.MinorLinkerVersion);
    return;
    
}
int main (int argc, char *argv[]){
    if(argc == 1){
	printf("No input .exe file name\n");
	return(-1);
    }
    else if(argc > 2){
	printf("Too many arguments\n");
	return(-1);
    }
    
    unsigned char buffer[64];
    FILE *f = fopen(argv[1], "rb");
    if(!f){
	printf("Error opening file\n");
	return(-1);
    }
    
    if (fread(buffer, 1, 64, f) != 64) {
	printf("Read error\n");
	return -1;
    }
    if(buffer[0] != 'M' || buffer[1] != 'Z'){
	printf("Not a PE file");
	return(-1);
    }
    GET_IMAGE_DOS_HEADER(buffer);
    PE_HEADER(buffer,f);
    PRINT_PE_HEADER(buffer);
    get_optional_header(f);
    print_optional_header();
    return(0);
}

void checkMachine(unsigned short int machineType){
    
    printf("WORD  Machine: %4x - ", machineType);
    switch(machineType){
    case 0x014c : printf("Intel 386 or later processors\n"); break;
    case 0x8664 : printf("x64\n"); break;
    case 0x01c0 : printf("ARM little endian\n"); break;
    case 0xaa64 : printf("ARM64 little endian\n"); break;
    default     : printf("Unknown\n"); break;
    }
    
    return;
}
