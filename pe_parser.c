#include "pe.h"

IMAGE_DOS_HEADER dos;
IMAGE_PE_HEADER pe;
IMAGE_OPTIONAL_HEADER32 header32;
IMAGE_OPTIONAL_HEADER64 header64;


void GET_IMAGE_DOS_HEADER(uint8_t buffer[]){
    dos.e_magic[0] = buffer[0];
    dos.e_magic[1] = buffer[1];
    if(dos.e_magic[0] != 'M' || dos.e_magic[1] != 'Z'){
	printf("Invalid DOS Header");
	return;
    }
    memcpy(&dos.e_lfanew, &buffer[E_LFANEW], sizeof(uint32_t));
    printf("WORD  e_magic: %c%c\n", dos.e_magic[0], dos.e_magic[1]);
    printf("DWORD e_lfanew: %u\n\n", dos.e_lfanew);
    return;
}

void PE_HEADER(uint8_t buffer[], FILE *f){
    
    fseek(f, dos.e_lfanew, SEEK_SET);
    if (fread(buffer, 1, 64, f) != 64) {
	printf("Read error\n");
	return;
    }
    
    memcpy(&pe.Signature, &buffer[FH_SIGNATURE], 4);
    if (pe.Signature[0] != 'P' || pe.Signature[1] != 'E' ||
        pe.Signature[2] != 0 || pe.Signature[3] != 0) {
	printf("Invalid PE signature\n");
	return;
    }
    memcpy(&pe.Machine,              &buffer[FH_MACHINE],sizeof(uint16_t));
    memcpy(&pe.NumberOfSections,     &buffer[FH_NUMBER_OF_SECTIONS],sizeof(uint16_t));
    memcpy(&pe.TimeDateStamp,        &buffer[FH_TIME_DATE_STAMP],sizeof(uint32_t));
    memcpy(&pe.PointerToSymbolTable, &buffer[FH_POINTER_TO_SYMBOL_TABLE],sizeof(uint32_t));
    memcpy(&pe.NumberOfSymbols,      &buffer[FH_NUMBER_OF_SYMBOLS],sizeof(uint32_t));
    memcpy(&pe.SizeOfOptionalHeader, &buffer[FH_SIZE_OF_OPTIONAL_HEADER],sizeof(uint16_t));
    memcpy(&pe.Characteristics,      &buffer[FH_CHARACTERISTICS],sizeof(uint16_t));
    return;
}

Header_type get_optional_header(FILE *f){
    uint8_t buffer[sizeof(header64)];
    uint32_t headerStart = dos.e_lfanew+sizeof(IMAGE_PE_HEADER);
    
    fseek(f, headerStart , SEEK_SET);
    if (fread(buffer, 1, sizeof(header64.Magic), f) != sizeof(header64.Magic)) {
	printf("Read error\n");
	return Type_Unknown;
    }
    uint16_t headerType = 0;
    fseek(f, headerStart , SEEK_SET);

    memcpy(&headerType, &buffer[0], sizeof(header64.Magic));
    if(headerType == HEADER32_MAGIC){
	if (fread(&header32, 1, sizeof(header32), f) != sizeof(header32))
	    printf("Read error 32 bit\n");
	return Type_32Bit;
    }
    else if(headerType == HEADER64_MAGIC){
	if (fread(&header64, 1, sizeof(header64), f) != sizeof(header64))
	    printf("Read error 64bit\n");
	return Type_64Bit;
    }
    else if(headerType == ROM_MAGIC){
	printf("\nIts ROM Type");
	return  Type_Rom;
    }

    return Type_Unknown;
}

void get_all_section_headers(FILE *f, Header_type header_type, IMAGE_SECTION_HEADER *sections){
    uint32_t headerStart =  dos.e_lfanew+sizeof(IMAGE_PE_HEADER);
    switch(header_type){
    case Type_32Bit:
        headerStart += sizeof(IMAGE_OPTIONAL_HEADER32);
	break;
    case Type_64Bit:
        headerStart += sizeof(IMAGE_OPTIONAL_HEADER64);
	break;
    default:
	break;
    }
    uint16_t i = 0;
    for(i = 0; i < pe.NumberOfSections; i++){
	fseek(f, headerStart , SEEK_SET);
	if (fread(&sections[i], 1, sizeof(IMAGE_SECTION_HEADER), f) != sizeof(IMAGE_SECTION_HEADER)) {
	    printf("Read error\n");
	}
     	headerStart = headerStart + (sizeof(IMAGE_SECTION_HEADER));
    }
    return;
}

void print_all_section_headers(IMAGE_SECTION_HEADER *sections){
   
    uint16_t i,j = 0;

    for(i = 0; i < pe.NumberOfSections; i++){
        printf("\n=== SECTION HEADER ===\n");
	printf("BYTE Name: ");
	for(j = 0; j < 8; j++){
	    if(isalpha(sections[i].Name[j]) || sections[i].Name[j] == '.')
		printf("%c", sections[i].Name[j]);
	}	   
	printf("\nDWORD PhysicalAddress | VirtualSize: %u\n", sections[i].Misc.PhysicalAddress);
	printf("DWORD VirtualAddress: %u\n", sections[i].VirtualAddress);
	printf("DWORD SizeOfRawData: %u\n", sections[i].SizeOfRawData);
	printf("DWORD PointerToRawData: %u\n", sections[i].PointerToRawData);
	printf("DWORD PointerToRelocations: %u\n", sections[i].PointerToRelocations);
	printf("DWORD PointerToLinenumbers: %u\n", sections[i].PointerToLinenumbers);
	printf("WORD  NumberOfRelocations: %u\n", sections[i].NumberOfRelocations);
	printf("WORD  Numberoflinenumbers: %u\n", sections[i].NumberOfLinenumbers);
	printf("DWORD Characteristics: %u", sections[i].Characteristics);
	
    }
    return;
    
}


void checkMachine(uint16_t machineType){
    
    printf("WORD  Machine: %4x - ", machineType);
    switch(machineType){
    case 0x0000 : printf("The content of this field is assumed to be applicable to any machine type\n"); break;
    case 0x0184 : printf("Alpha AXP, 32-bit address space\n"); break;
    case 0x0284 : printf("Alpha 64, 64-bit address space\n"); break;
    case 0x01d3 : printf("Matsushita AM33\n"); break;
    case 0x8664 : printf("x64\n"); break;
    case 0x01c0 : printf("ARM little endian\n"); break;
    case 0xaa64 : printf("ARM64 little endian\n"); break;
    case 0xA641 : printf("ABI that enables interoperability between native ARM64 and emulated x64 code.\n"); break;
    case 0xA64E : printf("Binary format that allows both native ARM64 and ARM64EC code to coexist in the same file.\n"); break;
    case 0x01c4 : printf("ARM Thumb-2 little endian\n"); break;
    case 0x0ebc : printf("EFI byte code\n"); break;
    case 0x014c : printf("Intel 386 or later processors and compatible processors\n"); break;
    case 0x0200 : printf("Intel Itanium processor family\n"); break;
    case 0x6232 : printf("LoongArch 32-bit processor family\n"); break;
    case 0x6264 : printf("LoongArch 64-bit processor family\n"); break;
    case 0x9041 : printf("Mitsubishi M32R little endian\n"); break;
    case 0x0266 : printf("MIPS16\n"); break;
    case 0x0366 : printf("MIPS with FPU\n"); break;
    case 0x0466 : printf("MIPS16 with FPU\n"); break;
    case 0x01f0 : printf("Power PC little endian\n"); break;
    case 0x01f1 : printf("Power PC with floating point support\n"); break;
    case 0x0160 : printf("MIPS I compatible 32-bit big endian\n"); break;
    case 0x0162 : printf("MIPS I compatible 32-bit little endian\n"); break;
    case 0x0166 : printf("MIPS III compatible 64-bit little endian\n"); break;
    case 0x0168 : printf("MIPS IV compatible 64-bit little endian\n"); break;
    case 0x5032 : printf("RISC-V 32-bit address space\n"); break;
    case 0x5064 : printf("RISC-V 64-bit address space\n"); break;
    case 0x5128 : printf("RISC-V 128-bit address space\n"); break;
    case 0x01a2 : printf("Hitachi SH3\n"); break;
    case 0x01a3 : printf("Hitachi SH3 DSP\n"); break;
    case 0x01a6 : printf("Hitachi SH4\n"); break;
    case 0x01a8 : printf("Hitachi SH5\n"); break;
    case 0x01c2 : printf("Thumb\n"); break;
    case 0x0169 : printf("MIPS little-endian WCE v2\n"); break;

    default     : printf("Unknown\n"); break;
    }
    
    return;
}


