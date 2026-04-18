#include "pe.h"

IMAGE_DOS_HEADER dos;
IMAGE_PE_HEADER pe;
IMAGE_OPTIONAL_HEADER32 header32;
IMAGE_OPTIONAL_HEADER64 header64;


void get_image_dos_header(uint8_t buffer[]){
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

bool get_pe_header(uint8_t buffer[], FILE *f){
    
    fseek(f, dos.e_lfanew, SEEK_SET);
    if (fread(buffer, 1, 64, f) != 64) {
	printf("Read error\n");
	return false;
    }
    
    memcpy(&pe.Signature, &buffer[FH_SIGNATURE], 4);
    if (pe.Signature[0] != 'P' || pe.Signature[1] != 'E' ||
        pe.Signature[2] != 0 || pe.Signature[3] != 0) {
	printf("Invalid PE signature\n");
	return false;
    }
    memcpy(&pe.Machine,              &buffer[FH_MACHINE],sizeof(uint16_t));
    memcpy(&pe.NumberOfSections,     &buffer[FH_NUMBER_OF_SECTIONS],sizeof(uint16_t));
    memcpy(&pe.TimeDateStamp,        &buffer[FH_TIME_DATE_STAMP],sizeof(uint32_t));
    memcpy(&pe.PointerToSymbolTable, &buffer[FH_POINTER_TO_SYMBOL_TABLE],sizeof(uint32_t));
    memcpy(&pe.NumberOfSymbols,      &buffer[FH_NUMBER_OF_SYMBOLS],sizeof(uint32_t));
    memcpy(&pe.SizeOfOptionalHeader, &buffer[FH_SIZE_OF_OPTIONAL_HEADER],sizeof(uint16_t));
    memcpy(&pe.Characteristics,      &buffer[FH_CHARACTERISTICS],sizeof(uint16_t));
    
    return (pe.SizeOfOptionalHeader == 0) ? true : false; 
}


header_t get_optional_header(FILE *f){
    uint8_t  buffer[sizeof(header64)];
    uint32_t headerStart = dos.e_lfanew+sizeof(IMAGE_PE_HEADER);
    uint16_t headerType = 0;

    fseek(f, headerStart , SEEK_SET);
    if (fread(buffer, 1, sizeof(header64.Magic), f) != sizeof(header64.Magic)) {
	printf("Read error\n");
	return Type_Unknown;
    }
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

void get_all_section_headers(FILE *f, header_t header_type, IMAGE_SECTION_HEADER *sections){
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






