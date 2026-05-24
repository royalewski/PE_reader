#include "pe.h"

void print_dos_header(void){
    printf("=== DOS HEADER ===\n");
    printf("WORD  Magic: %c%c\n", dos.e_magic[0], dos.e_magic[1]);
    printf("\t.\n\t.\n\t.\n");
    printf("DWORD e_lfanew: %u (0x%X)\n", dos.e_lfanew, dos.e_lfanew);
    return;
}

exit_t print_coff_header(){
    printf("\n=== COFF-HEADER ===\n");
    if(check_machine(coff.Machine) != true)
	return wrong_machine;
    printf("WORD  NumberOfSections: %u\n", coff.NumberOfSections);
    printf("DWORD TimeDateStamp:  %u\n", coff.TimeDateStamp);
    printf("DWORD PointerToSymbolTable: %u\n", coff.PointerToSymbolTable);
    printf("DWORD NumberOfSymbols: %u\n", coff.NumberOfSymbols);
    printf("WORD  SizeOfOptionalHeader: %u\n", coff.SizeOfOptionalHeader);
    printf("WORD  Characteristics: 0x%04X\n\n", coff.Characteristics);
    check_characteristics();
    return correct;
}

bool check_machine(uint16_t machineType){
    bool correct_machine = true;
    printf("WORD  Machine: 0x%04X - ", machineType);
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

    default     : printf("Unknown\n");
	          correct_machine = false;\
		  break;
    }
    
    return correct_machine;
}


void check_characteristics(void){
    printf("Characteristics: \n");
    if (coff.Characteristics & 0x0001) printf("IMAGE_FILE_RELOCS_STRIPPED\n");
    if (coff.Characteristics & 0x0002) printf("IMAGE_FILE_EXECUTABLE_IMAGE\n");
    if (coff.Characteristics & 0x0004) printf("IMAGE_FILE_LINE_NUMS_STRIPPED\n");
    if (coff.Characteristics & 0x0008) printf("IMAGE_FILE_LOCAL_SYMS_STRIPPED\n");
    if (coff.Characteristics & 0x0010) printf("IMAGE_FILE_AGGRESSIVE_WS_TRIM\n");
    if (coff.Characteristics & 0x0020) printf("IMAGE_FILE_LARGE_ADDRESS_AWARE\n");
    if (coff.Characteristics & 0x0040) printf("This flag is reserved for future use.\n");
    if (coff.Characteristics & 0x0080) printf("IMAGE_FILE_BYTES_REVERSED_LO\n");
    if (coff.Characteristics & 0x0100) printf("IMAGE_FILE_32BIT_MACHINE\n");
    if (coff.Characteristics & 0x0200) printf("IMAGE_FILE_DEBUG_STRIPPED\n");
    if (coff.Characteristics & 0x0400) printf("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP\n");
    if (coff.Characteristics & 0x0800) printf("IMAGE_FILE_NET_RUN_FROM_SWAP\n");
    if (coff.Characteristics & 0x1000) printf("IMAGE_FILE_SYSTEM\n");
    if (coff.Characteristics & 0x2000) printf("IMAGE_FILE_DLL\n");
    if (coff.Characteristics & 0x4000) printf("IMAGE_FILE_UP_SYSTEM_ONLY\n");
    if (coff.Characteristics & 0x8000) printf("IMAGE_FILE_BYTES_REVERSED_HI\n");								
    return;
}


void print_optional_header(header_t header_type){
    printf("\n=== OPTIONAL HEADER ===\n");
    switch(header_type){
    case Header_32Bit:
	printf("WORD  MAGIC:  0x%04X | PE32 File format\n", header32.Magic);
	printf("BYTE  MajorLinkerVersion: %u\n", header32.MajorLinkerVersion);
	printf("BYTE  MinorLinkerVersion: %u\n", header32.MinorLinkerVersion);
	printf("DWORD SizeOfCode: %u\n", header32.SizeOfCode);
	printf("DWORD SizeOfInitializedData: %u\n", header32.SizeOfInitializedData);
	printf("DWORD SizeOfUninitializedData: %u\n", header32.SizeOfUninitializedData);
	printf("DWORD AddressOfEntryPoint: %u\n", header32.AddressOfEntryPoint);
	printf("DWORD BaseOfCode: %u\n", header32.BaseOfCode);
	printf("DWORD BaseOfData: %u\n", header32.BaseOfData);
	printf("DWORD ImageBase: %u\n", header32.ImageBase);
	printf("DWORD SectionAlignment: %u\n", header32.SectionAlignment);
	printf("DWORD FileAlignment: %u\n", header32.FileAlignment);
	printf("WORD  MajorOperatingSystemVersion: %u\n", header32.MajorOperatingSystemVersion);
	printf("WORD  MinorOperatingSystemVersion: %u\n", header32.MinorOperatingSystemVersion);
	printf("WORD  MajorImageVersion: %u\n", header32.MajorImageVersion);
	printf("WORD  MinorImageVersion: %u\n", header32.MinorImageVersion);
	printf("WORD  MajorSubsystemVersion: %u\n", header32.MajorSubsystemVersion);
	printf("WORD  MinorSubsystemVersion: %u\n", header32.MinorSubsystemVersion);
	printf("DWORD Win32VersionValue: %u\n", header32.Win32VersionValue);
	printf("DWORD SizeOfImage: %u\n", header32.SizeOfImage);
	printf("DWORD SizeOfHeaders: %u\n", header32.SizeOfHeaders);
	printf("DWORD CheckSum: %u\n", header32.CheckSum);
	printf("WORD  Subsystem: %u\n", header32.Subsystem);
	printf("WORD  DllCharacteristics: %u\n", header32.DLLCharacteristics);
	printf("DWORD SizeOfStackReserve: %u\n", header32.SizeOfStackReserve);
	printf("DWORD SizeOfStackCommit: %u\n", header32.SizeOfStackCommit);
	printf("DWORD SizeOfHeapReserve: %u\n", header32.SizeOfHeapReserve);
	printf("DWORD SizeOfHeapCommit: %u\n", header32.SizeOfHeapCommit);
	printf("DWORD LoaderFlags: %u\n", header32.LoaderFlags);
	printf("DWORD NumberOfRvaAndSizes: %u\n", header32.NumberOfRvaAndSizes);
	break;
    case Header_64Bit:
	printf("WORD  MAGIC: 0x%04X\n | PE32+ File format\n", header64.Magic);
	printf("BYTE  MajorLinkerVersion: %u\n", header64.MajorLinkerVersion);
	printf("BYTE  MinorLinkerVersion: %u\n", header64.MinorLinkerVersion);
	printf("DWORD SizeOfCode: %u\n", header64.SizeOfCode);
	printf("DWORD SizeOfInitializedData: %u\n", header64.SizeOfInitializedData);
	printf("DWORD SizeOfUninitializedData: %u\n", header64.SizeOfUninitializedData);
	printf("DWORD AddressOfEntryPoint: %u\n", header64.AddressOfEntryPoint);
	printf("DWORD BaseOfCode: %u\n", header64.BaseOfCode);
	printf("ULONGLONG ImageBase: %llu\n", header64.ImageBase);
	printf("DWORD SectionAlignment: %u\n", header64.SectionAlignment);
	printf("DWORD FileAlignment: %u\n", header64.FileAlignment);
	printf("WORD  MajorOperatingSystemVersion: %u\n", header64.MajorOperatingSystemVersion);
	printf("WORD  MinorOperatingSystemVersion: %u\n", header64.MinorOperatingSystemVersion);
	printf("WORD  MajorImageVersion: %u\n", header64.MajorImageVersion);
	printf("WORD  MinorImageVersion: %u\n", header64.MinorImageVersion);
	printf("WORD  MajorSubsystemVersion: %u\n", header64.MajorSubsystemVersion);
	printf("WORD  MinorSubsystemVersion: %u\n", header64.MinorSubsystemVersion);
	printf("DWORD Win32VersionValue: %u\n", header64.Win32VersionValue);
	printf("DWORD SizeOfImage: %u\n", header64.SizeOfImage);
	printf("DWORD SizeOfHeaders: %u\n", header64.SizeOfHeaders);
	printf("DWORD CheckSum: %u\n", header64.CheckSum);
	printf("WORD  Subsystem: %u\n", header64.Subsystem);
	printf("WORD  DllCharacteristics: %u\n", header64.DLLCharacteristics);
	printf("ULONGLONG SizeOfStackReserve: %llu\n", header64.SizeOfStackReserve);
	printf("ULONGLONG SizeOfStackCommit: %llu\n", header64.SizeOfStackCommit);
	printf("ULONGLONG SizeOfHeapReserve: %llu\n", header64.SizeOfHeapReserve);
	printf("ULONGLONG SizeOfHeapCommit: %llu\n", header64.SizeOfHeapCommit);
	printf("DWORD LoaderFlags: %u\n", header64.LoaderFlags);
	printf("DWORD NumberOfRvaAndSizes: %u\n", header64.NumberOfRvaAndSizes);
	break;
    case Header_ROM:
	printf("Type is Read Only Memory\n");
       	break;
    case Header_Unknown:
	printf("Type is Unknown");
	break;
    default: return;
    }
    return;
    
}

void print_all_section_headers(IMAGE_SECTION_HEADER *sections){
   
    uint16_t i,j = 0;

    for(i = 0; i < coff.NumberOfSections; i++){
        printf("\n=== SECTION HEADER ===\n");
	printf("BYTE  Name: ");
	for(j = 0; j < 8; j++){
	    if(isprint(sections[i].Name[j]) || sections[i].Name[j] == '.')
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
	printf("DWORD Characteristics: 0x%04X:\n", sections[i].Characteristics);
	check_section_flags(sections[i].Characteristics);
    }
    return;
    
}

void check_section_flags(uint32_t section_characteristics) {

    // Flagi podstawowe
    if (section_characteristics & 0x00000008) printf("  IMAGE_SCN_TYPE_NO_PAD\n");
    if (section_characteristics & 0x00000020) printf("  IMAGE_SCN_CNT_CODE\n");
    if (section_characteristics & 0x00000040) printf("  IMAGE_SCN_CNT_INITIALIZED_DATA\n");
    if (section_characteristics & 0x00000080) printf("  IMAGE_SCN_CNT_UNINITIALIZED_DATA\n");
    if (section_characteristics & 0x00000200) printf("  IMAGE_SCN_LNK_INFO\n");
    if (section_characteristics & 0x00000800) printf("  IMAGE_SCN_LNK_REMOVE\n");
    if (section_characteristics & 0x00001000) printf("  IMAGE_SCN_LNK_COMDAT\n");
    if (section_characteristics & 0x00008000) printf("  IMAGE_SCN_GPREL\n");
    if (section_characteristics & 0x01000000) printf("  IMAGE_SCN_LNK_NRELOC_OVFL\n");
    if (section_characteristics & 0x02000000) printf("  IMAGE_SCN_MEM_DISCARDABLE\n");
    if (section_characteristics & 0x04000000) printf("  IMAGE_SCN_MEM_NOT_CACHED\n");
    if (section_characteristics & 0x08000000) printf("  IMAGE_SCN_MEM_NOT_PAGED\n");
    if (section_characteristics & 0x10000000) printf("  IMAGE_SCN_MEM_SHARED\n");
    if (section_characteristics & 0x20000000) printf("  IMAGE_SCN_MEM_EXECUTE\n");
    if (section_characteristics & 0x40000000) printf("  IMAGE_SCN_MEM_READ\n");
    if (section_characteristics & 0x80000000) printf("  IMAGE_SCN_MEM_WRITE\n");

    // Obsługa wyrównania (Align) - bity od 0x00100000 do 0x00F00000
    uint32_t align = section_characteristics & 0x00F00000;
    switch(align) {
        case 0x00100000: printf("  IMAGE_SCN_ALIGN_1BYTES\n"); break;
        case 0x00200000: printf("  IMAGE_SCN_ALIGN_2BYTES\n"); break;
        case 0x00300000: printf("  IMAGE_SCN_ALIGN_4BYTES\n"); break;
        case 0x00400000: printf("  IMAGE_SCN_ALIGN_8BYTES\n"); break;
        case 0x00500000: printf("  IMAGE_SCN_ALIGN_16BYTES\n"); break;
        case 0x00600000: printf("  IMAGE_SCN_ALIGN_32BYTES\n"); break;
        case 0x00700000: printf("  IMAGE_SCN_ALIGN_64BYTES\n"); break;
        case 0x00800000: printf("  IMAGE_SCN_ALIGN_128BYTES\n"); break;
        case 0x00900000: printf("  IMAGE_SCN_ALIGN_256BYTES\n"); break;
        case 0x00A00000: printf("  IMAGE_SCN_ALIGN_512BYTES\n"); break;
        case 0x00B00000: printf("  IMAGE_SCN_ALIGN_1024BYTES\n"); break;
        case 0x00C00000: printf("  IMAGE_SCN_ALIGN_2048BYTES\n"); break;
        case 0x00D00000: printf("  IMAGE_SCN_ALIGN_4096BYTES\n"); break;
        case 0x00E00000: printf("  IMAGE_SCN_ALIGN_8192BYTES\n"); break;
    }
}
