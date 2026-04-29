#include "pe.h"

MIN_IMAGE_DOS_HEADER dos;
IMAGE_COFF_HEADER coff;
IMAGE_OPTIONAL_HEADER32 header32;
IMAGE_OPTIONAL_HEADER64 header64;

exit_t get_image_dos_header(FILE* f, uint64_t file_size) {
    unsigned char dos_buf[DOS_MIN_HEADER_SIZE];
    if(fread(dos_buf, 1, sizeof(dos_buf), f) != sizeof(dos_buf)){
	return read_error;
    }
    dos.e_magic[0] = dos_buf[0];
    dos.e_magic[1] = dos_buf[1];
    memcpy(&dos.e_lfanew, &dos_buf[E_LFANEW], sizeof(uint32_t));
    if(dos.e_lfanew > file_size){
	printf("ERROR: E_LFANEW pointing outside the file");
	return wrong_elfanew;
    }
   
    return correct;
}

exit_t get_coff_header(FILE *f, bool is_exe, file_t* file_type) {
    if (is_exe) {
	uint32_t sig;
        if(fseek(f, dos.e_lfanew, SEEK_SET) != 0)  return read_error;
        if(fread(&sig, sizeof(sig), 1, f) != 1)    return read_error;
        if (sig != SIGNATURE) {
            printf("Error: Invalid PE signature\n");
            return (wrong_pe);
        }
    } else {
           dos.e_lfanew = 0;
    }

    if (fread(&coff, 1, sizeof(IMAGE_COFF_HEADER), f) != sizeof(IMAGE_COFF_HEADER)) {
        printf("Error reading File Header\n");
        return (read_error);
    }

    if (coff.NumberOfSections > NUMBER_OF_SECTIONS_LIMIT) {
        printf("Error: Too many sections (%d). Limit is %d.\n", coff.NumberOfSections, NUMBER_OF_SECTIONS_LIMIT);
        return(  wrong_num_of_sections);
    }
    
    *file_type = (coff.SizeOfOptionalHeader == 0) ? File_COFF : File_EXE;
    return correct;
}

exit_t get_optional_header(FILE *f, header_t* header_type) {
    /* Offset: e_lfanew + 4 (sig) + 20 (file header) */
    uint32_t headerStart = dos.e_lfanew + SIGNATURE_SIZE + sizeof(IMAGE_COFF_HEADER);
    uint16_t magicValue = 0;

    if(fseek(f, headerStart, SEEK_SET) != 0)
	    return read_error;
    if(fread(&magicValue, sizeof(magicValue), 1, f) != 1)
	    return read_error;
    if(fseek(f, headerStart, SEEK_SET) != 0)
	return read_error;

    
    if (magicValue == HEADER32_MAGIC) {
        if(fread(&header32, sizeof(IMAGE_OPTIONAL_HEADER32), 1, f) != 1)
	   return read_error;
	*header_type = Header_32Bit;
    }
    else if (magicValue == HEADER64_MAGIC) {
        if(fread(&header64, sizeof(IMAGE_OPTIONAL_HEADER64), 1, f) != 1)
	    return read_error;
        *header_type =  Header_64Bit;
    }
    else
	*header_type =  Header_Unknown;
    return correct;
}

exit_t  get_all_section_headers(FILE *f, header_t header_type, IMAGE_SECTION_HEADER *sections) {
    uint32_t sectionTableStart;

    if (header_type == Header_COFF) {
        sectionTableStart = sizeof(IMAGE_COFF_HEADER);
    } else {
        sectionTableStart = dos.e_lfanew + SIGNATURE_SIZE + sizeof(IMAGE_COFF_HEADER) + coff.SizeOfOptionalHeader;
    }

    if(fseek(f, sectionTableStart, SEEK_SET) != 0)
	return read_error;
    if(fread(sections, sizeof(IMAGE_SECTION_HEADER), coff.NumberOfSections, f) != coff.NumberOfSections)
	return read_error;

    return correct;
}
