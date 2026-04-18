#include "pe.h"



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
    get_image_dos_header(buffer);
    get_pe_header(buffer,f);
    print_pe_header();

    header_t header_type;
    header_type = get_optional_header(f);
    print_optional_header(header_type);

    uint8_t sectionNum = pe.NumberOfSections;
    IMAGE_SECTION_HEADER *sections;
    sections = (IMAGE_SECTION_HEADER*) malloc(sectionNum*sizeof(IMAGE_SECTION_HEADER));
    if(sections == NULL){
	printf("Allocation Error!");
	return -1;
    }
    get_all_section_headers(f, header_type, sections);
    print_all_section_headers(sections);
    free(sections); 
    return(0);
}

