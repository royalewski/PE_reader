#include "pe.h"

int main(int argc, char *argv[])
{
    exit_t err = correct;

    if (argc == 1) {
	printf("Usage: pe_reader.exe <input.exe|input.obj>\n");
        return wrong_input;
    } else if (argc > 2) {
        printf("Too many arguments\n");
        return wrong_input;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("Error opening file\n");
        return open_file_error;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return read_error;
    }

    long pos = ftell(f);
    if (pos < 0) {
        fclose(f);
        return read_error;
    }

    size_t file_size = (size_t)pos;
    rewind(f);

    if (file_size < COFF_HEADER_SIZE) {
        printf("File too small to be PE/COFF\n");
        fclose(f);
        return too_small;
    }

    unsigned char magic[2] = {0};
    if (fread(magic, 1, sizeof(magic), f) != sizeof(magic)) {
        fclose(f);
        return read_error;
    }
    rewind(f);

    file_t file_type = File_Unknown;
    header_t header_type = Header_Unknown;
    bool is_exe = false;

    if (magic[0] == 'M' && magic[1] == 'Z') {
        is_exe = true;

        err = get_image_dos_header(f, file_size);
        if (err != correct) {
            fclose(f);
            return err;
        }

        print_dos_header();

        err = get_coff_header(f, is_exe, &file_type);
        if (err != correct) {
            fclose(f);
            return err;
        }
    } else {
        err = get_coff_header(f, is_exe, &file_type);
        if (err != correct) {
            fclose(f);
            return err;
        }
    }

    print_coff_header();

    if (file_type == File_EXE) {
        err = get_optional_header(f, &header_type);
        if (err != correct) {
            fclose(f);
            return err;
        }

        print_optional_header(header_type);
    }
    else {
        printf("Format: COFF (Object file) - No Optional Header available.\n");
        header_type = Header_COFF; /* temporary design choice */
    }

    uint16_t sectionNum = coff.NumberOfSections;
    if (sectionNum > NUMBER_OF_SECTIONS_LIMIT) {
        printf("Number of sections (%u) exceeds safe limit (%u)\n",
               sectionNum,
               NUMBER_OF_SECTIONS_LIMIT);
        fclose(f);
        return wrong_section_num;
    }

    if (sectionNum > 0) {
        IMAGE_SECTION_HEADER *sections =
            (IMAGE_SECTION_HEADER *)malloc(sectionNum * sizeof(IMAGE_SECTION_HEADER));

        if (sections == NULL) {
            printf("Allocation Error!\n");
            fclose(f);
            return allocation_error;
        }

        err = get_all_section_headers(f, header_type, sections);
        if (err != correct) {
            free(sections);
            fclose(f);
            return err;
        }

        print_all_section_headers(sections);
        free(sections);
    }

    fclose(f);
    return correct;
}
