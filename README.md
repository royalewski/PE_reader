# PE Reader

A simple PE/COFF file parser written in C.

The program reads and displays basic information from Windows Portable Executable files and COFF object files. It was created as a learning project focused on low-level binary parsing, executable file structure and PE/COFF headers.

## Features

- detects PE files using the `MZ` DOS header and `PE\0\0` signature
- supports COFF object files without a DOS header
- parses the DOS header
- parses the COFF/File Header
- detects PE32 and PE32+ Optional Headers
- parses PE section headers
- displays section metadata and characteristics
- performs basic input validation, including:
  - file size checks
  - invalid PE signature detection
  - `e_lfanew` bounds checking
  - section count limit

## Supported formats

- PE32 executable files
- PE32+ executable files
- COFF object files

## Project structure

```text
PE_reader/
├── Makefile
├── pe.h
├── pe_parser.c
├── pe_printer.c
└── pe_reader.c
