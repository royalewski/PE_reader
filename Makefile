CC=gcc
CLAGS= -Wall -Wextra -std=c99 -pedantic

pe_reader.exe: pe_reader.o pe_printer.o pe_parser.o
	$(CC) $(CFLAGS) pe_parser.o pe_printer.o pe_reader.o -o pe_reader.exe

pe_parser.o: pe_parser.c pe.h
	$(CC) $(CFLAGS) -c pe_parser.c -o pe_parser.o

pe_reader.o: pe_reader.c pe.h
	$(CC) $(CFLAGS) -c pe_reader.c -o pe_reader.o

pe_printer.o: pe_printer.c pe.h
	$(CC) $(CFLAGS) -c pe_printer.c -o pe_printer.o
