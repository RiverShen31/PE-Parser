#ifndef HEADERS_H
#define HEADERS_H


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "pe_header.h"

// functions to read little endian data (strings and integers)
char     *read_str(FILE *in, int count);
uint8_t   read8_little_endian(FILE *in);
uint16_t  read16_little_endian(FILE *in);
uint32_t  read32_little_endian(FILE *in);
uint64_t  read64_little_endian(FILE *in);


// functions that perform high level tasks 
void load_file(int argc, char *argv[]);
void print_headers(DOS_HEADER_T *dosHeader);
void print_dataTables(DOS_HEADER_T *dosHeader);
void print_sections(DOS_HEADER_T *dosHeader);


#endif