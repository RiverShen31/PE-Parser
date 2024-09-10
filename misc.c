#include "headers.h"

// read_str(): reads a 'count' of characters from a file
char *read_str(FILE *in, int count) {
    char *ch_ptr = (char *)malloc(sizeof(char) * count);
    for (int i=0; i<count; i++) {
        ch_ptr[i] = fgetc(in);
    }
    ch_ptr[strlen(ch_ptr)] = '\0';
    return ch_ptr;
}

// read8_le(): reads an 8-bit integer from a file
uint8_t read8_little_endian(FILE *in) {
    return fgetc(in);
}

// read16_le(): reads an 16bit little-endian integer
uint16_t  read16_little_endian(FILE *in)
{
  uint16_t value;
  value = fgetc(in);
  value |= (fgetc(in)<<8);
  return value;
}

// read32_le(): reads an 32bit little-endian integer
uint32_t  read32_little_endian(FILE *in)
{
  uint32_t value;
  value = fgetc(in);
  value |= (fgetc(in)<<8);
  value |= (fgetc(in)<<16);
  value |= (fgetc(in)<<24);
  return value;
}

// read64_le(): reads an 64bit little-endian integer
// arguments: a file stream to read from
// return: an 64 bit integer
uint64_t  read64_little_endian(FILE *in)
{
  uint64_t value;
  value = (uint64_t)fgetc(in);
  value |= ((uint64_t)fgetc(in) <<8);
  value |= ((uint64_t)fgetc(in) <<16);
  value |= ((uint64_t)fgetc(in) <<24);
  value |= ((uint64_t)fgetc(in) <<32);
  value |= ((uint64_t)fgetc(in) <<40);
  value |= ((uint64_t)fgetc(in) <<48);
  value |= ((uint64_t)fgetc(in) <<54);

  return value;
}


// load_file(): loads and reads PE files in current directory
void load_file(int argc, char *argv[]) {
    DOS_HEADER_T dosHeader;
    FILE *in;

    for (int idx=1; idx<argc; idx++) {
        in = fopen(argv[idx], "rb");
        if (in == NULL) {
            printf("Error opening file %s\n", argv[idx]);
            continue;
        }

        read_dos(in, &dosHeader);
        read_pe(in, &dosHeader);

        // making sure we have a valid/standard PE file
        if (dosHeader.pe.Signature != 0x4550) {
            printf("invalid PE signature, file is likely corrupt PE, or not a valid PE file.\n");
            fclose(in);
            return;
        }

        read_dataDir(in, &dosHeader);
        read_sections(in, &dosHeader);
        read_dataOffset(&dosHeader);
        read_exportDir(in, &dosHeader);
        read_importDir(in, &dosHeader);
        read_relocDir(in, &dosHeader);

        // test printing information
        printf("showing file: %s\n\n", argv[idx]);
        print_headers(&dosHeader);
        print_dataTables(&dosHeader);
        print_sections(&dosHeader);
        print_exports(&dosHeader);
        print_imports(&dosHeader);
        print_relocs(&dosHeader);

        // clean up
        cleanup(&dosHeader);
        fclose(in);
    }
}

// print_headers(): prints the values of a DOS header object
void print_headers(DOS_HEADER_T *dosHeader) {
    printf("Magic bytes: \t\t%c%c\n", (0xff & dosHeader->e_magic), (dosHeader->e_magic>>8));
    printf("PE offset: \t\t%X \n", dosHeader->e_lfanew);

    printf("\nPE header information\n");
    printf("Signature: \t\t0x%X (%c%c) \n", dosHeader->pe.Signature,
                                            (0xff & dosHeader->pe.Signature),
                                            (0xff & dosHeader->pe.Signature>>8));

    printf("Machine: \t\t");
    print_machine(dosHeader->pe.Machine);

    printf("Sections Count: \t\t%d\n", dosHeader->pe.NumberOfSections);
    printf("Time Date Stamp: \t\t0x%X\n", dosHeader->pe.TimeStamp);
    printf("Pointer to symbol table: 0x%X\n", dosHeader->pe.PtrToSymbolTable);
    printf("Number of symbols:       %d\n", dosHeader->pe.NumberOfSymbols);
    printf("Size of Optional Header: %d\n", dosHeader->pe.SizeOfOptionalHeader);
    printf("Characteristics:         0x%X\n", dosHeader->pe.Characteristics);
    print_pe_characteristics(dosHeader->pe.Characteristics);

    printf("\nOptional Header\n");
    printf("Magic:      ");
    print_magic(dosHeader->pe.OptionalHeader.Magic);
    printf("MajorLinkerVersion:      0x%X\n", dosHeader->pe.OptionalHeader.MajorLinkerVersion);
    printf("MinorLinkerVersion:      0x%X\n", dosHeader->pe.OptionalHeader.MinorLinkerVersion);
    printf("SizeOfCode:              0x%X\n", dosHeader->pe.OptionalHeader.SizeOfCode);
    printf("SizeOfInitializedData:   0x%X\n", dosHeader->pe.OptionalHeader.SizeOfInitializedData);
    printf("SizeOfUninitializedData: 0x%X\n", dosHeader->pe.OptionalHeader.SizeOfUninitializedData);
    printf("EntryPoint:              0x%X\n", dosHeader->pe.OptionalHeader.AddressOfEntryPoint);
    printf("BaseOfCode:              0x%X\n", dosHeader->pe.OptionalHeader.BaseOfCode);
    if( dosHeader->pe.OptionalHeader.Magic == OPTIONAL_IMAGE_PE32 ){
        printf("BaseOfData:              0x%X\n", dosHeader->pe.OptionalHeader.BaseOfData);
    }
    printf("ImageBase:               %p\n", (void*) dosHeader->pe.OptionalHeader.ImageBase);
    printf("SectionAlignment:        0x%X\n", dosHeader->pe.OptionalHeader.SectionAlignment);
    printf("FileAlignment:           0x%X\n", dosHeader->pe.OptionalHeader.FileAlignment);
    printf("MajorOSVersion:          0x%X\n", dosHeader->pe.OptionalHeader.MajorOperatingSystemVersion);
    printf("MinorOSVersion:          0x%X\n", dosHeader->pe.OptionalHeader.MinorOperatingSystemVersion);  
    printf("MajorImageVersion:       0x%X\n", dosHeader->pe.OptionalHeader.MajorImageVersion);
    printf("MinorImageVersion:       0x%X\n", dosHeader->pe.OptionalHeader.MinorImageVersion);
    printf("MajorSubsysVersion:      0x%X\n", dosHeader->pe.OptionalHeader.MajorSubsystemVersion);
    printf("MinorSubsysVersion:      0x%X\n", dosHeader->pe.OptionalHeader.MinorSubsystemVersion);
    printf("Win32VersionValue:       0x%X\n", dosHeader->pe.OptionalHeader.Win32VersionValue);
    printf("SizeOfImage:             0x%X\n", dosHeader->pe.OptionalHeader.SizeOfImage);
    printf("SizeOfHeaders:           0x%X\n", dosHeader->pe.OptionalHeader.SizeOfHeaders);
    printf("CheckSum:                0x%X\n", dosHeader->pe.OptionalHeader.CheckSum);
    printf("Subsystem:             ");
    print_subsystem(dosHeader->pe.OptionalHeader.Subsystem);
    printf("DllCharacteristics:           \n");
    print_dllcharacteristics(dosHeader->pe.OptionalHeader.DllCharacteristics);

    printf("SizeOfStackReserve:      %p\n", (void*) dosHeader->pe.OptionalHeader.SizeOfStackReserve);
    printf("SizeOfStackCommit:       %p\n", (void*) dosHeader->pe.OptionalHeader.SizeOfStackCommit);
    printf("SizeOfHeapReserve:       %p\n", (void*) dosHeader->pe.OptionalHeader.SizeOfHeapReserve);
    printf("SizeOfHeapCommit:        %p\n", (void*) dosHeader->pe.OptionalHeader.SizeOfHeapCommit);

    printf("LoaderFlags:             0x%X\n", dosHeader->pe.OptionalHeader.LoaderFlags);
    printf("NumberOfRvaAndSizes:     %d\n", dosHeader->pe.OptionalHeader.NumberOfRvaAndSizes);
}

// print_dataTables(): prints a list of data tables in a PE file
void print_dataTables(DOS_HEADER_T *dosHeader) {
    // Data Directory Types
    char dataTable[][25] = { "Export Table",       "Import Table",
                         "Resource Table",    "Exception Table",
                           "Certificate ",    "Base Relocation",
                            "Debug Table",       "Architecture",
                       "Global Ptr Table",          "TLS Table",
                           "Load Config ",       "Bound Import",
                         "Import Address", "Delay Import Desc.",
                     "CLR Runtime Header", "Reserved, must be zero"};

    uint32_t offset, vAddress, sections, tables;
    sections = dosHeader->pe.NumberOfSections;
    tables = dosHeader->pe.OptionalHeader.NumberOfRvaAndSizes;

    printf("\nData Tables: \n");
    for (int idx=0; idx<tables; idx++) {
        vAddress = dosHeader->dataDirectory[idx].VirtualAddress;
        offset = rva_to_offset(sections, vAddress, dosHeader->section_table);

        printf("    Table: %s\n", dataTable[idx]);
        printf("    Address: 0x%X \tSize:   0x%X \tOffset: %X\n", vAddress,dosHeader->dataDirectory[idx].Size, offset);
    }
}

// print_sections(): prints PE sections info
void print_sections(DOS_HEADER_T *dosHeader) {
    SECTION_TABLE_T *sections;
    sections = dosHeader->section_table;
    printf("\nSections: \n");

    for (int idx=0; idx<dosHeader->pe.NumberOfSections; idx++) {
        printf("   Name: %s\n", sections[idx].name );
        printf("       VirtualAddress:        %X\n", sections[idx].VirtualAddress );
        printf("       VirtualSize:           %X\n", sections[idx].VirtualSize );
        printf("       SizeOfRawData:         %X\n", sections[idx].SizeOfRawData );
        printf("       PointerToRawData:      %X\n", sections[idx].PointerToRawData );
        printf("       PointerToRelactons:    %X\n", sections[idx].PointerToRelocations );
        printf("       PointerToLinenumbers:  %X\n", sections[idx].PointerToLinenumbers );
        printf("       NumberOfRelocations:   %X\n", sections[idx].NumberOfRelocations );
        printf("       NumberOfLinenumbers:   %X\n", sections[idx].NumberOfLinenumbers );
        printf("       Characteristics:       %X\n", sections[idx].Characteristics );
        // print_section_characteristics(sections[idx].characteristics);
    }
}

// print_exports(): prints a list of exports in a PE file
void print_exports(DOS_HEADER_T *dosHeader) {
    printf("\nExport Directory \n");
    printf("    Flags:           0x%X\n", dosHeader->exportDir.ExportFlags);
    printf("    TimeStamp:       0x%X\n", dosHeader->exportDir.TimeStamp);
    printf("    MajorVersion:    0x%X\n", dosHeader->exportDir.MajorVersion);
    printf("    MinorVersion:    0x%X\n", dosHeader->exportDir.MinorVersion);
    printf("    Name RVA:        0x%X\n", dosHeader->exportDir.NameRVA);
    printf("    OrdinalBase:     0x%X\n", dosHeader->exportDir.OrdinalBase);
    printf("    AddressTable Entries:  0x%X\n", dosHeader->exportDir.AddrTableEntries);
    printf("    NumberOfNames:         0x%X\n", dosHeader->exportDir.NumberOfNamePointers);
    printf("    ExportTable Entries:   0x%X\n", dosHeader->exportDir.ExportAddrTableRVA);
    printf("    AddressOfNames:        0x%X\n", dosHeader->exportDir.NamePtrRVA);
    printf("    OrdinalTable RVA:      0x%X\n", dosHeader->exportDir.OrdinalTableRVA);

    printf("\nExported functions: \n");
  
    // skipping none IMAGE_FILE_DLL
    if ((dosHeader->pe.Characteristics & 0x2000) == 0) { return; }

    for (int i=0; i<dosHeader->exportDir.NumberOfNamePointers; i++) {
        printf("    %s\n", dosHeader->exportDir.exportAddr_name_t[i].names);
    }
}

// print_imports(): prints a list of imports in a PE file
void print_imports(DOS_HEADER_T *dosHeader) {
    uint32_t tableEntries;
    char *importName;

    tableEntries = (dosHeader->dataDirectory[1].Size / 20)-1;
    printf("\nImport Directory\n");

    for (uint32_t idx=0; idx<tableEntries; idx++) {
        printf("    Import Lookup Table: %x\n", dosHeader->importDir[idx].ImportLookupTableRVA);
        printf("    TimeDateStamp: %x\n", dosHeader->importDir[idx].TimeStamp);
        printf("    Forwarder Chain:         %x\n", dosHeader->importDir[idx].ForwarderChain);
        printf("    Name RVA:                %x\n", dosHeader->importDir[idx].NameRVA);
        printf("    Import Address table RVA: %x\n\n", dosHeader->importDir[idx].ImportAddressRVA);
    }
}