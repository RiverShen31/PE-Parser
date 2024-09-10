#include "headers.h"

// header section types
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers

char section_flags_str[][34] = { "IMAGE_SCN_TYPE_NO_PAD",
"IMAGE_SCN_CNT_CODE", "IMAGE_SCN_CNT_INITIALIZED_DATA",
"IMAGE_SCN_CNT_UNINITIALIZED_ DATA", "IMAGE_SCN_LNK_OTHER",
"IMAGE_SCN_LNK_INFO", "IMAGE_SCN_LNK_REMOVE",
"IMAGE_SCN_LNK_COMDAT", "IMAGE_SCN_GPREL",
"IMAGE_SCN_MEM_PURGEABLE", "IMAGE_SCN_MEM_16BIT",
"IMAGE_SCN_MEM_LOCKED", "IMAGE_SCN_MEM_PRELOAD",
"IMAGE_SCN_ALIGN_1BYTES", "IMAGE_SCN_ALIGN_2BYTES",
"IMAGE_SCN_ALIGN_4BYTES", "IMAGE_SCN_ALIGN_8BYTES",
"IMAGE_SCN_ALIGN_16BYTES", "IMAGE_SCN_ALIGN_32BYTES",
"IMAGE_SCN_ALIGN_64BYTES", "IMAGE_SCN_ALIGN_128BYTES",
"IMAGE_SCN_ALIGN_256BYTES", "IMAGE_SCN_ALIGN_512BYTES",
"IMAGE_SCN_ALIGN_1024BYTES", "IMAGE_SCN_ALIGN_2048BYTES",
"IMAGE_SCN_ALIGN_4096BYTES", "IMAGE_SCN_ALIGN_8192BYTES",
"IMAGE_SCN_LNK_NRELOC_OVFL", "IMAGE_SCN_MEM_DISCARDABLE",
"IMAGE_SCN_MEM_NOT_CACHED", "IMAGE_SCN_MEM_NOT_PAGED",
"IMAGE_SCN_MEM_SHARED", "IMAGE_SCN_MEM_EXECUTE",
"IMAGE_SCN_MEM_READ", "IMAGE_SCN_MEM_WRITE"};

uint32_t section_flags_arr[] = {0x00000008,
0x00000020, 0x00000040, 0x00000080, 0x00000100,
0x00000200, 0x00000800, 0x00001000, 0x00008000,
0x00020000, 0x00020000, 0x00040000, 0x00080000,
0x00100000, 0x00200000, 0x00300000, 0x00400000,
0x00500000, 0x00600000, 0x00700000, 0x00800000,
0x00900000, 0x00A00000, 0x00B00000, 0x00C00000,
0x00D00000, 0x00E00000, 0x01000000, 0x02000000,
0x04000000, 0x08000000, 0x10000000, 0x20000000,
0x40000000, 0x80000000};

// Image PE File type
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
char image_file_str[][35] = {"IMAGE_FILE_RELOCS_STRIPPED", "IMAGE_FILE_EXECUTABLE_IMAGE", 
                      "IMAGE_FILE_LINE_NUMS_STRIPPED", "IMAGE_FILE_LOCAL_SYMS_STRIPPED", 
                      "IMAGE_FILE_AGGRESSIVE_WS_TRIM", "IMAGE_FILE_LARGE_ADDRESS_AWARE", 
                      "IMAGE_FILE_BYTES_REVERSED_LO", "IMAGE_FILE_32BIT_MACHINE", 
                      "IMAGE_FILE_DEBUG_STRIPPED","IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 
                      "IMAGE_FILE_NET_RUN_FROM_SWAP", "IMAGE_FILE_SYSTEM", "IMAGE_FILE_DLL", 
                      "IMAGE_FILE_UP_SYSTEM_ONLY", "IMAGE_FILE_BYTES_REVERSED_HI"};

uint16_t image_file_arr[] = {0x0001, 0x0002, 0x0004,
                    0x0008, 0x0010, 0x0020, 0x0080, 0x0100,
                    0x0200, 0x0400, 0x0800, 0x1000, 0x2000,
                    0x4000, 0x8000};

// DLL Characteristics
char image_dll_str[][47] = {"IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
                      "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                      "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
                      "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",		
                      "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
                      "IMAGE_DLLCHARACTERISTICS_NO_SEH",  		
                      "IMAGE_DLLCHARACTERISTICS_NO_BIND",
                      "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
                      "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
                      "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
                      "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"};

uint16_t image_dll_arr[] = {0x0020, 0x0040, 0x0080, 0x0100,
0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000};

uint64_t rva_to_offset(int numberOfSections, uint64_t rva, SECTION_TABLE_T *section_table) {
    if (rva == 0) return 0;
    uint64_t sumAddr;

    for (int idx=0; idx<numberOfSections; idx++) {
        sumAddr = section_table[idx].VirtualAddress + section_table[idx].SizeOfRawData;
        if (rva >= section_table[idx].VirtualAddress && rva < sumAddr) {
            return section_table[idx].PointerToRawData + (rva - section_table[idx].VirtualAddress);
        }
    }
    return -1;
}

// read_dos(): reads DOS Header values from a file
void read_dos(FILE *in, DOS_HEADER_T *dosHeader) {
    // READING DOS HEADER
    dosHeader->e_magic = read16_little_endian(in);
    dosHeader->e_cblp = read16_little_endian(in);
    dosHeader->e_cp       = read16_little_endian(in);
    dosHeader->e_crlc     = read16_little_endian(in);
    dosHeader->e_cparhdr  = read16_little_endian(in);
    dosHeader->e_minalloc = read16_little_endian(in);
    dosHeader->e_maxalloc = read16_little_endian(in);
    dosHeader->e_ss       = read16_little_endian(in);
    dosHeader->e_sp       = read16_little_endian(in);
    dosHeader->e_csum     = read16_little_endian(in);
    dosHeader->e_ip       = read16_little_endian(in);
    dosHeader->e_cs       = read16_little_endian(in);
    dosHeader->e_lfarlc   = read16_little_endian(in);
    dosHeader->e_ovno     = read16_little_endian(in);

    // some of the next fields are reserved/aren't used
    dosHeader->e_res      = read64_little_endian(in);
    dosHeader->e_oemid    = read16_little_endian(in);
    dosHeader->e_oeminfo  = read16_little_endian(in);
    dosHeader->e_res2     = read64_little_endian(in); // this is repeated on purpose since
    dosHeader->e_res2     = read64_little_endian(in); // most PE files have this field as zero
    dosHeader->e_res2     = read32_little_endian(in); // i'll fix it later.
    /////////////////////////////////////////////
    dosHeader->e_lfanew   = read32_little_endian(in);
}

// read_pe(): reads in PE header information
void read_pe(FILE *in, DOS_HEADER_T *dosHeader) {
    if (fseek(in, dosHeader->e_lfanew, SEEK_SET) != 0) {
        printf("Error during file reading.\n");
        exit(-1);
    }

    dosHeader->pe.Signature = read32_little_endian(in);
    dosHeader->pe.Machine            = read16_little_endian(in);
    dosHeader->pe.NumberOfSections   = read16_little_endian(in);
    dosHeader->pe.TimeStamp          = read32_little_endian(in);
    dosHeader->pe.PtrToSymbolTable        = read32_little_endian(in);
    dosHeader->pe.NumberOfSymbols        = read32_little_endian(in);
    dosHeader->pe.SizeOfOptionalHeader = read16_little_endian(in);
    dosHeader->pe.Characteristics    = read16_little_endian(in);

    // optional header (Standard Fields)
    dosHeader->pe.OptionalHeader.Magic          = read16_little_endian(in);
    dosHeader->pe.OptionalHeader.MajorLinkerVersion = read8_little_endian(in);
    dosHeader->pe.OptionalHeader.MinorLinkerVersion = read8_little_endian(in);
    dosHeader->pe.OptionalHeader.SizeOfCode     = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.SizeOfInitializedData    = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.SizeOfUninitializedData  = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.AddressOfEntryPoint = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.BaseOfCode = read32_little_endian(in);

    if (dosHeader->pe.OptionalHeader.Magic == OPTIONAL_IMAGE_PE32_plus) {
        dosHeader->pe.OptionalHeader.ImageBase = read64_little_endian(in);
    } else {
        dosHeader->pe.OptionalHeader.BaseOfData       = read32_little_endian(in);
        dosHeader->pe.OptionalHeader.ImageBase        = read32_little_endian(in);
    }
    
    dosHeader->pe.OptionalHeader.SectionAlignment  = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.FileAlignment     = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.MajorOperatingSystemVersion        = read16_little_endian(in);
    dosHeader->pe.OptionalHeader.MinorOperatingSystemVersion        = read16_little_endian(in);
    dosHeader->pe.OptionalHeader.MajorImageVersion     = read16_little_endian(in);
    dosHeader->pe.OptionalHeader.MinorImageVersion     = read16_little_endian(in);
    dosHeader->pe.OptionalHeader.MajorSubsystemVersion = read16_little_endian(in);
    dosHeader->pe.OptionalHeader.MinorSubsystemVersion = read16_little_endian(in);
    dosHeader->pe.OptionalHeader.Win32VersionValue   = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.SizeOfImage       = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.SizeOfHeaders     = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.CheckSum          = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.Subsystem         = read16_little_endian(in);
    dosHeader->pe.OptionalHeader.DllCharacteristics= read16_little_endian(in);
    
    if( dosHeader->pe.OptionalHeader.Magic == OPTIONAL_IMAGE_PE32_plus )
    {
        dosHeader->pe.OptionalHeader.SizeOfStackReserve= read64_little_endian(in);
        dosHeader->pe.OptionalHeader.SizeOfStackCommit = read64_little_endian(in);
        dosHeader->pe.OptionalHeader.SizeOfHeapReserve = read64_little_endian(in);
        dosHeader->pe.OptionalHeader.SizeOfHeapCommit  = read64_little_endian(in);      
    } else {
        dosHeader->pe.OptionalHeader.SizeOfStackReserve= read32_little_endian(in);
        dosHeader->pe.OptionalHeader.SizeOfStackCommit = read32_little_endian(in);
        dosHeader->pe.OptionalHeader.SizeOfHeapReserve = read32_little_endian(in);
        dosHeader->pe.OptionalHeader.SizeOfHeapCommit  = read32_little_endian(in);
    }
    dosHeader->pe.OptionalHeader.LoaderFlags         = read32_little_endian(in);
    dosHeader->pe.OptionalHeader.NumberOfRvaAndSizes = read32_little_endian(in);
}

// read_dataDir(): reads in Data Directories information
void read_dataDir(FILE *in, DOS_HEADER_T *dosHeader) {
    int dirs = dosHeader->pe.OptionalHeader.NumberOfRvaAndSizes;

    // Reading Data Directories
    dosHeader->dataDirectory = (DATA_DIRECTORY_T*)malloc(dirs * sizeof(DATA_DIRECTORY_T));

    for (int idx=0; idx<dirs; idx++) {
        dosHeader->dataDirectory[idx].VirtualAddress = read32_little_endian(in);
        dosHeader->dataDirectory[idx].Size = read32_little_endian(in);
    }
}

void read_dataOffset(DOS_HEADER_T *dosHeader) {
    int dirs = dosHeader->pe.OptionalHeader.NumberOfRvaAndSizes;
    
    for(int idx = 0; idx < dirs ; idx++)
    {
        dosHeader->dataDirectory[idx].offset = rva_to_offset(dosHeader->pe.NumberOfSections,
                                    dosHeader->dataDirectory[idx].VirtualAddress,
                                    dosHeader->section_table);
    }

}

// read_sections(): reads in sections information
void read_sections(FILE *in, DOS_HEADER_T *dosHeader) {
    int sections = dosHeader->pe.NumberOfSections;
    // Reading Sections data
    dosHeader->section_table = (SECTION_TABLE_T*)malloc(sections * sizeof(SECTION_TABLE_T));

    for(int idx = 0; idx < sections; idx++)
    {
        dosHeader->section_table[idx].name            = read_str(in, 8);
        dosHeader->section_table[idx].VirtualSize     = read32_little_endian(in);
        dosHeader->section_table[idx].VirtualAddress     = read32_little_endian(in);
        dosHeader->section_table[idx].SizeOfRawData   = read32_little_endian(in);
        dosHeader->section_table[idx].PointerToRawData    = read32_little_endian(in);
        dosHeader->section_table[idx].PointerToRelocations      = read32_little_endian(in);
        dosHeader->section_table[idx].PointerToLinenumbers    = read32_little_endian(in);
        dosHeader->section_table[idx].NumberOfRelocations   = read16_little_endian(in);
        dosHeader->section_table[idx].NumberOfLinenumbers = read16_little_endian(in);
        dosHeader->section_table[idx].Characteristics = read32_little_endian(in);
    }
}

// read_exportDir(): reads in Export directory information
void read_exportDir(FILE *in, DOS_HEADER_T *dosHeader) {
    uint32_t offset;

    offset = dosHeader->dataDirectory[0].offset;

    if (offset < 0) return;

    if (fseek(in, offset, SEEK_SET) == -1) {
        printf("fseek failed in read export.\n");
        return;
    }

    dosHeader->exportDir.ExportFlags  = read32_little_endian(in);
    dosHeader->exportDir.TimeStamp    = read32_little_endian(in);
    dosHeader->exportDir.MajorVersion     = read16_little_endian(in);
    dosHeader->exportDir.MinorVersion     = read16_little_endian(in);
    dosHeader->exportDir.NameRVA      = read32_little_endian(in);
    dosHeader->exportDir.OrdinalBase          = read32_little_endian(in);
    dosHeader->exportDir.AddrTableEntries     = read32_little_endian(in);
    dosHeader->exportDir.NumberOfNamePointers = read32_little_endian(in);
    dosHeader->exportDir.ExportAddrTableRVA   = read32_little_endian(in);
    dosHeader->exportDir.NamePtrRVA           = read32_little_endian(in);
    dosHeader->exportDir.OrdinalTableRVA      = read32_little_endian(in);
    
    read_exportNames(in, dosHeader);
}

// read_exportNames(): reads the ascii names of exported functions
void read_exportNames(FILE *in, DOS_HEADER_T *dosHeader) {
    uint32_t tableOffset;
    uint32_t nameOffset;
    uint32_t nameRVA;
    uint32_t tableSize;
    char buffer[100];

    tableSize = dosHeader->exportDir.NumberOfNamePointers;
    tableOffset = rva_to_offset(dosHeader->pe.NumberOfSections,
                                dosHeader->exportDir.NamePtrRVA,
                                dosHeader->section_table);
    
    dosHeader->exportDir.exportAddr_name_t = (export_address_name_t*)malloc(tableSize * sizeof(export_address_name_t));

    // reading Export table entries (per DLL)
    for (uint32_t idx = 0; idx < tableSize; idx++) {
        fseek(in, tableOffset, 0);
        nameRVA = read32_little_endian(in);
        nameOffset = rva_to_offset(dosHeader->pe.NumberOfSections, nameRVA, dosHeader->section_table);
        fseek(in, nameOffset, 0);
        fgets(buffer, 100, in);
        strcat(dosHeader->exportDir.exportAddr_name_t[idx].names, buffer);

        tableOffset += 4; // after reading 4 bytes, jump to next 4 bytes
    }
}

// read_importDir(): reads the imports table entries
void read_importDir(FILE *in, DOS_HEADER_T *dosHeader) {
    uint32_t tableEntries;

    // each import entry has 5 fields, 4 bytes per field (20 bytes per entry)
    // minus 1 because the final table will be empty signaling the end of the entries
    tableEntries = (dosHeader->dataDirectory[1].Size / 20) - 1;
    fseek(in, dosHeader->dataDirectory[1].offset, 0);

    dosHeader->importDir = (IMPORT_DIRECTORY_T*)malloc(tableEntries * sizeof(IMPORT_DIRECTORY_T));

    for (uint32_t idx = 0; idx < tableEntries; idx++) {
        dosHeader->importDir[idx].ImportLookupTableRVA = read32_little_endian(in);
        dosHeader->importDir[idx].TimeStamp        = read32_little_endian(in);
        dosHeader->importDir[idx].ForwarderChain   = read32_little_endian(in);
        dosHeader->importDir[idx].NameRVA          = read32_little_endian(in);
        dosHeader->importDir[idx].ImportAddressRVA = read32_little_endian(in);
    }
}

void read_importNames(FILE *in, DOS_HEADER_T *dosHeader) {
    
}

// print_machine(): prints the machine type of a PE image
void print_machine(uint16_t mach) {
    switch (mach)
    {
    case IMAGE_FILE_MACHINE_UNKNOWN:
        printf("(%X)  IMAGE_FILE_MACHINE_UNKNOWN\n", IMAGE_FILE_MACHINE_UNKNOWN);
        break;

    case IMAGE_FILE_MACHINE_IA64:
        printf("(%X)  IMAGE_FILE_MACHINE_IA64\n", IMAGE_FILE_MACHINE_IA64);
        break;

    case IMAGE_FILE_MACHINE_I386:
        printf("(%X)  IMAGE_FILE_MACHINE_I386\n", IMAGE_FILE_MACHINE_I386);
        break;

    case IMAGE_FILE_MACHINE_AMD64:
        printf("(%X)  IMAGE_FILE_MACHINE_AMD64\n", IMAGE_FILE_MACHINE_AMD64);
        break;

    case IMAGE_FILE_MACHINE_ARM:
        printf("(%X)  IMAGE_FILE_MACHINE_ARM\n", IMAGE_FILE_MACHINE_ARM);
        break;

    case IMAGE_FILE_MACHINE_ARM64:
        printf("(%X)  IMAGE_FILE_MACHINE_ARM64\n", IMAGE_FILE_MACHINE_ARM64);
        break;

    case IMAGE_FILE_MACHINE_ARMNT:
        printf("(%X)  IMAGE_FILE_MACHINE_ARMNT\n", IMAGE_FILE_MACHINE_ARM64);
        break;

    case IMAGE_FILE_MACHINE_EBC:
        printf("(%X)  IMAGE_FILE_MACHINE_EBC\n", IMAGE_FILE_MACHINE_EBC);
        break;

    default:
        break;
    }
}

// print_pe_characteristics(): takes in a flags characteristics and prints them
void print_pe_characteristics(uint16_t ch) {
    for (int idx=0; idx<15; idx++) {
        if (ch & (image_file_arr[idx])) {
            printf("    %s\n", image_file_str[idx]);
        }
    }
}

// print_magic(): prints the type of a PE image
void print_magic(uint16_t magic) {
    switch(magic) {
        case OPTIONAL_IMAGE_PE32:
            printf("%X (PE) \n", OPTIONAL_IMAGE_PE32);
            break;

        case OPTIONAL_IMAGE_PE32_plus:
            printf("%X (PE+) \n", OPTIONAL_IMAGE_PE32_plus);
            break;

        default:
            printf("0 (Error) \n");
            break;
    }
}

// print_subsystem(): prints the subsystem of a PE
void print_subsystem(uint16_t subsystem) {
    switch (subsystem)
    {
    case IMAGE_SUBSYSTEM_UNKNOWN:
        printf("  (%X)   IMAGE_SUBSYSTEM_UNKNOWN\n", IMAGE_SUBSYSTEM_UNKNOWN);
        break;

    case IMAGE_SUBSYSTEM_NATIVE:
        printf("  (%X)   IMAGE_SUBSYSTEM_NATIVE\n", IMAGE_SUBSYSTEM_NATIVE);
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        printf("  (%X)   IMAGE_SUBSYSTEM_WINDOWS_GUI\n", IMAGE_SUBSYSTEM_WINDOWS_GUI);
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        printf("  (%X)   IMAGE_SUBSYSTEM_WINDOWS_CUI\n", IMAGE_SUBSYSTEM_WINDOWS_CUI);
        break;

    case IMAGE_SUBSYSTEM_OS2_CUI:
        printf("     IMAGE_SUBSYSTEM_OS2_CUI\n");
        break;

    case IMAGE_SUBSYSTEM_POSIX_CUI:
        printf("     IMAGE_SUBSYSTEM_POSIX_CUI\n");
        break;

    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
        printf("     IMAGE_SUBSYSTEM_NATIVE_WINDOWS\n");
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        printf("     IMAGE_SUBSYSTEM_WINDOWS_CE_GUI\n");
        break;

    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        printf("     IMAGE_SUBSYSTEM_EFI_APPLICATION\n");
        break;

    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        printf("     IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER\n");
        break;

    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        printf("     IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER\n");
        break;

    case IMAGE_SUBSYSTEM_EFI_ROM:
        printf("     IMAGE_SUBSYSTEM_EFI_ROM\n");
        break;

    case IMAGE_SUBSYSTEM_XBOX:
        printf("     IMAGE_SUBSYSTEM_XBOX\n");
        break;

    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
        printf("     IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION\n");
        break;

    default:
        break;
    }
}

// print_dllcharacteristics(): takes in a flags characteristics and prints them
void print_dllcharacteristics(uint16_t ch) {
    for (int idx=0; idx<11; idx++) {
        if (ch & (image_dll_arr[idx])) {
            printf("    %s\n", image_dll_str[idx]);
        }
    }
}

// print_section_characteristics(): prints the flags set on a section
void print_section_characteristics(uint32_t ch) {
    for (int idx=0; idx<35; idx++) {
        if (ch & (section_flags_arr[idx])) {
            printf("    %s\n", section_flags_str[idx]);
        }
    }
}

// cleanup(): a function to clean allocated memory inside structs
void cleanup(DOS_HEADER_T *dosHeader) {
    free(dosHeader->dataDirectory);
    for (int i=0; i<dosHeader->pe.NumberOfSections; i++) {
        free(dosHeader->section_table[i].name);
    }
    free(dosHeader->exportDir.exportAddr_name_t);
    free(dosHeader->section_table);
    free(dosHeader->importDir);
    free(dosHeader->baseRelocTable->relocations);
    free(dosHeader->baseRelocTable);
}

// read relocation directory
void read_relocDir(FILE *in, DOS_HEADER_T *dosHeader) {
    if (dosHeader->dataDirectory[5].Size == 0) {
        dosHeader->baseRelocTable = NULL;
        return;
    }

    uint32_t offset = dosHeader->dataDirectory[5].offset; // Base Relocation Table is at index 5
    if (offset < 0) return;

    if (fseek(in, offset, SEEK_SET) == -1) {
        printf("fseek failed in read_relocDir.\n");
        return;
    }

    dosHeader->baseRelocTable = (BASE_RELOCATION_BLOCK_T *)malloc(sizeof(BASE_RELOCATION_BLOCK_T));
    dosHeader->baseRelocTable->PageRVA = read32_little_endian(in);
    dosHeader->baseRelocTable->BlockSize = read32_little_endian(in);

    int numEntries = (dosHeader->baseRelocTable->BlockSize - 8) / 2; // 8 bytes for pageRVA and blockSize
    dosHeader->baseRelocTable->relocations = (uint16_t *)malloc(numEntries * sizeof(uint16_t));

    for (int i = 0; i < numEntries; i++) {
        dosHeader->baseRelocTable->relocations[i] = read16_little_endian(in);
    }
}

// print relocation table
void print_relocs(DOS_HEADER_T *dosHeader) {
    if (dosHeader->baseRelocTable == NULL) {
        return; // Do not print anything if there is no Base Relocation Table
    }

    printf("\nBase Relocation Table\n");
    printf("    Page RVA: 0x%X\n", dosHeader->baseRelocTable->PageRVA);
    printf("    Block Size: 0x%X\n", dosHeader->baseRelocTable->BlockSize);

    int numEntries = (dosHeader->baseRelocTable->BlockSize - 8) / 2;
    for (int i = 0; i < numEntries; i++) {
        uint16_t entry = dosHeader->baseRelocTable->relocations[i];
        uint16_t type = entry >> 12;
        uint16_t offset = entry & 0xFFF;
        printf("    Type: 0x%X, Offset: 0x%X\n", type, offset);
    }
}
