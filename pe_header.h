// pe_header.h
//    Definitions and declarations for PE module
//
#ifndef PE_HEADER_H
#define PE_HEADER_H

// Disable warning for fopen() under visual studio
#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

#include "headers.h"

// Import Table
typedef struct IMPORT_DIRECTORY_T{
  uint32_t ImportLookupTableRVA;// RVA of the import lookup table 
  uint32_t TimeStamp;       
  uint32_t ForwarderChain; 
  uint32_t NameRVA;             // address of an ASCII string name of the DLL
  uint32_t ImportAddressRVA;
}IMPORT_DIRECTORY_T;

// export address table
typedef struct export_address_name_t{
  char   names[1024];
}export_address_name_t;

// export table
typedef struct EXPORT_DIRECTORY_T{
  uint32_t    ExportFlags;      // Reserved, must be 0. 
  uint32_t    TimeStamp;        // The time and date that the export 
                                // data was created. 

  uint16_t    MajorVersion;
  uint16_t    MinorVersion;
  uint32_t    NameRVA;          // The address of the ASCII string that contains
                                // the name of the DLL.

  uint32_t    OrdinalBase;          // The starting ordinal number for exports in 
                                // this image. This field specifies the 
                                // starting ordinal number for the export 
                                // address table. 

  uint32_t    AddrTableEntries;     // The number of entries in the 
                                    // export address table. 
  uint32_t    NumberOfNamePointers;
  uint32_t    ExportAddrTableRVA; // The address of the export address table,
  uint32_t    NamePtrRVA;
  uint32_t    OrdinalTableRVA;
  export_address_name_t *exportAddr_name_t;
}EXPORT_DIRECTORY_T;


// section table
typedef struct SECTION_TABLE_T{
  char       *name;
  uint32_t    VirtualSize;
  uint32_t    VirtualAddress;
  uint32_t    SizeOfRawData;
  uint32_t    PointerToRawData;
  uint32_t    PointerToRelocations;
  uint32_t    PointerToLinenumbers;
  uint32_t    NumberOfRelocations;
  uint32_t    NumberOfLinenumbers;
  uint32_t    Characteristics;
}SECTION_TABLE_T;

// Data Directory 
typedef struct DATA_DIRECTORY_T{
  uint64_t    offset;
  uint32_t    VirtualAddress; 
  uint32_t    Size;
}DATA_DIRECTORY_T;

// Optional Header Image
typedef struct OPTIONAL_HEADER_T{
  uint16_t    Magic;  
  uint8_t     MajorLinkerVersion;
  uint8_t     MinorLinkerVersion;
  uint32_t    SizeOfCode;
  uint32_t    SizeOfInitializedData;
  uint32_t    SizeOfUninitializedData;
  uint32_t    AddressOfEntryPoint;
  uint32_t    BaseOfCode;
  uint32_t    BaseOfData;
  uint64_t    ImageBase;
  uint32_t    SectionAlignment;
  uint32_t    FileAlignment;
  uint16_t    MajorOperatingSystemVersion;
  uint16_t    MinorOperatingSystemVersion;
  uint16_t 	  MajorImageVersion; 	
  uint16_t 	  MinorImageVersion;	
  uint16_t 	  MajorSubsystemVersion; 
  uint16_t 	  MinorSubsystemVersion; 
  uint32_t 	  Win32VersionValue; 	
  uint32_t 	  SizeOfImage; 		
  uint32_t 	  SizeOfHeaders; 		
  uint32_t 	  CheckSum; 			
  uint16_t 	  Subsystem; 			
  uint16_t 	  DllCharacteristics; 	
  uint64_t 	  SizeOfStackReserve; 	
  uint64_t 	  SizeOfStackCommit; 	
  uint64_t 	  SizeOfHeapReserve; 	
  uint64_t 	  SizeOfHeapCommit; 	
  uint32_t 	  LoaderFlags; 		
  uint32_t 	  NumberOfRvaAndSizes;
} OPTIONAL_HEADER_T;

// Base Relocation Table
typedef struct BASE_RELOCATION_BLOCK_T {
    uint32_t PageRVA;
    uint32_t BlockSize;
    uint16_t *relocations;
} BASE_RELOCATION_BLOCK_T;


// PE header
typedef struct PE_HEADER_T{
  uint32_t          peOffset; 
  uint32_t          Signature;   
  uint16_t          Machine; 
  uint16_t          NumberOfSections;
  uint32_t          TimeStamp;
  uint32_t          PtrToSymbolTable;
  uint32_t          NumberOfSymbols;
  uint16_t          SizeOfOptionalHeader;
  uint16_t          Characteristics;
  OPTIONAL_HEADER_T OptionalHeader;
} PE_HEADER_T;

// DOS header
typedef struct DOS_HEADER_T{
  uint16_t  e_magic;      // Magic DOS signature MZ 
  uint16_t  e_cblp;		  // Bytes on last page of file
  uint16_t  e_cp;		    // Pages in file
  uint16_t  e_crlc;		  // Relocations
  uint16_t	e_cparhdr;	// Size of header in paragraphs
  uint16_t	e_minalloc;	// Minimum extra paragraphs needed
  uint16_t	e_maxalloc;	// Maximum extra paragraphs needed
  uint16_t	e_ss;		    // nitial (relative) SS value
  uint16_t	e_sp;		    // Initial SP value
  uint16_t	e_csum;		  // Checksum
  uint16_t	e_ip;		    // Initial IP value
  uint16_t	e_cs;		    // Initial (relative) CS value
  uint16_t	e_lfarlc;	  // File address of relocation table
  uint16_t	e_ovno;		  // Overloay number
  uint64_t	e_res;	    // Reserved uint16_ts (4 uint16_ts)
  uint16_t	e_oemid;		// OEM identifier (for e_oeminfo)
  uint16_t	e_oeminfo;	// OEM information; e_oemid specific
  uint64_t	e_res2;	    // Reserved uint16_ts (10 uint16_ts)
  uint32_t  e_lfanew;   // Offset to start of PE header 
  PE_HEADER_T         pe;
  SECTION_TABLE_T    *section_table;
  DATA_DIRECTORY_T   *dataDirectory;
  EXPORT_DIRECTORY_T  exportDir;
  IMPORT_DIRECTORY_T  *importDir;
  BASE_RELOCATION_BLOCK_T *baseRelocTable;
  // to be implemented later:
  //    resources directory
  //    base relocation table
  //    debug table
  //    tls table
  //    load config table
  //    delay import descriptor
}DOS_HEADER_T;

// misc functions to help with the general parsing operations
uint64_t  rva_to_offset(int numberOfSections, uint64_t rva, 
                           SECTION_TABLE_T *sections);

// functions to output PE info
void      print_pe_characteristics(uint16_t ch);
void      print_machine(uint16_t mach);
void      print_magic(uint16_t magic);
void      print_subsystem(uint16_t system);
void      print_dllcharacteristics(uint16_t ch);
void      print_section_characteristics(uint32_t ch);
void      print_exports(DOS_HEADER_T *dosHeader);
void      print_imports(DOS_HEADER_T *dosHeader);
void      print_relocs(DOS_HEADER_T *dosHeader);

// functions to parse section from PE file
void      read_dos(FILE *in, DOS_HEADER_T *dosHeader);
void      read_pe(FILE *in, DOS_HEADER_T *dosHeader);
void      read_dataDir(FILE *in, DOS_HEADER_T *dosHeader);
void      read_sections(FILE *in, DOS_HEADER_T *dosHeader);
void      read_dataOffset(DOS_HEADER_T *dosHeader);
void      read_exportDir(FILE *in, DOS_HEADER_T *dosHeader);
void      read_exportNames(FILE *in, DOS_HEADER_T *dosHeader);
void      read_importDir(FILE *in, DOS_HEADER_T *dosHeader);
void      read_relocDir(FILE *in, DOS_HEADER_T *dosHeader);

void read_relocDir(FILE *in, DOS_HEADER_T *dosHeader);
void print_relocs(DOS_HEADER_T *dosHeader);
// cleanup function
void      cleanup(DOS_HEADER_T *dosHeader);


// Machine types
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
#define IMAGE_FILE_MACHINE_UNKNOWN  0x0     // assumed to be applicable to any machine type
#define IMAGE_FILE_MACHINE_IA64   	0x200   // Intel Itanium processor family
#define IMAGE_FILE_MACHINE_I386   	0x14c   // Intel 386 or later processors and compatible processors
#define IMAGE_FILE_MACHINE_AMD64   	0x8664  // x64
#define IMAGE_FILE_MACHINE_ARM   		0x1c0   // ARM little endian
#define IMAGE_FILE_MACHINE_ARM64   	0xaa64  // ARM64 little endian
#define IMAGE_FILE_MACHINE_ARMNT   	0x1c4   // ARM Thumb-2 little endian
#define IMAGE_FILE_MACHINE_EBC   		0xebc   // EFI byte code

// PE optional image
#define OPTIONAL_IMAGE_PE32      0x10b
#define OPTIONAL_IMAGE_PE32_plus 0x20b

// Image subsystem
#define IMAGE_SUBSYSTEM_UNKNOWN   		  	0   		//  An unknown subsystem
#define IMAGE_SUBSYSTEM_NATIVE    		  	1   		//  Device drivers and native Windows processes
#define IMAGE_SUBSYSTEM_WINDOWS_GUI     	2  		 	//  The Windows graphical user interface (GUI) subsystem
#define IMAGE_SUBSYSTEM_WINDOWS_CUI     	3  		 	//  The Windows character subsystem
#define IMAGE_SUBSYSTEM_OS2_CUI     	  	5    		//  The OS/2 character subsystem
#define IMAGE_SUBSYSTEM_POSIX_CUI     		7    		//	The Posix character subsystem
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS    8  	    //  Native Win9x driver
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI   	9   		//  Windows CE
#define IMAGE_SUBSYSTEM_EFI_APPLICATION   10   		//  An Extensible Firmware Interface (EFI) application
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER    11   //  An EFI driver with boot services
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER     	   12   // 	An EFI driver with run-time services
#define IMAGE_SUBSYSTEM_EFI_ROM     		13      	    	//	An EFI ROM image
#define IMAGE_SUBSYSTEM_XBOX     			  14              //  XBOX
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    16  //  Windows boot application. 

#endif