// Copyright (c) 2000-2020 Mikael Klasson
// License: MIT

#ifndef __pe_header_h_included
#define __pe_header_h_included

// Reads <bytes> bytes from file.
// Returns read data as an unsigned int.
// <bytes> must be <= sizeof(unsigned int).
// Changes the file's current location.
unsigned int read_data(FILE* file, int bytes);

// Returns the file offset of the PE header, or 0 on error.
// Changes the file's current location.
unsigned int get_pe_offset(FILE* file);

// Converts an RVA to a file offset.
// Returns the file offset, or 0 on error.
// Changes the file's current location.
unsigned int rva_to_offset(FILE* file, unsigned int rva);

#endif  // __pe_header_h_included
