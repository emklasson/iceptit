// Copyright (c) 2000-2020 Mikael Klasson
// License: MIT

#include <cstdio>
#include <iostream>
#include "pe_header.h"
using namespace std;

unsigned int read_data(FILE* file, int bytes) {
    unsigned int data = 0;
    if (bytes < 0 || bytes > sizeof(data)) {
        cout << "ERROR: invalid bytes argument to read_data: " << bytes << endl;
        return 0;
    }

    fread(&data, bytes, 1, file);
    return data;
}

unsigned int get_pe_offset(FILE* file) {
    fseek(file, 0x3c, SEEK_SET);
    auto pe_offset = read_data(file, 4);
    fseek(file, pe_offset, SEEK_SET);
    auto data = read_data(file, 4);
    if (data != 0x004550) {
        cout << "ERROR: no PE header found." << endl;
        return 0;
    }

    return pe_offset;
}

unsigned int rva_to_offset(FILE* file, unsigned int rva) {
    auto pe_offset = get_pe_offset(file);
    if (!pe_offset) {
        return 0;
    }

    fseek(file, pe_offset + 0x06, SEEK_SET);
    auto objects = read_data(file, 2);

    fseek(file, pe_offset + 0x14, SEEK_SET);
    auto offset = read_data(file, 2) + pe_offset + 0x18;

    // Search sections.
    for (unsigned int j = 0; j < objects; j++) {
        fseek(file, offset + 8, SEEK_SET);
        auto object_size = read_data(file, 4);
        auto object_rva = read_data(file, 4);
        if (object_rva <= rva && object_rva + object_size > rva) {
            fseek(file, 4, SEEK_CUR);
            auto object_offset = read_data(file, 4);
            return rva + object_offset - object_rva;
        }

        offset += 0x28;
    }

    return 0;
}
