// Copyright (c) 2000-2020 Mikael Klasson
// License: MIT

// Finds the function names that a dll exports and creates iceptit.def and
// functions.h for use with iceptit.
// I've implemented two ways of doing it:
//   The first is via direct parsing of the exports section of the dll file.
//   The other is via Microsoft's dumpbin utility.
// Direct dll parsing finds 60 or so functions in kernel32.dll that dumpbin
// doesn't (I guess they weren't in the lib file I used). Dumpbin on the
// other hand finds all *Vlm functions, but seeing as how they're not
// exported by name in kernel32.dll you'll have trouble intercepting them
// anyway. Use dumpbin if direct dll parsing fails.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include "pe_header.h"
using namespace std;

// Parses a list of function names and outputs iceptit.def and functions.h.
int parse_functions(vector<string> symbols) {
    const string def_name = "iceptit.def";
    const string header_name = "functions.h";

    ofstream def(def_name, ios_base::out);
    if (!def) {
        cout << "Couldn't open " << def_name << " for writing." << endl;
        return 1;
    }

    ofstream header(header_name, ios_base::out);
    if (!header) {
        cout << "Couldn't open " << header_name << " for writing." << endl;
        return 1;
    }

    sort(symbols.begin(), symbols.end());

    const string auto_generated_warning = "Warning: Auto-generated file. Your changes may be lost.";

    header << "// " << auto_generated_warning << endl << endl
        << "const int num_functions = " << symbols.size() << ";" << endl
        << "void* function_ptrs[num_functions];" << endl << endl;

    def << "; " << auto_generated_warning << endl << endl
        << "EXPORTS" << endl;

    header << "const char* function_names[] = {" << endl;
    for (auto name : symbols) {
        def << "    " << name << "=fix" << name << endl;
        header << "    \"" << name << "\"," << endl;
    }

    header << "};" << endl << endl;

    for (size_t j = 0; j < symbols.size(); ++j) {
        header << "#ifndef FIX_" << symbols[j] << endl
            << "    __declspec(naked) void __stdcall fix" << symbols[j]
            << "(void) { __asm jmp dword ptr function_ptrs[" << j << " * 4] }" << endl
            << "#endif" << endl;
    }

    cout << "Ok. Parsed " << symbols.size() << " symbols and wrote " << def_name
        << " and " << header_name << "." << endl;
    return 0;
}

// Parses a dll file looking for exported functions.
int use_dll_directly(string dll_name) {
    FILE* dll;
    char path[260];
    vector<string> symbols;

    if (fopen_s(&dll, dll_name.c_str(), "rb")) {
        if (!GetModuleHandle(dll_name.c_str())
            || !GetModuleFileName(GetModuleHandle(dll_name.c_str()), path, sizeof(path))) {
            cout << "ERROR: couldn't find " << dll_name << endl;
            return 1;
        }

        if (fopen_s(&dll, path, "rb")) {
            cout << "ERROR: couldn't open " << path << endl;
            return 1;
        }

        cout << "Parsing " << path << endl;
    } else {
        cout << "Parsing " << dll_name << endl;
    }

    auto pe_offset = get_pe_offset(dll);
    if (!pe_offset) {
        return 1;
    }

    fseek(dll, pe_offset + 15 * 8, SEEK_SET);
    auto export_rva = read_data(dll, 4);

    auto export_offset = rva_to_offset(dll, export_rva);
    if (!export_offset) {
        cout << "ERROR: couldn't locate export table." << endl;
        return 1;
    }

    fseek(dll, export_offset + 24, SEEK_SET);
    auto name_count = read_data(dll, 4);
    fseek(dll, 4, SEEK_CUR);
    auto name_ptr_table_rva = read_data(dll, 4);
    auto name_ptr_table_offset = rva_to_offset(dll, name_ptr_table_rva);
    if (!name_ptr_table_offset) {
        cout << "ERROR: couldn't locate export name ptr table." << endl;
        return 1;
    }

    for (unsigned int j = 0; j < name_count; j++) {
        fseek(dll, name_ptr_table_offset + j * 4, SEEK_SET);
        auto name_rva = read_data(dll, 4);
        auto name_offset = rva_to_offset(dll, name_rva);
        fseek(dll, name_offset, SEEK_SET);
        char name[256];
        fgets(name, sizeof(name), dll);
        symbols.push_back(name);
    }

    fclose(dll);

    if (!symbols.size()) {
        cout << "ERROR: couldn't parse any symbols in dll file." << endl;
        return 1;
    }

    return parse_functions(symbols);
}

// Parses a lib or dll file looking for exported functions using Microsoft's
// dumpbin utility.
int use_dumpbin(string lib_name) {
    char temp_name[L_tmpnam_s];
    if (tmpnam_s(temp_name, sizeof(temp_name))) {
        cout << "ERROR: couldn't create temp file for dumpbin." << endl;
        return 1;
    }

    if (system(string("dumpbin /EXPORTS " + lib_name + " > " + temp_name).c_str())) {
        cout << "ERROR: dumpbin call failed." << endl;
        return 1;
    }

    ifstream dumpbin_output(temp_name);
    vector<string> symbols;
    string line;
    size_t name_column = 0;

    // Find start of exports list and column where export names start.
    while (getline(dumpbin_output, line)) {
        name_column = line.find("name");
        if (name_column != line.npos && line.find("ordinal") != line.npos) {
            break;
        }
    }

    // Parse all export names.
    while (getline(dumpbin_output, line)) {
        if (line.find('[') != line.npos) {
            continue;
        }

        auto summary_column = line.find("Summary");
        if (summary_column != line.npos && summary_column != name_column) {
            break;
        }

        if (name_column < line.size()) {
            stringstream ss(line.substr(name_column));
            string name;
            ss >> name;
            if (name.length() > 0) {
                symbols.push_back(name);
            }
        }
    }

    if (!symbols.size()) {
        cout << "ERROR: couldn't parse any symbols in dumpbin output." << endl;
        return 1;
    }

    return parse_functions(symbols);
}

int main(int argc, char** argv) {
    if (argc < 2 || (!_stricmp(argv[1], "/dumpbin") && argc < 3)) {
        cout << "Usage: get_dll_functions [/dumpbin] <input_file>" << endl;
        return 1;
    }

    if (!_stricmp(argv[1], "/dumpbin")) {
        return use_dumpbin(argv[2]);
    } else {
        return use_dll_directly(argv[1]);
    }
}
