// Copyright (c) 2000-2020 Mikael Klasson
// License: MIT
//
// Patches the Import section of an executable (containing a PE header) and
// changes all references to a specific dll to refer to a dll of your choosing
// instead, e.g. iceptit.dll.

#include <iostream>
#include <string>
#include "../get_dll_functions/pe_header.h"
using namespace std;

string tolower(string s) {
    for (auto& c : s) {
        c = static_cast<char>(tolower(c));
    }
    return s;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        cout << "Usage: patch_import <exe_name> <dll_name> <iceptit_dll_name>" << endl
            << "Example: patch_import test.exe kernel32.dll iceptit.dll" << endl;
        return 1;
    }

    FILE* exe_file;
    string exe_name = argv[1];
    string dll_name = argv[2];
    string iceptit_dll_name = argv[3];

    if (fopen_s(&exe_file, exe_name.c_str(), "rb+")) {
        cout << "ERROR: couldn't open " << exe_name << endl;
        return 1;
    }

    cout << "Parsing " << exe_name << endl;
    auto pe_offset = get_pe_offset(exe_file);
    if (!pe_offset) {
        return 1;
    }

    fseek(exe_file, pe_offset + 0x80, SEEK_SET);
    auto import_rva = read_data(exe_file, 4);

    auto import_offset = rva_to_offset(exe_file, import_rva);
    if (!import_offset) {
        cout << "ERROR: couldn't locate import table." << endl;
        return 1;
    }

    bool found = false;
    bool problem = false;
    for (int j = 0; ; ++j) {
        fseek(exe_file, import_offset + 20 * j + 12, SEEK_SET);
        auto name_rva = read_data(exe_file, 4);
        if (!name_rva) {
            break;
        }

        auto name_offset = rva_to_offset(exe_file, name_rva);
        fseek(exe_file, name_offset, SEEK_SET);

        string name;
        while (int c = fgetc(exe_file)) {
            name.push_back(static_cast<char>(c));
        }

        cout << "Imports " << name << ".";
        if (tolower(name) == tolower(dll_name)) {
            found = true;
            cout << " Patching." << endl;

            // Include zero-padding in name.
            do {
                name.push_back(0);
            } while (!fgetc(exe_file));

            if (name.size() <= iceptit_dll_name.size()) {
                problem = true;
                cout << "  ERROR: I wanted to patch this, but \"" << iceptit_dll_name << "\" won't fit." << endl
                    << "  Rename " << iceptit_dll_name << " to something no more than " << name.size() - 1 << " characters long." << endl
                    << "  Just \"i\" is always a last resort." << endl;
            } else {
                fseek(exe_file, name_offset, SEEK_SET);
                snprintf(&name[0], name.size(), "%s", iceptit_dll_name.c_str());
                fwrite(&name[0], name.size(), 1, exe_file);
                cout << "  Ok, now imports " << iceptit_dll_name << " instead." << endl;
            }
        } else {
            cout << " Ignoring." << endl;
        }
    }

    if (!found) {
        cout << "Sorry, I couldn't find any reference to " << dll_name << "." << endl;
    } else if (problem) {
        cout << "There were errors while patching. Review the output above." << endl;
    } else {
        cout << "Everything went fine. Enjoy!" << endl;
    }

    fclose(exe_file);
}
