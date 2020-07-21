# iceptit

This Visual Studio 2019 solution contains four projects:

1. **iceptit** can be used to intercept other Windows executables' calls to functions in arbitrary dll files and make them run your own code from iceptit.dll instead.

2. **get_dll_functions** retrieves a list of the functions a given dll file exports and creates iceptit.def and functions.h suitable for use with **iceptit**.

3. **patch_import** patches a PE executable's Import section and changes all references to a particular dll to refer to another dll, e.g. iceptit.dll.

4. **test_iceptit** is a small test program that calls GetVersionEx and displays the result. It's automatically patched to use iceptit.dll instead of kernel32.dll in a PostBuild event using **patch_import**.

To make a program use iceptit.dll you'll have to replace the name of the normal dll with "iceptit.dll" inside the to-be-fooled executable's Import section. If you don't feel like doing that manually, use **patch_import**.

If you need to intercept calls to several different dlls then just build multiple renamed iceptit dlls and patch the executable once for each &lt;iceptit, target&gt; dll pair.

The included example iceptit.cpp intercepts kernel32.dll's GetVersionExA and returns Windows v4.0. Running parse_kernel32.bat will regenerate iceptit.def and functions.h from your system's kernel32.dll using **get_dll_functions**.

You should be able to just build the solution and run test_iceptit.exe to try it out.

Have fun!

## License

Copyright &copy; 2000-2020 Mikael Klasson  
License: [MIT](LICENSE)
