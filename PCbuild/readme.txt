Building Python using VC++ 5.0 or 6.0
-------------------------------------

This directory is used to build Python for Win32 platforms,
e.g. Windows 95, 98 and NT.  It requires Microsoft Visual C++ 5.x.
(For other Windows platforms and compilers, see ../PC/readme.txt.)

Unlike previous versions, there's no longer a need to copy the project
files from the PC/vc5x subdirectory to the PCbuild directory -- they
come in PCbuild.

All you need to do is open the workspace "pcbuild.dsw" in MSVC++,
select the Debug or Release setting (using Set Active
Configuration... in the Build menu), and build the projects.

The proper order to build is

1) python16 (this builds python16.dll and python16.lib)
2) python   (this builds python.exe)
3) the other subprojects

Some subprojects require that you have distributions of other
software: Tcl/Tk, bsddb and zlib.  If you don't have these, you can't
build the corresponding extensions.  If you do have them, you may have
to change the project settings to point to the right include files,
libraries etc.

When using the Debug setting, the output files have a _d added to
their name: python16_d.dll, python_d.exe, parser_d.pyd, and so on.

If you want to create your own extension module DLL, there's an
example with easy-to-follow instructions in ../PC/example/; read the
file readme.txt there first.

Pointers:
Python	http://www.python.org
Tcl/Tk	http://dev.scriptics.com
zlib	http://www.winimage.com/zLibDll
bsddb	Sam Rushing's web/ftp site
