"""Routine to "compile" a .py file to a .pyc (or .pyo) file.

This module has intimate knowledge of the format of .pyc files.
"""

import __builtin__
import imp
import marshal
import os
import sys
import traceback

MAGIC = imp.get_magic()

__all__ = ["compile", "main"]

# Define an internal helper according to the platform
if os.name == "mac":
    import macfs
    def set_creator_type(file):
        macfs.FSSpec(file).SetCreatorType('Pyth', 'PYC ')
else:
    def set_creator_type(file):
        pass

def wr_long(f, x):
    """Internal; write a 32-bit int to a file in little-endian order."""
    f.write(chr( x        & 0xff))
    f.write(chr((x >> 8)  & 0xff))
    f.write(chr((x >> 16) & 0xff))
    f.write(chr((x >> 24) & 0xff))

def compile(file, cfile=None, dfile=None):
    """Byte-compile one Python source file to Python bytecode.

    Arguments:

    file:  source filename
    cfile: target filename; defaults to source with 'c' or 'o' appended
           ('c' normally, 'o' in optimizing mode, giving .pyc or .pyo)
    dfile: purported filename; defaults to source (this is the filename
           that will show up in error messages)

    Note that it isn't necessary to byte-compile Python modules for
    execution efficiency -- Python itself byte-compiles a module when
    it is loaded, and if it can, writes out the bytecode to the
    corresponding .pyc (or .pyo) file.

    However, if a Python installation is shared between users, it is a
    good idea to byte-compile all modules upon installation, since
    other users may not be able to write in the source directories,
    and thus they won't be able to write the .pyc/.pyo file, and then
    they would be byte-compiling every module each time it is loaded.
    This can slow down program start-up considerably.

    See compileall.py for a script/module that uses this module to
    byte-compile all installed files (or all files in selected
    directories).

    """
    f = open(file, 'U')
    try:
        timestamp = long(os.fstat(f.fileno()).st_mtime)
    except AttributeError:
        timestamp = long(os.stat(file).st_mtime)
    codestring = f.read()
    f.close()
    if codestring and codestring[-1] != '\n':
        codestring = codestring + '\n'
    try:
        codeobject = __builtin__.compile(codestring, dfile or file, 'exec')
    except SyntaxError, detail:
        lines = traceback.format_exception_only(SyntaxError, detail)
        for line in lines:
            sys.stderr.write(line.replace('File "<string>"',
                                          'File "%s"' % (dfile or file)))
        return
    if cfile is None:
        cfile = file + (__debug__ and 'c' or 'o')
    fc = open(cfile, 'wb')
    fc.write('\0\0\0\0')
    wr_long(fc, timestamp)
    marshal.dump(codeobject, fc)
    fc.flush()
    fc.seek(0, 0)
    fc.write(MAGIC)
    fc.close()
    set_creator_type(cfile)

def main(args=None):
    """Compile several source files.

    The files named in 'args' (or on the command line, if 'args' is
    not specified) are compiled and the resulting bytecode is cached
    in the normal manner.  This function does not search a directory
    structure to locate source files; it only compiles files named
    explicitly.

    """
    if args is None:
        args = sys.argv[1:]
    for filename in args:
        compile(filename)

if __name__ == "__main__":
    main()
