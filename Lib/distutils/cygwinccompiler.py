"""distutils.cygwinccompiler

Provides the CygwinCCompiler class, a subclass of UnixCCompiler that
handles the Cygwin port of the GNU C compiler to Windows.  It also contains
the Mingw32CCompiler class which handles the mingw32 port of GCC (same as
cygwin in no-cygwin mode).
"""

# problems:
#
# * if you use a msvc compiled python version (1.5.2)
#   1. you have to insert a __GNUC__ section in its config.h
#   2. you have to generate a import library for its dll
#      - create a def-file for python??.dll
#      - create a import library using
#             dlltool --dllname python15.dll --def python15.def \
#                       --output-lib libpython15.a
#
#   see also http://starship.python.net/crew/kernr/mingw32/Notes.html
#
# * We use put export_symbols in a def-file, and don't use 
#   --export-all-symbols because it doesn't worked reliable in some
#   tested configurations. And because other windows compilers also
#   need their symbols specified this no serious problem.
#
# tested configurations:
#   
# * cygwin gcc 2.91.57/ld 2.9.4/dllwrap 0.2.4 works 
#   (after patching python's config.h and for C++ some other include files)
#   see also http://starship.python.net/crew/kernr/mingw32/Notes.html
# * mingw32 gcc 2.95.2/ld 2.9.4/dllwrap 0.2.4 works 
#   (ld doesn't support -shared, so we use dllwrap)   
# * cygwin gcc 2.95.2/ld 2.10.90/dllwrap 2.10.90 works now
#   - its dllwrap doesn't work, there is a bug in binutils 2.10.90
#     see also .....
#   - using gcc -mdll instead dllwrap doesn't work without -static because 
#     it tries to link against dlls instead their import libraries. (If
#     it finds the dll first.)
#     By specifying -static we force ld to link against the import libraries, 
#     this is windows standard and there are normally not the necessary symbols 
#     in the dlls.

# created 2000/05/05, Rene Liebscher

__revision__ = "$Id$"

import os,sys
from distutils.unixccompiler import UnixCCompiler
from distutils.file_util import write_file

class CygwinCCompiler (UnixCCompiler):

    compiler_type = 'cygwin'
    gcc_version = None
    dllwrap_version = None
    ld_version = None
   
    def __init__ (self,
                  verbose=0,
                  dry_run=0,
                  force=0):

        UnixCCompiler.__init__ (self, verbose, dry_run, force)

        if check_config_h()<=0:
            self.warn(
                "Python's config.h doesn't seem to support your compiler. "
                "Compiling may fail because of undefined preprocessor macros.")
        
        (self.gcc_version, self.ld_version, self.dllwrap_version) = \
            get_versions()
        sys.stderr.write(self.compiler_type + ": gcc %s, ld %s, dllwrap %s\n" %
                         (self.gcc_version, 
                          self.ld_version, 
                          self.dllwrap_version) )

        # ld_version >= "2.10.90" should also be able to use 
        # gcc -mdll instead of dllwrap
        # Older dllwraps had own version numbers, newer ones use the 
        # same as the rest of binutils ( also ld )
        # dllwrap 2.10.90 is buggy
        if self.ld_version >= "2.10.90": 
            self.linker = "gcc"
        else:
            self.linker = "dllwrap"

        # Hard-code GCC because that's what this is all about.
        # XXX optimization, warnings etc. should be customizable.
        self.set_executables(compiler='gcc -mcygwin -O -Wall',
                             compiler_so='gcc -mcygwin -mdll -O -Wall',
                             linker_exe='gcc -mcygwin',
                             linker_so=('%s -mcygwin -mdll -static' %
                                        self.linker))

        # cygwin and mingw32 need different sets of libraries 
        if self.gcc_version == "2.91.57":
            # cygwin shouldn't need msvcrt, but without the dlls will crash
            # (gcc version 2.91.57) -- perhaps something about initialization
            self.dll_libraries=["msvcrt"]
            self.warn( 
                "Consider upgrading to a newer version of gcc")
        else:
            self.dll_libraries=[]
        
    # __init__ ()

    def link_shared_object (self,
                            objects,
                            output_filename,
                            output_dir=None,
                            libraries=None,
                            library_dirs=None,
                            runtime_library_dirs=None,
                            export_symbols=None,
                            debug=0,
                            extra_preargs=None,
                            extra_postargs=None,
                            build_temp=None):
        
        # use separate copies, so can modify the lists
        extra_preargs = list(extra_preargs or [])
        libraries = list(libraries or [])
        
        # Additional libraries
        libraries.extend(self.dll_libraries)
        
        # we want to put some files in the same directory as the 
        # object files are, build_temp doesn't help much

        # where are the object files
        temp_dir = os.path.dirname(objects[0])

        # name of dll to give the helper files (def, lib, exp) the same name
        (dll_name, dll_extension) = os.path.splitext(
            os.path.basename(output_filename))

        # generate the filenames for these files
        def_file = None # this will be done later, if necessary
        exp_file = os.path.join(temp_dir, dll_name + ".exp")
        lib_file = os.path.join(temp_dir, 'lib' + dll_name + ".a")

        #extra_preargs.append("--verbose")
        if self.linker == "dllwrap":
            extra_preargs.extend([#"--output-exp",exp_file,
                                  "--output-lib",lib_file,
                                 ])
        else:
            # doesn't work: bfd_close build\...\libfoo.a: Invalid operation
            extra_preargs.extend([#"-Wl,--out-implib,%s" % lib_file,
                                 ])
       
        #  check what we got in export_symbols
        if export_symbols is not None:
            # Make .def file
            # (It would probably better to check if we really need this, 
            # but for this we had to insert some unchanged parts of 
            # UnixCCompiler, and this is not what we want.) 
            def_file = os.path.join(temp_dir, dll_name + ".def")
            contents = [
                "LIBRARY %s" % os.path.basename(output_filename),
                "EXPORTS"]
            for sym in export_symbols:
                contents.append(sym)
            self.execute(write_file, (def_file, contents),
                         "writing %s" % def_file)

        if def_file:
            if self.linker == "dllwrap":
                # for dllwrap we have to use a special option
                extra_preargs.append("--def")
            # for gcc/ld it is specified as any other object file    
            extra_preargs.append(def_file)
                                                 
        # who wants symbols and a many times larger output file
        # should explicitly switch the debug mode on 
        # otherwise we let dllwrap/ld strip the output file
        # (On my machine unstripped_file = stripped_file + 254KB
        #   10KB < stripped_file < ??100KB ) 
        if not debug: 
            extra_preargs.append("-s") 
        
        UnixCCompiler.link_shared_object(self,
                            objects,
                            output_filename,
                            output_dir,
                            libraries,
                            library_dirs,
                            runtime_library_dirs,
                            None, # export_symbols, we do this in our def-file
                            debug,
                            extra_preargs,
                            extra_postargs,
                            build_temp)
        
    # link_shared_object ()

# class CygwinCCompiler


# the same as cygwin plus some additional parameters
class Mingw32CCompiler (CygwinCCompiler):

    compiler_type = 'mingw32'

    def __init__ (self,
                  verbose=0,
                  dry_run=0,
                  force=0):

        CygwinCCompiler.__init__ (self, verbose, dry_run, force)
        
        # A real mingw32 doesn't need to specify a different entry point,
        # but cygwin 2.91.57 in no-cygwin-mode needs it.
        if self.gcc_version <= "2.91.57":
            entry_point = '--entry _DllMain@12'
        else:
            entry_point = ''

        self.set_executables(compiler='gcc -mno-cygwin -O -Wall',
                             compiler_so='gcc -mno-cygwin -mdll -O -Wall',
                             linker_exe='gcc -mno-cygwin',
                             linker_so='%s -mno-cygwin -mdll -static %s' 
                                        % (self.linker, entry_point))
        # Maybe we should also append -mthreads, but then the finished
        # dlls need another dll (mingwm10.dll see Mingw32 docs)
        # (-mthreads: Support thread-safe exception handling on `Mingw32')       
        
        # no additional libraries needed 
        self.dll_libraries=[]
        
    # __init__ ()

# class Mingw32CCompiler

# Because these compilers aren't configured in Python's config.h file by
# default, we should at least warn the user if he is using a unmodified
# version.

def check_config_h():
    """Checks if the GCC compiler is mentioned in config.h.  If it is not,
       compiling probably doesn't work.
    """
    # return values
    #  2: OK, python was compiled with GCC
    #  1: OK, python's config.h mentions __GCC__
    #  0: uncertain, because we couldn't check it
    # -1: probably not OK, because we didn't found it in config.h
    # You could check check_config_h()>0 => OK

    from distutils import sysconfig
    import string,sys
    # if sys.version contains GCC then python was compiled with
    # GCC, and the config.h file should be OK
    if -1 == string.find(sys.version,"GCC"):
        pass # go to the next test
    else:
        return 2
    
    try:
        # It would probably better to read single lines to search.
        # But we do this only once, and it is fast enough 
        f=open(sysconfig.get_config_h_filename())
        s=f.read()
        f.close()
        
        # is somewhere a #ifdef __GNUC__ or something similar
        if -1 == string.find(s,"__GNUC__"):
            return -1  
        else:
            return 1
    except IOError:
        # if we can't read this file, we cannot say it is wrong
        # the compiler will complain later about this file as missing
        pass
    return 0

def get_versions():
    """ Try to find out the versions of gcc, ld and dllwrap.
        If not possible it returns None for it.
    """
    from distutils.version import StrictVersion
    from distutils.spawn import find_executable
    import re
        
    gcc_exe = find_executable('gcc')
    if gcc_exe:
        out = os.popen(gcc_exe + ' -dumpversion','r')
        out_string = out.read()
        out.close()
        result = re.search('(\d+\.\d+\.\d+)',out_string)
        if result:
            gcc_version = StrictVersion(result.group(1))
        else:
            gcc_version = None
    else:
        gcc_version = None
    ld_exe = find_executable('ld')
    if ld_exe:
        out = os.popen(ld_exe + ' -v','r')
        out_string = out.read()
        out.close()
        result = re.search('(\d+\.\d+\.\d+)',out_string)
        if result:
            ld_version = StrictVersion(result.group(1))
        else:
            ld_version = None
    else:
        ld_version = None
    dllwrap_exe = find_executable('dllwrap')
    if dllwrap_exe:
        out = os.popen(dllwrap_exe + ' --version','r')
        out_string = out.read()
        out.close()
        result = re.search(' (\d+\.\d+\.\d+)',out_string)
        if result:
            dllwrap_version = StrictVersion(result.group(1))
        else:
            dllwrap_version = None
    else:
        dllwrap_version = None
    return (gcc_version, ld_version, dllwrap_version)

