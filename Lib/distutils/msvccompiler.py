"""distutils.ccompiler

Contains MSVCCompiler, an implementation of the abstract CCompiler class
for the Microsoft Visual Studio."""


# created 1999/08/19, Perry Stoll
# hacked by Robin Becker and Thomas Heller to do a better job of
#   finding DevStudio (through the registry)

__revision__ = "$Id$"

import sys, os, string
from types import *
from distutils.errors import *
from distutils.ccompiler import \
     CCompiler, gen_preprocess_options, gen_lib_options


def get_devstudio_versions ():
    """Get list of devstudio versions from the Windows registry.  Return a
       list of strings containing version numbers; the list will be
       empty if we were unable to access the registry (eg. couldn't import
       a registry-access module) or the appropriate registry keys weren't
       found."""

    try:
        import win32api
        import win32con
    except ImportError:
        return []

    K = 'Software\\Microsoft\\Devstudio'
    L = []
    for base in (win32con.HKEY_CLASSES_ROOT,
                 win32con.HKEY_LOCAL_MACHINE,
                 win32con.HKEY_CURRENT_USER,
                 win32con.HKEY_USERS):
        try:
            k = win32api.RegOpenKeyEx(base,K)
            i = 0
            while 1:
                try:
                    p = win32api.RegEnumKey(k,i)
                    if p[0] in '123456789' and p not in L:
                        L.append(p)
                except win32api.error:
                    break
                i = i + 1
        except win32api.error:
            pass
    L.sort()
    L.reverse()
    return L

# get_devstudio_versions ()


def get_msvc_paths (path, version='6.0', platform='x86'):
    """Get a list of devstudio directories (include, lib or path).  Return
       a list of strings; will be empty list if unable to access the
       registry or appropriate registry keys not found."""
       
    try:
        import win32api
        import win32con
    except ImportError:
        return []

    L = []
    if path=='lib':
        path= 'Library'
    path = string.upper(path + ' Dirs')
    K = ('Software\\Microsoft\\Devstudio\\%s\\' +
         'Build System\\Components\\Platforms\\Win32 (%s)\\Directories') % \
        (version,platform)
    for base in (win32con.HKEY_CLASSES_ROOT,
                 win32con.HKEY_LOCAL_MACHINE,
                 win32con.HKEY_CURRENT_USER,
                 win32con.HKEY_USERS):
        try:
            k = win32api.RegOpenKeyEx(base,K)
            i = 0
            while 1:
                try:
                    (p,v,t) = win32api.RegEnumValue(k,i)
                    if string.upper(p) == path:
                        V = string.split(v,';')
                        for v in V:
                            if v == '' or v in L: continue
                            L.append(v)
                        break
                    i = i + 1
                except win32api.error:
                    break
        except win32api.error:
            pass
    return L

# get_msvc_paths()


def find_exe (exe, version_number):
    """Try to find an MSVC executable program 'exe' (from version
       'version_number' of MSVC) in several places: first, one of the MSVC
       program search paths from the registry; next, the directories in the
       PATH environment variable.  If any of those work, return an absolute
       path that is known to exist.  If none of them work, just return the
       original program name, 'exe'."""

    for p in get_msvc_paths ('path', version_number):
        fn = os.path.join (os.path.abspath(p), exe)
        if os.path.isfile(fn):
            return fn

    # didn't find it; try existing path
    for p in string.split (os.environ['Path'],';'):
        fn = os.path.join(os.path.abspath(p),exe)
        if os.path.isfile(fn):
            return fn

    return exe                          # last desperate hope 


def set_path_env_var (name, version_number):
    """Set environment variable 'name' to an MSVC path type value obtained
       from 'get_msvc_paths()'.  This is equivalent to a SET command prior
       to execution of spawned commands."""

    p = get_msvc_paths (name, version_number)
    if p:
        os.environ[name] = string.join (p,';')


class MSVCCompiler (CCompiler) :
    """Concrete class that implements an interface to Microsoft Visual C++,
       as defined by the CCompiler abstract class."""

    compiler_type = 'msvc'

    # Private class data (need to distinguish C from C++ source for compiler)
    _c_extensions = ['.c']
    _cpp_extensions = ['.cc','.cpp']

    # Needed for the filename generation methods provided by the
    # base class, CCompiler.
    src_extensions = _c_extensions + _cpp_extensions
    obj_extension = '.obj'
    static_lib_extension = '.lib'
    shared_lib_extension = '.dll'
    static_lib_format = shared_lib_format = '%s%s'
    exe_extension = '.exe'


    def __init__ (self,
                  verbose=0,
                  dry_run=0,
                  force=0):

        CCompiler.__init__ (self, verbose, dry_run, force)

        self.add_library_dir( os.path.join( sys.exec_prefix, 'libs' ) )
        
        versions = get_devstudio_versions ()

        if versions:
            version = versions[0]  # highest version

            self.cc   = _find_exe("cl.exe", version)
            self.link = _find_exe("link.exe", version)
            self.lib  = _find_exe("lib.exe", version)
            set_path_env_var ('lib', version)
            set_path_env_var ('include', version)
            path=get_msvc_paths('path', version)
            try:
                for p in string.split(os.environ['path'],';'):
                    path.append(p)
            except KeyError:
                pass
            os.environ['path'] = string.join(path,';')
        else:
            # devstudio not found in the registry
            self.cc = "cl.exe"
            self.link = "link.exe"
            self.lib = "lib.exe"

        self.preprocess_options = None
        self.compile_options = [ '/nologo', '/Ox', '/MD', '/W3' ]
        self.compile_options_debug = ['/nologo', '/Od', '/MDd', '/W3', '/Z7', '/D_DEBUG']

        self.ldflags_shared = ['/DLL', '/nologo', '/INCREMENTAL:NO']
        self.ldflags_shared_debug = [
            '/DLL', '/nologo', '/INCREMENTAL:no', '/pdb:None', '/DEBUG'
            ]
        self.ldflags_static = [ '/nologo']


    # -- Worker methods ------------------------------------------------

    def compile (self,
                 sources,
                 output_dir=None,
                 macros=None,
                 include_dirs=None,
                 debug=0,
                 extra_preargs=None,
                 extra_postargs=None):

        (output_dir, macros, include_dirs) = \
            self._fix_compile_args (output_dir, macros, include_dirs)
        (objects, skip_sources) = self._prep_compile (sources, output_dir)

        if extra_postargs is None:
            extra_postargs = []

        pp_opts = gen_preprocess_options (macros, include_dirs)
        compile_opts = extra_preargs or []
        compile_opts.append ('/c')
        if debug:
            compile_opts.extend (self.compile_options_debug)
        else:
            compile_opts.extend (self.compile_options)
        
        for i in range (len (sources)):
            src = sources[i] ; obj = objects[i]
            ext = (os.path.splitext (src))[1]

            if skip_sources[src]:
                self.announce ("skipping %s (%s up-to-date)" % (src, obj))
            else:
                if ext in self._c_extensions:
                    input_opt = "/Tc" + src
                elif ext in self._cpp_extensions:
                    input_opt = "/Tp" + src

                output_opt = "/Fo" + obj

                self.mkpath (os.path.dirname (obj))
                self.spawn ([self.cc] + compile_opts + pp_opts +
                            [input_opt, output_opt] +
                            extra_postargs)

        return objects

    # compile ()


    def create_static_lib (self,
                           objects,
                           output_libname,
                           output_dir=None,
                           debug=0,
                           extra_preargs=None,
                           extra_postargs=None):

        (objects, output_dir) = \
            self._fix_link_args (objects, output_dir, takes_libs=0)
        output_filename = \
            self.library_filename (output_libname, output_dir=output_dir)

        if self._need_link (objects, output_filename):
            lib_args = objects + ['/OUT:' + output_filename]
            if debug:
                pass                    # XXX what goes here?
            if extra_preargs:
                lib_args[:0] = extra_preargs
            if extra_postargs:
                lib_args.extend (extra_postargs)
            self.spawn ([self.link] + ld_args)
        else:
            self.announce ("skipping %s (up-to-date)" % output_filename)

    # create_static_lib ()
    

    def link_shared_lib (self,
                         objects,
                         output_libname,
                         output_dir=None,
                         libraries=None,
                         library_dirs=None,
                         debug=0,
                         extra_preargs=None,
                         extra_postargs=None):

        self.link_shared_object (objects,
                                 self.shared_library_name(output_libname),
                                 output_dir=output_dir,
                                 libraries=libraries,
                                 library_dirs=library_dirs,
                                 debug=debug,
                                 extra_preargs=extra_preargs,
                                 extra_postargs=extra_postargs)
                    
    
    def link_shared_object (self,
                            objects,
                            output_filename,
                            output_dir=None,
                            libraries=None,
                            library_dirs=None,
                            debug=0,
                            extra_preargs=None,
                            extra_postargs=None):

        (objects, output_dir, libraries, library_dirs) = \
            self._fix_link_args (objects, output_dir, takes_libs=1,
                                 libraries=libraries, library_dirs=library_dirs)
        
        lib_opts = gen_lib_options (self,
                                    library_dirs, self.runtime_library_dirs,
                                    libraries)
        if type (output_dir) not in (StringType, NoneType):
            raise TypeError, "'output_dir' must be a string or None"
        if output_dir is not None:
            output_filename = os.path.join (output_dir, output_filename)

        if self._need_link (objects, output_filename):

            if debug:
                ldflags = self.ldflags_shared_debug
                # XXX not sure this belongs here
                # extensions in debug_mode are named 'module_d.pyd'
                basename, ext = os.path.splitext (output_filename)
                output_filename = basename + '_d' + ext
            else:
                ldflags = self.ldflags_shared

            ld_args = ldflags + lib_opts + \
                      objects + ['/OUT:' + output_filename]

            if extra_preargs:
                ld_args[:0] = extra_preargs
            if extra_postargs:
                ld_args.extend (extra_postargs)

            self.mkpath (os.path.dirname (output_filename))
            self.spawn ([self.link] + ld_args)

        else:
            self.announce ("skipping %s (up-to-date)" % output_filename)

    # link_shared_object ()
    

    # -- Miscellaneous methods -----------------------------------------
    # These are all used by the 'gen_lib_options() function, in
    # ccompiler.py.

    def library_dir_option (self, dir):
        return "/LIBPATH:" + dir

    def runtime_library_dir_option (self, dir):
        raise DistutilsPlatformError, \
              "don't know how to set runtime library search path for MSVC++"

    def library_option (self, lib):
        return self.library_filename (lib)


    def find_library_file (self, dirs, lib):

        for dir in dirs:
            libfile = os.path.join (dir, self.library_filename (lib))
            if os.path.exists (libfile):
                return libfile

        else:
            # Oops, didn't find it in *any* of 'dirs'
            return None

    # find_library_file ()

# class MSVCCompiler
