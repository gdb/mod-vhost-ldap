"""distutils.ccompiler

Contains MSVCCompiler, an implementation of the abstract CCompiler class
for the Microsoft Visual Studio."""


# created 1999/08/19, Perry Stoll
# 
__rcsid__ = "$Id$"

import os
import sys
import string
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


def _find_SET(name,version_number):
    """looks up in the registry and returns a list of values suitable for
       use in a SET command eg SET name=value. Normally the value will be a
       ';' separated list similar to a path list.

       name is the name of an MSVC path and version_number is a version_number
       of an MSVC installation."""
    return get_msvc_paths(name, version_number)


def _do_SET(name, version_number):
    """sets os.environ[name] to an MSVC path type value obtained from
       _find_SET. This is equivalent to a SET command prior to execution of
       spawned commands."""
    p=_find_SET(name, version_number)
    if p:
        os.environ[name]=string.join(p,';')


class MSVCCompiler (CCompiler) :
    """Concrete class that implements an interface to Microsoft Visual C++,
       as defined by the CCompiler abstract class."""

    compiler_type = 'msvc'

    def __init__ (self,
                  verbose=0,
                  dry_run=0,
                  force=0):

        CCompiler.__init__ (self, verbose, dry_run, force)

        self.add_library_dir( os.path.join( sys.exec_prefix, 'libs' ) )
        
        vNum = get_devstudio_versions ()

        if vNum:
            vNum = vNum[0]  # highest version

            self.cc   = _find_exe("cl.exe", vNum)
            self.link = _find_exe("link.exe", vNum)
            _do_SET('lib', vNum)
            _do_SET('include', vNum)
            path=_find_SET('path', vNum)
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

        self.preprocess_options = None
        self.compile_options = [ '/nologo', '/Ox', '/MD', '/W3' ]
        self.compile_options_debug = [
            '/nologo', '/Od', '/MDd', '/W3', '/Z7', '/D_DEBUG'
            ]

        self.ldflags_shared = ['/DLL', '/nologo', '/INCREMENTAL:NO']
        self.ldflags_shared_debug = [
            '/DLL', '/nologo', '/INCREMENTAL:no', '/pdb:None', '/DEBUG'
            ]
        self.ldflags_static = [ '/nologo']


    # -- Worker methods ------------------------------------------------
    # (must be implemented by subclasses)

    _c_extensions = [ '.c' ]
    _cpp_extensions = [ '.cc', '.cpp' ]

    _obj_ext = '.obj'
    _exe_ext = '.exe'
    _shared_lib_ext = '.dll'
    _static_lib_ext = '.lib'

    # XXX the 'output_dir' parameter is ignored by the methods in this
    # class!  I just put it in to be consistent with CCompiler and
    # UnixCCompiler, but someone who actually knows Visual C++ will
    # have to make it work...
    
    def compile (self,
                 sources,
                 output_dir=None,
                 macros=None,
                 include_dirs=None,
                 debug=0,
                 extra_preargs=None,
                 extra_postargs=None):

        if macros is None:
            macros = []
        if include_dirs is None:
            include_dirs = []

        objectFiles = []

        base_pp_opts = \
            gen_preprocess_options (self.macros + macros,
                                    self.include_dirs + include_dirs)

        base_pp_opts.append('/c')

        if debug:
            compile_options = self.compile_options_debug
        else:
            compile_options = self.compile_options
        
        for srcFile in sources:
            base,ext = os.path.splitext(srcFile)
            objFile = base + ".obj"

            if ext in self._c_extensions:
                fileOpt = "/Tc"
            elif ext in self._cpp_extensions:
                fileOpt = "/Tp"

            inputOpt  = fileOpt + srcFile
            outputOpt = "/Fo"   + objFile

            cc_args = compile_options + \
                      base_pp_opts + \
                      [outputOpt, inputOpt]

            if extra_preargs:
                cc_args[:0] = extra_preargs
            if extra_postargs:
                cc_args.extend (extra_postargs)

            self.spawn ([self.cc] + cc_args)
            objectFiles.append( objFile )
        return objectFiles


    # XXX the signature of this method is different from CCompiler and
    # UnixCCompiler -- but those extra parameters (libraries, library_dirs)
    # are actually used.  So: are they really *needed*, or can they be
    # ditched?  If needed, the CCompiler API will have to change...
    def link_static_lib (self,
                         objects,
                         output_libname,
                         output_dir=None,
                         libraries=None,
                         library_dirs=None,
                         debug=0,
                         extra_preargs=None,
                         extra_postargs=None):

        if libraries is None:
            libraries = []
        if library_dirs is None:
            library_dirs = []
        
        lib_opts = gen_lib_options (self.libraries + libraries,
                                    self.library_dirs + library_dirs,
                                    "%s.lib", "/LIBPATH:%s")

        ld_args = self.ldflags_static + lib_opts + \
                  objects + ['/OUT:' + output_filename]
        if debug:
            pass                        # XXX what goes here?
        if extra_preargs:
            ld_args[:0] = extra_preargs
        if extra_postargs:
            ld_args.extend (extra_postargs)

        self.spawn ( [ self.link ] + ld_args )
    

    def link_shared_lib (self,
                         objects,
                         output_libname,
                         output_dir=None,
                         libraries=None,
                         library_dirs=None,
                         debug=0,
                         extra_preargs=None,
                         extra_postargs=None):

        # XXX should we sanity check the library name? (eg. no
        # slashes)
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
        """Link a bunch of stuff together to create a shared object
           file.  Much like 'link_shared_lib()', except the output
           filename is explicitly supplied as 'output_filename'."""
        if libraries is None:
            libraries = []
        if library_dirs is None:
            library_dirs = []
        
        lib_opts = gen_lib_options (self,
                                    self.library_dirs + library_dirs,
                                    self.libraries + libraries)

        if debug:
            ldflags = self.ldflags_shared_debug
            basename, ext = os.path.splitext (output_filename)
            #XXX not sure this belongs here
            # extensions in debug_mode are named 'module_d.pyd'
            output_filename = basename + '_d' + ext
        else:
            ldflags = self.ldflags_shared

        ld_args = ldflags + lib_opts + \
                  objects + ['/OUT:' + output_filename]

        if extra_preargs:
            ld_args[:0] = extra_preargs
        if extra_postargs:
            ld_args.extend (extra_postargs)

        self.spawn ( [ self.link ] + ld_args )


    # -- Filename mangling methods -------------------------------------

    def _change_extensions( self, filenames, newExtension ):
        object_filenames = []

        for srcFile in filenames:
            base,ext = os.path.splitext( srcFile )
            # XXX should we strip off any existing path?
            object_filenames.append( base + newExtension )

        return object_filenames

    def object_filenames (self, source_filenames):
        """Return the list of object filenames corresponding to each
           specified source filename."""
        return self._change_extensions( source_filenames, self._obj_ext )

    def shared_object_filename (self, source_filename):
        """Return the shared object filename corresponding to a
           specified source filename."""
        return self._change_extensions( source_filenames, self._shared_lib_ext )

    def library_filename (self, libname):
        """Return the static library filename corresponding to the
           specified library name."""
        return "%s%s" %( libname, self._static_lib_ext )

    def shared_library_filename (self, libname):
        """Return the shared library filename corresponding to the
           specified library name."""
        return "%s%s" %( libname, self._shared_lib_ext )


    def library_dir_option (self, dir):
        return "/LIBPATH:" + dir

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
