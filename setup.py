# Autodetecting setup.py script for building the Python extensions
#

__version__ = "$Revision$"

import sys, os, getopt, imp, re

from distutils import log
from distutils import sysconfig
from distutils import text_file
from distutils.errors import *
from distutils.core import Extension, setup
from distutils.command.build_ext import build_ext
from distutils.command.install import install
from distutils.command.install_lib import install_lib

# This global variable is used to hold the list of modules to be disabled.
disabled_module_list = []

def add_dir_to_list(dirlist, dir):
    """Add the directory 'dir' to the list 'dirlist' (at the front) if
    1) 'dir' is not already in 'dirlist'
    2) 'dir' actually exists, and is a directory."""
    if dir is not None and os.path.isdir(dir) and dir not in dirlist:
        dirlist.insert(0, dir)

def find_file(filename, std_dirs, paths):
    """Searches for the directory where a given file is located,
    and returns a possibly-empty list of additional directories, or None
    if the file couldn't be found at all.

    'filename' is the name of a file, such as readline.h or libcrypto.a.
    'std_dirs' is the list of standard system directories; if the
        file is found in one of them, no additional directives are needed.
    'paths' is a list of additional locations to check; if the file is
        found in one of them, the resulting list will contain the directory.
    """

    # Check the standard locations
    for dir in std_dirs:
        f = os.path.join(dir, filename)
        if os.path.exists(f): return []

    # Check the additional directories
    for dir in paths:
        f = os.path.join(dir, filename)
        if os.path.exists(f):
            return [dir]

    # Not found anywhere
    return None

def find_library_file(compiler, libname, std_dirs, paths):
    result = compiler.find_library_file(std_dirs + paths, libname)
    if result is None:
        return None

    # Check whether the found file is in one of the standard directories
    dirname = os.path.dirname(result)
    for p in std_dirs:
        # Ensure path doesn't end with path separator
        p = p.rstrip(os.sep)
        if p == dirname:
            return [ ]

    # Otherwise, it must have been in one of the additional directories,
    # so we have to figure out which one.
    for p in paths:
        # Ensure path doesn't end with path separator
        p = p.rstrip(os.sep)
        if p == dirname:
            return [p]
    else:
        assert False, "Internal error: Path not found in std_dirs or paths"

def module_enabled(extlist, modname):
    """Returns whether the module 'modname' is present in the list
    of extensions 'extlist'."""
    extlist = [ext for ext in extlist if ext.name == modname]
    return len(extlist)

def find_module_file(module, dirlist):
    """Find a module in a set of possible folders. If it is not found
    return the unadorned filename"""
    list = find_file(module, [], dirlist)
    if not list:
        return module
    if len(list) > 1:
        log.info("WARNING: multiple copies of %s found"%module)
    return os.path.join(list[0], module)

class PyBuildExt(build_ext):

    def build_extensions(self):

        # Detect which modules should be compiled
        self.detect_modules()

        # Remove modules that are present on the disabled list
        self.extensions = [ext for ext in self.extensions
                           if ext.name not in disabled_module_list]

        # Fix up the autodetected modules, prefixing all the source files
        # with Modules/ and adding Python's include directory to the path.
        (srcdir,) = sysconfig.get_config_vars('srcdir')
        if not srcdir:
            # Maybe running on Windows but not using CYGWIN?
            raise ValueError("No source directory; cannot proceed.")

        # Figure out the location of the source code for extension modules
        moddir = os.path.join(os.getcwd(), srcdir, 'Modules')
        moddir = os.path.normpath(moddir)
        srcdir, tail = os.path.split(moddir)
        srcdir = os.path.normpath(srcdir)
        moddir = os.path.normpath(moddir)

        moddirlist = [moddir]
        incdirlist = ['./Include']

        # Platform-dependent module source and include directories
        platform = self.get_platform()
        if platform in ('darwin', 'mac'):
            # Mac OS X also includes some mac-specific modules
            macmoddir = os.path.join(os.getcwd(), srcdir, 'Mac/Modules')
            moddirlist.append(macmoddir)
            incdirlist.append('./Mac/Include')

        alldirlist = moddirlist + incdirlist

        # Fix up the paths for scripts, too
        self.distribution.scripts = [os.path.join(srcdir, filename)
                                     for filename in self.distribution.scripts]

        for ext in self.extensions[:]:
            ext.sources = [ find_module_file(filename, moddirlist)
                            for filename in ext.sources ]
            if ext.depends is not None:
                ext.depends = [find_module_file(filename, alldirlist)
                               for filename in ext.depends]
            ext.include_dirs.append( '.' ) # to get config.h
            for incdir in incdirlist:
                ext.include_dirs.append( os.path.join(srcdir, incdir) )

            # If a module has already been built statically,
            # don't build it here
            if ext.name in sys.builtin_module_names:
                self.extensions.remove(ext)

        if platform != 'mac':
            # Parse Modules/Setup to figure out which modules are turned
            # on in the file.
            input = text_file.TextFile('Modules/Setup', join_lines=1)
            remove_modules = []
            while 1:
                line = input.readline()
                if not line: break
                line = line.split()
                remove_modules.append( line[0] )
            input.close()

            for ext in self.extensions[:]:
                if ext.name in remove_modules:
                    self.extensions.remove(ext)

        # When you run "make CC=altcc" or something similar, you really want
        # those environment variables passed into the setup.py phase.  Here's
        # a small set of useful ones.
        compiler = os.environ.get('CC')
        linker_so = os.environ.get('LDSHARED')
        args = {}
        # unfortunately, distutils doesn't let us provide separate C and C++
        # compilers
        if compiler is not None:
            (ccshared,opt,base) = sysconfig.get_config_vars('CCSHARED','OPT','BASECFLAGS')
            args['compiler_so'] = compiler + ' ' + opt + ' ' + ccshared + ' ' + base
        if linker_so is not None:
            args['linker_so'] = linker_so
        self.compiler.set_executables(**args)

        build_ext.build_extensions(self)

    def build_extension(self, ext):

        try:
            build_ext.build_extension(self, ext)
        except (CCompilerError, DistutilsError), why:
            self.announce('WARNING: building of extension "%s" failed: %s' %
                          (ext.name, sys.exc_info()[1]))
            return
        # Workaround for Mac OS X: The Carbon-based modules cannot be
        # reliably imported into a command-line Python
        if 'Carbon' in ext.extra_link_args:
            self.announce(
                'WARNING: skipping import check for Carbon-based "%s"' %
                ext.name)
            return
        # Workaround for Cygwin: Cygwin currently has fork issues when many
        # modules have been imported
        if self.get_platform() == 'cygwin':
            self.announce('WARNING: skipping import check for Cygwin-based "%s"'
                % ext.name)
            return
        ext_filename = os.path.join(
            self.build_lib,
            self.get_ext_filename(self.get_ext_fullname(ext.name)))
        try:
            imp.load_dynamic(ext.name, ext_filename)
        except ImportError, why:
            self.announce('*** WARNING: renaming "%s" since importing it'
                          ' failed: %s' % (ext.name, why), level=3)
            assert not self.inplace
            basename, tail = os.path.splitext(ext_filename)
            newname = basename + "_failed" + tail
            if os.path.exists(newname):
                os.remove(newname)
            os.rename(ext_filename, newname)

            # XXX -- This relies on a Vile HACK in
            # distutils.command.build_ext.build_extension().  The
            # _built_objects attribute is stored there strictly for
            # use here.
            # If there is a failure, _built_objects may not be there,
            # so catch the AttributeError and move on.
            try:
                for filename in self._built_objects:
                    os.remove(filename)
            except AttributeError:
                self.announce('unable to remove files (ignored)')
        except:
            exc_type, why, tb = sys.exc_info()
            self.announce('*** WARNING: importing extension "%s" '
                          'failed with %s: %s' % (ext.name, exc_type, why),
                          level=3)

    def get_platform(self):
        # Get value of sys.platform
        for platform in ['cygwin', 'beos', 'darwin', 'atheos', 'osf1']:
            if sys.platform.startswith(platform):
                return platform
        return sys.platform

    def detect_modules(self):
        # Ensure that /usr/local is always used
        add_dir_to_list(self.compiler.library_dirs, '/usr/local/lib')
        add_dir_to_list(self.compiler.include_dirs, '/usr/local/include')

        # fink installs lots of goodies in /sw/... - make sure we
        # check there
        if sys.platform == "darwin":
            add_dir_to_list(self.compiler.library_dirs, '/sw/lib')
            add_dir_to_list(self.compiler.include_dirs, '/sw/include')

        if os.path.normpath(sys.prefix) != '/usr':
            add_dir_to_list(self.compiler.library_dirs,
                            sysconfig.get_config_var("LIBDIR"))
            add_dir_to_list(self.compiler.include_dirs,
                            sysconfig.get_config_var("INCLUDEDIR"))

        try:
            have_unicode = unicode
        except NameError:
            have_unicode = 0

        # lib_dirs and inc_dirs are used to search for files;
        # if a file is found in one of those directories, it can
        # be assumed that no additional -I,-L directives are needed.
        lib_dirs = self.compiler.library_dirs + ['/lib', '/usr/lib']
        inc_dirs = self.compiler.include_dirs + ['/usr/include']
        exts = []

        platform = self.get_platform()
        (srcdir,) = sysconfig.get_config_vars('srcdir')

        # Check for AtheOS which has libraries in non-standard locations
        if platform == 'atheos':
            lib_dirs += ['/system/libs', '/atheos/autolnk/lib']
            lib_dirs += os.getenv('LIBRARY_PATH', '').split(os.pathsep)
            inc_dirs += ['/system/include', '/atheos/autolnk/include']
            inc_dirs += os.getenv('C_INCLUDE_PATH', '').split(os.pathsep)

        # OSF/1 and Unixware have some stuff in /usr/ccs/lib (like -ldb)
        if platform in ['osf1', 'unixware7', 'openunix8']:
            lib_dirs += ['/usr/ccs/lib']

        # Check for MacOS X, which doesn't need libm.a at all
        math_libs = ['m']
        if platform in ['darwin', 'beos', 'mac']:
            math_libs = []

        # XXX Omitted modules: gl, pure, dl, SGI-specific modules

        #
        # The following modules are all pretty straightforward, and compile
        # on pretty much any POSIXish platform.
        #

        # Some modules that are normally always on:
        exts.append( Extension('regex', ['regexmodule.c', 'regexpr.c']) )
        exts.append( Extension('pcre', ['pcremodule.c', 'pypcre.c']) )

        exts.append( Extension('_hotshot', ['_hotshot.c']) )
        exts.append( Extension('_weakref', ['_weakref.c']) )
        exts.append( Extension('xreadlines', ['xreadlinesmodule.c']) )

        # array objects
        exts.append( Extension('array', ['arraymodule.c']) )
        # complex math library functions
        exts.append( Extension('cmath', ['cmathmodule.c'],
                               libraries=math_libs) )

        # math library functions, e.g. sin()
        exts.append( Extension('math',  ['mathmodule.c'],
                               libraries=math_libs) )
        # fast string operations implemented in C
        exts.append( Extension('strop', ['stropmodule.c']) )
        # time operations and variables
        exts.append( Extension('time', ['timemodule.c'],
                               libraries=math_libs) )
        exts.append( Extension('datetime', ['datetimemodule.c'],
                               libraries=math_libs) )
        # random number generator implemented in C
        exts.append( Extension("_random", ["_randommodule.c"]) )
        # fast iterator tools implemented in C
        exts.append( Extension("itertools", ["itertoolsmodule.c"]) )
        # heapq
        exts.append( Extension("heapq", ["heapqmodule.c"]) )
        # operator.add() and similar goodies
        exts.append( Extension('operator', ['operator.c']) )
        # Python C API test module
        exts.append( Extension('_testcapi', ['_testcapimodule.c']) )
        # static Unicode character database
        if have_unicode:
            exts.append( Extension('unicodedata', ['unicodedata.c']) )
        # access to ISO C locale support
        data = open('pyconfig.h').read()
        m = re.search(r"#s*define\s+WITH_LIBINTL\s+1\s*", data)
        if m is not None:
            locale_libs = ['intl']
        else:
            locale_libs = []
        exts.append( Extension('_locale', ['_localemodule.c'],
                               libraries=locale_libs ) )

        # Modules with some UNIX dependencies -- on by default:
        # (If you have a really backward UNIX, select and socket may not be
        # supported...)

        # fcntl(2) and ioctl(2)
        exts.append( Extension('fcntl', ['fcntlmodule.c']) )
        if platform not in ['mac']:
                # pwd(3)
            exts.append( Extension('pwd', ['pwdmodule.c']) )
            # grp(3)
            exts.append( Extension('grp', ['grpmodule.c']) )
        # select(2); not on ancient System V
        exts.append( Extension('select', ['selectmodule.c']) )

        # The md5 module implements the RSA Data Security, Inc. MD5
        # Message-Digest Algorithm, described in RFC 1321.  The
        # necessary files md5c.c and md5.h are included here.
        exts.append( Extension('md5', ['md5module.c', 'md5c.c']) )

        # The sha module implements the SHA checksum algorithm.
        # (NIST's Secure Hash Algorithm.)
        exts.append( Extension('sha', ['shamodule.c']) )

        # Helper module for various ascii-encoders
        exts.append( Extension('binascii', ['binascii.c']) )

        # Fred Drake's interface to the Python parser
        exts.append( Extension('parser', ['parsermodule.c']) )

        # cStringIO and cPickle
        exts.append( Extension('cStringIO', ['cStringIO.c']) )
        exts.append( Extension('cPickle', ['cPickle.c']) )

        # Memory-mapped files (also works on Win32).
        if platform not in ['atheos', 'mac']:
            exts.append( Extension('mmap', ['mmapmodule.c']) )

        # Lance Ellinghaus's modules:
        # enigma-inspired encryption
        exts.append( Extension('rotor', ['rotormodule.c']) )
        if platform not in ['mac']:
            # syslog daemon interface
            exts.append( Extension('syslog', ['syslogmodule.c']) )

        # George Neville-Neil's timing module:
        exts.append( Extension('timing', ['timingmodule.c']) )

        #
        # Here ends the simple stuff.  From here on, modules need certain
        # libraries, are platform-specific, or present other surprises.
        #

        # Multimedia modules
        # These don't work for 64-bit platforms!!!
        # These represent audio samples or images as strings:

        # Disabled on 64-bit platforms
        if sys.maxint != 9223372036854775807L:
            # Operations on audio samples
            exts.append( Extension('audioop', ['audioop.c']) )
            # Operations on images
            exts.append( Extension('imageop', ['imageop.c']) )
            # Read SGI RGB image files (but coded portably)
            exts.append( Extension('rgbimg', ['rgbimgmodule.c']) )

        # readline
        if self.compiler.find_library_file(lib_dirs, 'readline'):
            readline_libs = ['readline']
            if self.compiler.find_library_file(lib_dirs,
                                                 'ncurses'):
                readline_libs.append('ncurses')
            elif self.compiler.find_library_file(lib_dirs, 'curses'):
                readline_libs.append('curses')
            elif self.compiler.find_library_file(lib_dirs +
                                               ['/usr/lib/termcap'],
                                               'termcap'):
                readline_libs.append('termcap')
            exts.append( Extension('readline', ['readline.c'],
                                   library_dirs=['/usr/lib/termcap'],
                                   libraries=readline_libs) )
        if platform not in ['mac']:
            # crypt module.

            if self.compiler.find_library_file(lib_dirs, 'crypt'):
                libs = ['crypt']
            else:
                libs = []
            exts.append( Extension('crypt', ['cryptmodule.c'], libraries=libs) )

        # CSV files
        exts.append( Extension('_csv', ['_csv.c']) )

        # socket(2)
        exts.append( Extension('_socket', ['socketmodule.c'],
                               depends = ['socketmodule.h']) )
        # Detect SSL support for the socket module (via _ssl)
        ssl_incs = find_file('openssl/ssl.h', inc_dirs,
                             ['/usr/local/ssl/include',
                              '/usr/contrib/ssl/include/'
                             ]
                             )
        if ssl_incs is not None:
            krb5_h = find_file('krb5.h', inc_dirs,
                               ['/usr/kerberos/include'])
            if krb5_h:
                ssl_incs += krb5_h
        ssl_libs = find_library_file(self.compiler, 'ssl',lib_dirs,
                                     ['/usr/local/ssl/lib',
                                      '/usr/contrib/ssl/lib/'
                                     ] )

        if (ssl_incs is not None and
            ssl_libs is not None):
            exts.append( Extension('_ssl', ['_ssl.c'],
                                   include_dirs = ssl_incs,
                                   library_dirs = ssl_libs,
                                   libraries = ['ssl', 'crypto'],
                                   depends = ['socketmodule.h']), )

        # Modules that provide persistent dictionary-like semantics.  You will
        # probably want to arrange for at least one of them to be available on
        # your machine, though none are defined by default because of library
        # dependencies.  The Python module anydbm.py provides an
        # implementation independent wrapper for these; dumbdbm.py provides
        # similar functionality (but slower of course) implemented in Python.

        # Sleepycat Berkeley DB interface.  http://www.sleepycat.com
        #
        # This requires the Sleepycat DB code. The earliest supported version
        # of that library is 3.1, the latest supported version is 4.2.  A list
        # of available releases can be found at
        #
        # http://www.sleepycat.com/update/index.html
        #
        # NOTE: 3.1 is only partially supported; expect the extended bsddb module
        # test suite to show failures due to some missing methods and behaviours
        # in BerkeleyDB 3.1.

        # when sorted in reverse order, keys for this dict must appear in the
        # order you wish to search - e.g., search for db4 before db3
        db_try_this = {
            'db4': {'libs': ('db-4.2', 'db42', 'db-4.1', 'db41', 'db-4.0', 'db4',),
                    'libdirs': ('/usr/local/BerkeleyDB.4.2/lib',
                                '/usr/local/BerkeleyDB.4.1/lib',
                                '/usr/local/BerkeleyDB.4.0/lib',
                                '/usr/local/lib',
                                '/opt/sfw',
                                '/sw/lib',
                                ),
                    'incdirs': ('/usr/local/BerkeleyDB.4.2/include',
                                '/usr/local/include/db42',
                                '/usr/local/BerkeleyDB.4.1/include',
                                '/usr/local/include/db41',
                                '/usr/local/BerkeleyDB.4.0/include',
                                '/usr/local/include/db4',
                                '/opt/sfw/include/db4',
                                '/sw/include/db4',
                                '/usr/include/db4',
                                )},
            'db3': {'libs': ('db-3.3', 'db-3.2', 'db-3.1', 'db3',),
                    'libdirs': ('/usr/local/BerkeleyDB.3.3/lib',
                                '/usr/local/BerkeleyDB.3.2/lib',
                                '/usr/local/BerkeleyDB.3.1/lib',
                                '/usr/local/lib',
                                '/opt/sfw/lib',
                                '/sw/lib',
                                ),
                    'incdirs': ('/usr/local/BerkeleyDB.3.3/include',
                                '/usr/local/BerkeleyDB.3.2/include',
                                '/usr/local/BerkeleyDB.3.1/include',
                                '/usr/local/include/db3',
                                '/opt/sfw/include/db3',
                                '/sw/include/db3',
                                '/usr/include/db3',
                                )},
            }

        db_search_order = db_try_this.keys()
        db_search_order.sort()
        db_search_order.reverse()

        class found(Exception): pass
        try:
            # See whether there is a Sleepycat header in the standard
            # search path.
            std_dbinc = None
            for d in inc_dirs:
                f = os.path.join(d, "db.h")
                if os.path.exists(f):
                    f = open(f).read()
                    m = re.search(r"#define\WDB_VERSION_MAJOR\W([1-9]+)", f)
                    if m:
                        std_dbinc = 'db' + m.group(1)
            for dbkey in db_search_order:
                dbd = db_try_this[dbkey]
                for dblib in dbd['libs']:
                    # Prefer version-specific includes over standard
                    # include locations.
                    db_incs = find_file('db.h', [], dbd['incdirs'])
                    dblib_dir = find_library_file(self.compiler,
                                                  dblib,
                                                  lib_dirs,
                                                  list(dbd['libdirs']))
                    if (db_incs or dbkey == std_dbinc) and \
                           dblib_dir is not None:
                        dblibs = [dblib]
                        raise found
        except found:
            dblibs = [dblib]
            # A default source build puts Berkeley DB in something like
            # /usr/local/Berkeley.3.3 and the lib dir under that isn't
            # normally on ld.so's search path, unless the sysadmin has hacked
            # /etc/ld.so.conf.  We add the directory to runtime_library_dirs
            # so the proper -R/--rpath flags get passed to the linker.  This
            # is usually correct and most trouble free, but may cause problems
            # in some unusual system configurations (e.g. the directory is on
            # an NFS server that goes away).
            exts.append(Extension('_bsddb', ['_bsddb.c'],
                                  library_dirs=dblib_dir,
                                  runtime_library_dirs=dblib_dir,
                                  include_dirs=db_incs,
                                  libraries=dblibs))
        else:
            db_incs = None
            dblibs = []
            dblib_dir = None


        # Look for Berkeley db 1.85.   Note that it is built as a different
        # module name so it can be included even when later versions are
        # available.  A very restrictive search is performed to avoid
        # accidentally building this module with a later version of the
        # underlying db library.  May BSD-ish Unixes incorporate db 1.85
        # symbols into libc and place the include file in /usr/include.
        f = "/usr/include/db.h"
        if os.path.exists(f):
            data = open(f).read()
            m = re.search(r"#s*define\s+HASHVERSION\s+2\s*", data)
            if m is not None:
                # bingo - old version used hash file format version 2
                ### XXX this should be fixed to not be platform-dependent
                ### but I don't have direct access to an osf1 platform and
                ### seemed to be muffing the search somehow
                libraries = platform == "osf1" and ['db'] or None
                if libraries is not None:
                    exts.append(Extension('bsddb185', ['bsddbmodule.c'],
                                          libraries=libraries))
                else:
                    exts.append(Extension('bsddb185', ['bsddbmodule.c']))

        # The standard Unix dbm module:
        if platform not in ['cygwin']:
            if find_file("ndbm.h", inc_dirs, []) is not None:
                # Some systems have -lndbm, others don't
                if self.compiler.find_library_file(lib_dirs, 'ndbm'):
                    ndbm_libs = ['ndbm']
                else:
                    ndbm_libs = []
                exts.append( Extension('dbm', ['dbmmodule.c'],
                                       define_macros=[('HAVE_NDBM_H',None)],
                                       libraries = ndbm_libs ) )
            elif (self.compiler.find_library_file(lib_dirs, 'gdbm')
                  and find_file("gdbm/ndbm.h", inc_dirs, []) is not None):
                exts.append( Extension('dbm', ['dbmmodule.c'],
                                       define_macros=[('HAVE_GDBM_NDBM_H',None)],
                                       libraries = ['gdbm'] ) )
            elif db_incs is not None:
                exts.append( Extension('dbm', ['dbmmodule.c'],
                                       library_dirs=dblib_dir,
                                       runtime_library_dirs=dblib_dir,
                                       include_dirs=db_incs,
                                       define_macros=[('HAVE_BERKDB_H',None),
                                                      ('DB_DBM_HSEARCH',None)],
                                       libraries=dblibs))

        # Anthony Baxter's gdbm module.  GNU dbm(3) will require -lgdbm:
        if (self.compiler.find_library_file(lib_dirs, 'gdbm')):
            exts.append( Extension('gdbm', ['gdbmmodule.c'],
                                   libraries = ['gdbm'] ) )

        # The mpz module interfaces to the GNU Multiple Precision library.
        # You need to ftp the GNU MP library.
        # This was originally written and tested against GMP 1.2 and 1.3.2.
        # It has been modified by Rob Hooft to work with 2.0.2 as well, but I
        # haven't tested it recently, and it definitely doesn't work with
        # GMP 4.0.  For more complete modules, refer to
        # http://gmpy.sourceforge.net and
        # http://www.egenix.com/files/python/mxNumber.html

        # A compatible MP library unencumbered by the GPL also exists.  It was
        # posted to comp.sources.misc in volume 40 and is widely available from
        # FTP archive sites. One URL for it is:
        # ftp://gatekeeper.dec.com/.b/usenet/comp.sources.misc/volume40/fgmp/part01.Z

        if (self.compiler.find_library_file(lib_dirs, 'gmp')):
            exts.append( Extension('mpz', ['mpzmodule.c'],
                                   libraries = ['gmp'] ) )


        # Unix-only modules
        if platform not in ['mac', 'win32']:
            # Steen Lumholt's termios module
            exts.append( Extension('termios', ['termios.c']) )
            # Jeremy Hylton's rlimit interface
            if platform not in ['atheos']:
                exts.append( Extension('resource', ['resource.c']) )

            # Sun yellow pages. Some systems have the functions in libc.
            if platform not in ['cygwin', 'atheos']:
                if (self.compiler.find_library_file(lib_dirs, 'nsl')):
                    libs = ['nsl']
                else:
                    libs = []
                exts.append( Extension('nis', ['nismodule.c'],
                                       libraries = libs) )

        # Curses support, requring the System V version of curses, often
        # provided by the ncurses library.
        if platform == 'sunos4':
            inc_dirs += ['/usr/5include']
            lib_dirs += ['/usr/5lib']

        if (self.compiler.find_library_file(lib_dirs, 'ncurses')):
            curses_libs = ['ncurses']
            exts.append( Extension('_curses', ['_cursesmodule.c'],
                                   libraries = curses_libs) )
        elif (self.compiler.find_library_file(lib_dirs, 'curses')
              and platform != 'darwin'):
                # OSX has an old Berkeley curses, not good enough for
                # the _curses module.
            if (self.compiler.find_library_file(lib_dirs, 'terminfo')):
                curses_libs = ['curses', 'terminfo']
            elif (self.compiler.find_library_file(lib_dirs, 'termcap')):
                curses_libs = ['curses', 'termcap']
            else:
                curses_libs = ['curses']

            exts.append( Extension('_curses', ['_cursesmodule.c'],
                                   libraries = curses_libs) )

        # If the curses module is enabled, check for the panel module
        if (module_enabled(exts, '_curses') and
            self.compiler.find_library_file(lib_dirs, 'panel')):
            exts.append( Extension('_curses_panel', ['_curses_panel.c'],
                                   libraries = ['panel'] + curses_libs) )


        # Andrew Kuchling's zlib module.  Note that some versions of zlib
        # 1.1.3 have security problems.  See CERT Advisory CA-2002-07:
        # http://www.cert.org/advisories/CA-2002-07.html
        #
        # zlib 1.1.4 is fixed, but at least one vendor (RedHat) has decided to
        # patch its zlib 1.1.3 package instead of upgrading to 1.1.4.  For
        # now, we still accept 1.1.3, because we think it's difficult to
        # exploit this in Python, and we'd rather make it RedHat's problem
        # than our problem <wink>.
        #
        # You can upgrade zlib to version 1.1.4 yourself by going to
        # http://www.gzip.org/zlib/
        zlib_inc = find_file('zlib.h', [], inc_dirs)
        if zlib_inc is not None:
            zlib_h = zlib_inc[0] + '/zlib.h'
            version = '"0.0.0"'
            version_req = '"1.1.3"'
            fp = open(zlib_h)
            while 1:
                line = fp.readline()
                if not line:
                    break
                if line.startswith('#define ZLIB_VERSION'):
                    version = line.split()[2]
                    break
            if version >= version_req:
                if (self.compiler.find_library_file(lib_dirs, 'z')):
                    exts.append( Extension('zlib', ['zlibmodule.c'],
                                           libraries = ['z']) )

        # Gustavo Niemeyer's bz2 module.
        if (self.compiler.find_library_file(lib_dirs, 'bz2')):
            exts.append( Extension('bz2', ['bz2module.c'],
                                   libraries = ['bz2']) )

        # Interface to the Expat XML parser
        #
        # Expat was written by James Clark and is now maintained by a
        # group of developers on SourceForge; see www.libexpat.org for
        # more information.  The pyexpat module was written by Paul
        # Prescod after a prototype by Jack Jansen.  The Expat source
        # is included in Modules/expat/.  Usage of a system
        # shared libexpat.so/expat.dll is not advised.
        #
        # More information on Expat can be found at www.libexpat.org.
        #
        if sys.byteorder == "little":
            xmlbo = "1234"
        else:
            xmlbo = "4321"
        expatinc = os.path.join(os.getcwd(), srcdir, 'Modules', 'expat')
        define_macros = [
            ('XML_NS', '1'),
            ('XML_DTD', '1'),
            ('BYTEORDER', xmlbo),
            ('XML_CONTEXT_BYTES','1024'),
            ]
        config_h = sysconfig.get_config_h_filename()
        config_h_vars = sysconfig.parse_config_h(open(config_h))
        for feature_macro in ['HAVE_MEMMOVE', 'HAVE_BCOPY']:
            if config_h_vars.has_key(feature_macro):
                define_macros.append((feature_macro, '1'))
        exts.append(Extension('pyexpat',
                              define_macros = define_macros,
                              include_dirs = [expatinc],
                              sources = ['pyexpat.c',
                                         'expat/xmlparse.c',
                                         'expat/xmlrole.c',
                                         'expat/xmltok.c',
                                         ],
                              ))

        # Dynamic loading module
        if sys.maxint == 0x7fffffff:
            # This requires sizeof(int) == sizeof(long) == sizeof(char*)
            dl_inc = find_file('dlfcn.h', [], inc_dirs)
            if (dl_inc is not None) and (platform not in ['atheos', 'darwin']):
                exts.append( Extension('dl', ['dlmodule.c']) )

        # Platform-specific libraries
        if platform == 'linux2':
            # Linux-specific modules
            exts.append( Extension('linuxaudiodev', ['linuxaudiodev.c']) )

        if platform in ('linux2', 'freebsd4'):
            exts.append( Extension('ossaudiodev', ['ossaudiodev.c']) )

        if platform == 'sunos5':
            # SunOS specific modules
            exts.append( Extension('sunaudiodev', ['sunaudiodev.c']) )

        if platform == 'darwin':
            # Mac OS X specific modules.
            exts.append( Extension('_CF', ['cf/_CFmodule.c', 'cf/pycfbridge.c'],
                        extra_link_args=['-framework', 'CoreFoundation']) )

            exts.append( Extension('ColorPicker', ['ColorPickermodule.c'],
                        extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('autoGIL', ['autoGIL.c'],
                        extra_link_args=['-framework', 'CoreFoundation']) )
            exts.append( Extension('gestalt', ['gestaltmodule.c'],
                        extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('MacOS', ['macosmodule.c'],
                        extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('OSATerminology', ['OSATerminology.c'],
                        extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('icglue', ['icgluemodule.c'],
                        extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Res', ['res/_Resmodule.c'],
                        extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Snd', ['snd/_Sndmodule.c'],
                        extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('Nav', ['Nav.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_AE', ['ae/_AEmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_AH', ['ah/_AHmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_App', ['app/_Appmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_CarbonEvt', ['carbonevt/_CarbonEvtmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_CG', ['cg/_CGmodule.c'],
                    extra_link_args=['-framework', 'ApplicationServices']) )
            exts.append( Extension('_Cm', ['cm/_Cmmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Ctl', ['ctl/_Ctlmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Dlg', ['dlg/_Dlgmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Drag', ['drag/_Dragmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Evt', ['evt/_Evtmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_File', ['file/_Filemodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Folder', ['folder/_Foldermodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Fm', ['fm/_Fmmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Help', ['help/_Helpmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Icn', ['icn/_Icnmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_IBCarbon', ['ibcarbon/_IBCarbon.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_List', ['list/_Listmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Menu', ['menu/_Menumodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Mlte', ['mlte/_Mltemodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Qd', ['qd/_Qdmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Qdoffs', ['qdoffs/_Qdoffsmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_Qt', ['qt/_Qtmodule.c'],
                    extra_link_args=['-framework', 'QuickTime',
                                     '-framework', 'Carbon']) )
            exts.append( Extension('_Scrap', ['scrap/_Scrapmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            exts.append( Extension('_TE', ['te/_TEmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )
            # As there is no standardized place (yet) to put
            # user-installed Mac libraries on OSX, we search for "waste"
            # in parent directories of the Python source tree. You
            # should put a symlink to your Waste installation in the
            # same folder as your python source tree.  Or modify the
            # next few lines:-)
            waste_incs = find_file("WASTE.h", [],
                    ['../'*n + 'waste/C_C++ Headers' for n in (0,1,2,3,4)])
            waste_libs = find_library_file(self.compiler, "WASTE", [],
                    ["../"*n + "waste/Static Libraries" for n in (0,1,2,3,4)])
            if waste_incs != None and waste_libs != None:
                (srcdir,) = sysconfig.get_config_vars('srcdir')
                exts.append( Extension('waste',
                               ['waste/wastemodule.c'] + [
                                os.path.join(srcdir, d) for d in
                                'Mac/Wastemods/WEObjectHandlers.c',
                                'Mac/Wastemods/WETabHooks.c',
                                'Mac/Wastemods/WETabs.c'
                               ],
                               include_dirs = waste_incs + [os.path.join(srcdir, 'Mac/Wastemods')],
                               library_dirs = waste_libs,
                               libraries = ['WASTE'],
                               extra_link_args = ['-framework', 'Carbon'],
                ) )
            exts.append( Extension('_Win', ['win/_Winmodule.c'],
                    extra_link_args=['-framework', 'Carbon']) )

        self.extensions.extend(exts)

        # Call the method for detecting whether _tkinter can be compiled
        self.detect_tkinter(inc_dirs, lib_dirs)

    def detect_tkinter_darwin(self, inc_dirs, lib_dirs):
        # The _tkinter module, using frameworks. Since frameworks are quite
        # different the UNIX search logic is not sharable.
        from os.path import join, exists
        framework_dirs = [
            '/System/Library/Frameworks/',
            '/Library/Frameworks',
            join(os.getenv('HOME'), '/Library/Frameworks')
        ]

        # Find the directory that contains the Tcl.framwork and Tk.framework
        # bundles.
        # XXX distutils should support -F!
        for F in framework_dirs:
            # both Tcl.framework and Tk.framework should be present
            for fw in 'Tcl', 'Tk':
                if not exists(join(F, fw + '.framework')):
                    break
            else:
                # ok, F is now directory with both frameworks. Continure
                # building
                break
        else:
            # Tk and Tcl frameworks not found. Normal "unix" tkinter search
            # will now resume.
            return 0

        # For 8.4a2, we must add -I options that point inside the Tcl and Tk
        # frameworks. In later release we should hopefully be able to pass
        # the -F option to gcc, which specifies a framework lookup path.
        #
        include_dirs = [
            join(F, fw + '.framework', H)
            for fw in 'Tcl', 'Tk'
            for H in 'Headers', 'Versions/Current/PrivateHeaders'
        ]

        # For 8.4a2, the X11 headers are not included. Rather than include a
        # complicated search, this is a hard-coded path. It could bail out
        # if X11 libs are not found...
        include_dirs.append('/usr/X11R6/include')
        frameworks = ['-framework', 'Tcl', '-framework', 'Tk']

        ext = Extension('_tkinter', ['_tkinter.c', 'tkappinit.c'],
                        define_macros=[('WITH_APPINIT', 1)],
                        include_dirs = include_dirs,
                        libraries = [],
                        extra_compile_args = frameworks,
                        extra_link_args = frameworks,
                        )
        self.extensions.append(ext)
        return 1


    def detect_tkinter(self, inc_dirs, lib_dirs):
        # The _tkinter module.

        # Rather than complicate the code below, detecting and building
        # AquaTk is a separate method. Only one Tkinter will be built on
        # Darwin - either AquaTk, if it is found, or X11 based Tk.
        platform = self.get_platform()
        if platform == 'darwin' and \
           self.detect_tkinter_darwin(inc_dirs, lib_dirs):
            return

        # Assume we haven't found any of the libraries or include files
        # The versions with dots are used on Unix, and the versions without
        # dots on Windows, for detection by cygwin.
        tcllib = tklib = tcl_includes = tk_includes = None
        for version in ['8.4', '84', '8.3', '83', '8.2',
                        '82', '8.1', '81', '8.0', '80']:
            tklib = self.compiler.find_library_file(lib_dirs, 'tk' + version)
            tcllib = self.compiler.find_library_file(lib_dirs, 'tcl' + version)
            if tklib and tcllib:
                # Exit the loop when we've found the Tcl/Tk libraries
                break

        # Now check for the header files
        if tklib and tcllib:
            # Check for the include files on Debian, where
            # they're put in /usr/include/{tcl,tk}X.Y
            debian_tcl_include = [ '/usr/include/tcl' + version ]
            debian_tk_include =  [ '/usr/include/tk'  + version ] + \
                                 debian_tcl_include
            tcl_includes = find_file('tcl.h', inc_dirs, debian_tcl_include)
            tk_includes = find_file('tk.h', inc_dirs, debian_tk_include)

        if (tcllib is None or tklib is None or
            tcl_includes is None or tk_includes is None):
            # Something's missing, so give up
            return

        # OK... everything seems to be present for Tcl/Tk.

        include_dirs = [] ; libs = [] ; defs = [] ; added_lib_dirs = []
        for dir in tcl_includes + tk_includes:
            if dir not in include_dirs:
                include_dirs.append(dir)

        # Check for various platform-specific directories
        if platform == 'sunos5':
            include_dirs.append('/usr/openwin/include')
            added_lib_dirs.append('/usr/openwin/lib')
        elif os.path.exists('/usr/X11R6/include'):
            include_dirs.append('/usr/X11R6/include')
            added_lib_dirs.append('/usr/X11R6/lib')
        elif os.path.exists('/usr/X11R5/include'):
            include_dirs.append('/usr/X11R5/include')
            added_lib_dirs.append('/usr/X11R5/lib')
        else:
            # Assume default location for X11
            include_dirs.append('/usr/X11/include')
            added_lib_dirs.append('/usr/X11/lib')

        # If Cygwin, then verify that X is installed before proceeding
        if platform == 'cygwin':
            x11_inc = find_file('X11/Xlib.h', [], include_dirs)
            if x11_inc is None:
                return

        # Check for BLT extension
        if self.compiler.find_library_file(lib_dirs + added_lib_dirs,
                                           'BLT8.0'):
            defs.append( ('WITH_BLT', 1) )
            libs.append('BLT8.0')
        elif self.compiler.find_library_file(lib_dirs + added_lib_dirs,
                                           'BLT'):
            defs.append( ('WITH_BLT', 1) )
            libs.append('BLT')

        # Add the Tcl/Tk libraries
        libs.append('tk'+ version)
        libs.append('tcl'+ version)

        if platform in ['aix3', 'aix4']:
            libs.append('ld')

        # Finally, link with the X11 libraries (not appropriate on cygwin)
        if platform != "cygwin":
            libs.append('X11')

        ext = Extension('_tkinter', ['_tkinter.c', 'tkappinit.c'],
                        define_macros=[('WITH_APPINIT', 1)] + defs,
                        include_dirs = include_dirs,
                        libraries = libs,
                        library_dirs = added_lib_dirs,
                        )
        self.extensions.append(ext)

##         # Uncomment these lines if you want to play with xxmodule.c
##         ext = Extension('xx', ['xxmodule.c'])
##         self.extensions.append(ext)

        # XXX handle these, but how to detect?
        # *** Uncomment and edit for PIL (TkImaging) extension only:
        #       -DWITH_PIL -I../Extensions/Imaging/libImaging  tkImaging.c \
        # *** Uncomment and edit for TOGL extension only:
        #       -DWITH_TOGL togl.c \
        # *** Uncomment these for TOGL extension only:
        #       -lGL -lGLU -lXext -lXmu \

class PyBuildInstall(install):
    # Suppress the warning about installation into the lib_dynload
    # directory, which is not in sys.path when running Python during
    # installation:
    def initialize_options (self):
        install.initialize_options(self)
        self.warn_dir=0

class PyBuildInstallLib(install_lib):
    # Do exactly what install_lib does but make sure correct access modes get
    # set on installed directories and files. All installed files with get
    # mode 644 unless they are a shared library in which case they will get
    # mode 755. All installed directories will get mode 755.

    so_ext = sysconfig.get_config_var("SO")

    def install(self):
        outfiles = install_lib.install(self)
        self.set_file_modes(outfiles, 0644, 0755)
        self.set_dir_modes(self.install_dir, 0755)
        return outfiles

    def set_file_modes(self, files, defaultMode, sharedLibMode):
        if not self.is_chmod_supported(): return
        if not files: return

        for filename in files:
            if os.path.islink(filename): continue
            mode = defaultMode
            if filename.endswith(self.so_ext): mode = sharedLibMode
            log.info("changing mode of %s to %o", filename, mode)
            if not self.dry_run: os.chmod(filename, mode)

    def set_dir_modes(self, dirname, mode):
        if not self.is_chmod_supported(): return
        os.path.walk(dirname, self.set_dir_modes_visitor, mode)

    def set_dir_modes_visitor(self, mode, dirname, names):
        if os.path.islink(dirname): return
        log.info("changing mode of %s to %o", dirname, mode)
        if not self.dry_run: os.chmod(dirname, mode)

    def is_chmod_supported(self):
        return hasattr(os, 'chmod')

SUMMARY = """
Python is an interpreted, interactive, object-oriented programming
language. It is often compared to Tcl, Perl, Scheme or Java.

Python combines remarkable power with very clear syntax. It has
modules, classes, exceptions, very high level dynamic data types, and
dynamic typing. There are interfaces to many system calls and
libraries, as well as to various windowing systems (X11, Motif, Tk,
Mac, MFC). New built-in modules are easily written in C or C++. Python
is also usable as an extension language for applications that need a
programmable interface.

The Python implementation is portable: it runs on many brands of UNIX,
on Windows, DOS, OS/2, Mac, Amiga... If your favorite system isn't
listed here, it may still be supported, if there's a C compiler for
it. Ask around on comp.lang.python -- or just try compiling Python
yourself.
"""

CLASSIFIERS = """
Development Status :: 3 - Alpha
Development Status :: 6 - Mature
License :: OSI Approved :: Python Software Foundation License
Natural Language :: English
Programming Language :: C
Programming Language :: Python
Topic :: Software Development
"""

def main():
    # turn off warnings when deprecated modules are imported
    import warnings
    warnings.filterwarnings("ignore",category=DeprecationWarning)
    setup(# PyPI Metadata (PEP 301)
          name = "Python",
          version = sys.version.split()[0],
          url = "http://www.python.org/%s" % sys.version[:3],
          maintainer = "Guido van Rossum and the Python community",
          maintainer_email = "python-dev@python.org",
          description = "A high-level object-oriented programming language",
          long_description = SUMMARY.strip(),
          license = "PSF license",
          classifiers = filter(None, CLASSIFIERS.split("\n")),
          platforms = ["Many"],

          # Build info
          cmdclass = {'build_ext':PyBuildExt, 'install':PyBuildInstall,
                      'install_lib':PyBuildInstallLib},
          # The struct module is defined here, because build_ext won't be
          # called unless there's at least one extension module defined.
          ext_modules=[Extension('struct', ['structmodule.c'])],

          # Scripts to install
          scripts = ['Tools/scripts/pydoc', 'Tools/scripts/idle']
        )

# --install-platlib
if __name__ == '__main__':
    main()
