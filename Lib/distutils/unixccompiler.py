"""distutils.unixccompiler

Contains the UnixCCompiler class, a subclass of CCompiler that handles
the "typical" Unix-style command-line C compiler:
  * macros defined with -Dname[=value]
  * macros undefined with -Uname
  * include search directories specified with -Idir
  * libraries specified with -lllib
  * library search directories specified with -Ldir
  * compile handled by 'cc' (or similar) executable with -c option:
    compiles .c to .o
  * link static library handled by 'ar' command (possibly with 'ranlib')
  * link shared library handled by 'cc -shared'
"""

# created 1999/07/05, Greg Ward

__rcsid__ = "$Id$"

import string, re
from types import *
from sysconfig import \
     CC, CCSHARED, CFLAGS, OPT, LDSHARED, LDFLAGS, RANLIB, AR, SO
from ccompiler import CCompiler


# XXX Things not currently handled:
#   * optimization/debug/warning flags; we just use whatever's in Python's
#     Makefile and live with it.  Is this adequate?  If not, we might
#     have to have a bunch of subclasses GNUCCompiler, SGICCompiler,
#     SunCCompiler, and I suspect down that road lies madness.
#   * even if we don't know a warning flag from an optimization flag,
#     we need some way for outsiders to feed preprocessor/compiler/linker
#     flags in to us -- eg. a sysadmin might want to mandate certain flags
#     via a site config file, or a user might want to set something for
#     compiling this module distribution only via the setup.py command
#     line, whatever.  As long as these options come from something on the
#     current system, they can be as system-dependent as they like, and we
#     should just happily stuff them into the preprocessor/compiler/linker
#     options and carry on.


class UnixCCompiler (CCompiler):

    # XXX perhaps there should really be *three* kinds of include
    # directories: those built in to the preprocessor, those from Python's
    # Makefiles, and those supplied to {add,set}_include_dirs().  Currently
    # we make no distinction between the latter two at this point; it's all
    # up to the client class to select the include directories to use above
    # and beyond the compiler's defaults.  That is, both the Python include
    # directories and any module- or package-specific include directories
    # are specified via {add,set}_include_dirs(), and there's no way to
    # distinguish them.  This might be a bug.
    
    def __init__ (self,
                  verbose=0,
                  dry_run=0):

        CCompiler.__init__ (self, verbose, dry_run)

        self.preprocess_options = None
        self.compile_options = None

        # Munge CC and OPT together in case there are flags stuck in CC.
        # Note that using these variables from sysconfig immediately makes
        # this module specific to building Python extensions and
        # inappropriate as a general-purpose C compiler front-end.  So sue
        # me.  Note also that we use OPT rather than CFLAGS, because CFLAGS
        # is the flags used to compile Python itself -- not only are there
        # -I options in there, they are the *wrong* -I options.  We'll
        # leave selection of include directories up to the class using
        # UnixCCompiler!

        (self.cc, self.ccflags) = \
            _split_command (CC + ' ' + OPT)
        self.ccflags_shared = string.split (CCSHARED)

        (self.ld_shared, self.ldflags_shared) = \
            _split_command (LDSHARED)


    def compile (self,
                 sources,
                 macros=None,
                 includes=None):

        if macros is None:
            macros = []
        if includes is None:
            includes = []

        if type (macros) is not ListType:
            raise TypeError, \
                  "'macros' (if supplied) must be a list of tuples"
        if type (includes) is not ListType:
            raise TypeError, \
                  "'includes' (if supplied) must be a list of strings"

        pp_opts = _gen_preprocess_options (self.macros + macros,
                                           self.include_dirs + includes)

        # use of ccflags_shared means we're blithely assuming that we're
        # compiling for inclusion in a shared object! (will have to fix
        # this when I add the ability to build a new Python)
        cc_args = ['-c'] + pp_opts + \
                  self.ccflags + self.ccflags_shared + \
                  sources

        # this will change to 'spawn' when I have it!
        #print string.join ([self.cc] + cc_args, ' ')
        self.spawn ([self.cc] + cc_args)


    # XXX punting on 'link_static_lib()' for now -- it might be better for
    # CCompiler to mandate just 'link_binary()' or some such to build a new
    # Python binary; it would then take care of linking in everything
    # needed for the new Python without messing with an intermediate static
    # library.

    def link_shared_lib (self,
                         objects,
                         output_libname,
                         libraries=None,
                         library_dirs=None):
        # XXX should we sanity check the library name? (eg. no
        # slashes)
        self.link_shared_object (objects, "lib%s%s" % (output_libname, SO))


    def link_shared_object (self,
                            objects,
                            output_filename,
                            libraries=None,
                            library_dirs=None):

        if libraries is None:
            libraries = []
        if library_dirs is None:
            library_dirs = []

        lib_opts = _gen_lib_options (self.libraries + libraries,
                                     self.library_dirs + library_dirs)
        ld_args = self.ldflags_shared + lib_opts + \
                  objects + ['-o', output_filename]

        #print string.join ([self.ld_shared] + ld_args, ' ')
        self.spawn ([self.ld_shared] + ld_args)


    def object_filenames (self, source_filenames):
        outnames = []
        for inname in source_filenames:
            outnames.append (re.sub (r'\.(c|C|cc|cxx)$', '.o', inname))
        return outnames

    def shared_object_filename (self, source_filename):
        return re.sub (r'\.(c|C|cc|cxx)$', SO)

    def library_filename (self, libname):
        return "lib%s.a" % libname

    def shared_library_filename (self, libname):
        return "lib%s.so" % libname


# class UnixCCompiler


def _split_command (cmd):
    """Split a command string up into the progam to run (a string) and
       the list of arguments; return them as (cmd, arglist)."""
    args = string.split (cmd)
    return (args[0], args[1:])


def _gen_preprocess_options (macros, includes):

    # XXX it would be nice (mainly aesthetic, and so we don't generate
    # stupid-looking command lines) to go over 'macros' and eliminate
    # redundant definitions/undefinitions (ie. ensure that only the
    # latest mention of a particular macro winds up on the command
    # line).  I don't think it's essential, though, since most (all?)
    # Unix C compilers only pay attention to the latest -D or -U
    # mention of a macro on their command line.  Similar situation for
    # 'includes'.  I'm punting on both for now.  Anyways, weeding out
    # redundancies like this should probably be the province of
    # CCompiler, since the data structures used are inherited from it
    # and therefore common to all CCompiler classes.


    pp_opts = []
    for macro in macros:
        if len (macro) == 1:        # undefine this macro
            pp_opts.append ("-U%s" % macro[0])
        elif len (macro) == 2:
            if macro[1] is None:    # define with no explicit value
                pp_opts.append ("-D%s" % macro[0])
            else:
                # XXX *don't* need to be clever about quoting the
                # macro value here, because we're going to avoid the
                # shell at all costs when we spawn the command!
                pp_opts.append ("-D%s=%s" % macro)

    for dir in includes:
        pp_opts.append ("-I%s" % dir)

    return pp_opts

# _gen_preprocess_options ()


def _gen_lib_options (libraries, library_dirs):

    lib_opts = []

    for dir in library_dirs:
        lib_opts.append ("-L%s" % dir)

    # XXX it's important that we *not* remove redundant library mentions!
    # sometimes you really do have to say "-lfoo -lbar -lfoo" in order to
    # resolve all symbols.  I just hope we never have to say "-lfoo obj.o
    # -lbar" to get things to work -- that's certainly a possibility, but a
    # pretty nasty way to arrange your C code.

    for lib in libraries:
        lib_opts.append ("-l%s" % lib)

    return lib_opts

# _gen_lib_options ()
