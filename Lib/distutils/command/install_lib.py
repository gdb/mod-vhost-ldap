# created 1999/03/13, Greg Ward

__revision__ = "$Id$"

import sys, string
from distutils.core import Command
from distutils.util import copy_tree

class install_lib (Command):

    description = "install pure Python modules"

    user_options = [
        ('install-dir=', 'd', "directory to install to"),
        ('build-dir=','b', "build directory (where to install from)"),
        ('compile', 'c', "compile .py to .pyc"),
        ('optimize', 'o', "compile .py to .pyo (optimized)"),
        ]
               

    def initialize_options (self):
        # let the 'install' command dictate our installation directory
        self.install_dir = None
        self.build_dir = None
        self.compile = 1
        self.optimize = 1

    def finalize_options (self):

        # Get all the information we need to install pure Python modules
        # from the umbrella 'install' command -- build (source) directory,
        # install (target) directory, and whether to compile .py files.
        self.set_undefined_options ('install',
                                    ('build_lib', 'build_dir'),
                                    ('install_lib', 'install_dir'),
                                    ('compile_py', 'compile'),
                                    ('optimize_py', 'optimize'))


    def run (self):

        # Make sure we have "built" all pure Python modules first
        self.run_peer ('build_py')

        # Install everything: simply dump the entire contents of the build
        # directory to the installation directory (that's the beauty of
        # having a build directory!)
        outfiles = self.copy_tree (self.build_dir, self.install_dir)
                   
        # (Optionally) compile .py to .pyc
        # XXX hey! we can't control whether we optimize or not; that's up
        # to the invocation of the current Python interpreter (at least
        # according to the py_compile docs).  That sucks.

        if self.compile:
            from py_compile import compile

            for f in outfiles:
                # XXX can't assume this filename mapping! (what if
                # we're running under "python -O"?)

                # only compile the file if it is actually a .py file
                if f[-3:] == '.py':
                    out_fn = string.replace (f, '.py', '.pyc')
                    
                    self.make_file (f, out_fn, compile, (f,),
                                    "byte-compiling %s" % f,
                                    "byte-compilation of %s skipped" % f)
                    
        # XXX ignore self.optimize for now, since we don't really know if
        # we're compiling optimally or not, and couldn't pick what to do
        # even if we did know.  ;-(

    # run ()

# class InstallPy
