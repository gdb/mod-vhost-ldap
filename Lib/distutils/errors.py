"""distutils.errors

Provides exceptions used by the Distutils modules.  Note that Distutils
modules may raise standard exceptions; in particular, SystemExit is
usually raised for errors that are obviously the end-user's fault
(eg. bad command-line arguments).

This module safe to use in "from ... import *" mode; it only exports
symbols whose names start with "Distutils" and end with "Error"."""

# created 1999/03/03, Greg Ward

__revision__ = "$Id$"

import types

if type (RuntimeError) is types.ClassType:

    class DistutilsError (Exception):
        """The root of all Distutils evil."""
        pass

    class DistutilsModuleError (DistutilsError):
        """Unable to load an expected module, or to find an expected class
        within some module (in particular, command modules and classes)."""
        pass

    class DistutilsClassError (DistutilsError):
        """Some command class (or possibly distribution class, if anyone
        feels a need to subclass Distribution) is found not to be holding
        up its end of the bargain, ie. implementing some part of the
        "command "interface."""
        pass

    class DistutilsGetoptError (DistutilsError):
        """The option table provided to 'fancy_getopt()' is bogus."""
        pass

    class DistutilsArgError (DistutilsError):
        """Raised by fancy_getopt in response to getopt.error -- ie. an
        error in the command line usage."""
        pass

    class DistutilsFileError (DistutilsError):
        """Any problems in the filesystem: expected file not found, etc.
        Typically this is for problems that we detect before IOError or
        OSError could be raised."""
        pass

    class DistutilsOptionError (DistutilsError):
        """Syntactic/semantic errors in command options, such as use of
        mutually conflicting options, or inconsistent options,
        badly-spelled values, etc.  No distinction is made between option
        values originating in the setup script, the command line, config
        files, or what-have-you -- but if we *know* something originated in
        the setup script, we'll raise DistutilsSetupError instead."""
        pass

    class DistutilsSetupError (DistutilsError):
        """For errors that can be definitely blamed on the setup script,
        such as invalid keyword arguments to 'setup()'."""
        pass

    class DistutilsPlatformError (DistutilsError):
        """We don't know how to do something on the current platform (but
        we do know how to do it on some platform) -- eg. trying to compile
        C files on a platform not supported by a CCompiler subclass."""
        pass

    class DistutilsExecError (DistutilsError):
        """Any problems executing an external program (such as the C
        compiler, when compiling C files)."""
        pass

    class DistutilsInternalError (DistutilsError):
        """Internal inconsistencies or impossibilities (obviously, this
        should never be seen if the code is working!)."""
        pass

# String-based exceptions
else:
    DistutilsError = 'DistutilsError'
    DistutilsModuleError = 'DistutilsModuleError'
    DistutilsClassError = 'DistutilsClassError'
    DistutilsGetoptError = 'DistutilsGetoptError'
    DistutilsArgError = 'DistutilsArgError'
    DistutilsFileError = 'DistutilsFileError'
    DistutilsOptionError = 'DistutilsOptionError'
    DistutilsPlatformError = 'DistutilsPlatformError'
    DistutilsExecError = 'DistutilsExecError'
    DistutilsInternalError = 'DistutilsInternalError'
    
del types
