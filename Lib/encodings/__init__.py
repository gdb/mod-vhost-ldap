""" Standard "encodings" Package

    Standard Python encoding modules are stored in this package
    directory.

    Codec modules must have names corresponding to standard lower-case
    encoding names. Hyphens are automatically converted to
    underscores, e.g. 'utf-8' is looked up as module utf_8.

    Each codec module must export the following interface:

    * getregentry() -> (encoder, decoder, stream_reader, stream_writer)
    The getregentry() API must return callable objects which adhere to
    the Python Codec Interface Standard.

    In addition, a module may optionally also define the following
    APIs which are then used by the package's codec search function:

    * getaliases() -> sequence of encoding name strings to use as aliases

    Alias names returned by getaliases() must be lower-case.


Written by Marc-Andre Lemburg (mal@lemburg.com).

(c) Copyright CNRI, All Rights Reserved. NO WARRANTY.

"""#"

import string,codecs,aliases

_cache = {}
_unkown = '--unkown--'

def search_function(encoding):
    
    # Cache lookup
    entry = _cache.get(encoding,_unkown)
    if entry is not _unkown:
        return entry

    # Import the module
    modname = string.replace(encoding,'-','_')
    modname = aliases.aliases.get(modname,modname)
    try:
        mod = __import__(modname,globals(),locals(),'*')
    except ImportError,why:
        _cache[encoding] = None
        return None
    
    # Now ask the module for the registry entry
    try:
        entry = tuple(mod.getregentry())
    except AttributeError:
        entry = ()
    if len(entry) != 4:
        raise SystemError,\
              'module "%s.%s" failed to register' % \
              (__name__,modname)
    for obj in entry:
        if not callable(obj):
            raise SystemError,\
                  'incompatible codecs in module "%s.%s"' % \
                  (__name__,modname)

    # Cache the encoding and its aliases
    _cache[encoding] = entry
    try:
        codecaliases = mod.getaliases()
    except AttributeError:
        pass
    else:
        for alias in codecaliases:
            _cache[alias] = entry
    return entry

# Register the search_function in the Python codec registry
codecs.register(search_function)
