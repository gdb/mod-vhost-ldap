"""Simple API for XML (SAX) implementation for Python.

This module provides an implementation of the SAX 2 interface;
information about the Java version of the interface can be found at
http://www.megginson.com/SAX/.  The Python version of the interface is
documented at <...>.

This package contains the following modules:

handler -- Base classes and constants which define the SAX 2 API for
           the 'client-side' of SAX for Python.

saxutils -- Implementation of the convenience classes commonly used to
            work with SAX.

xmlreader -- Base classes and constants which define the SAX 2 API for
             the parsers used with SAX for Python.

expatreader -- Driver that allows use of the Expat parser with the
               classes defined in saxlib.

"""

from handler import ContentHandler, ErrorHandler
from _exceptions import SAXException, SAXNotRecognizedException, \
                        SAXParseException, SAXNotSupportedException


def parse(filename_or_stream, handler, errorHandler=ErrorHandler()):
    parser = ExpatParser()
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler)
    parser.parse(filename_or_stream)

def parseString(string, handler, errorHandler=ErrorHandler()):
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO
        
    if errorHandler is None:
        errorHandler = ErrorHandler()
    parser = ExpatParser()
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler)
    parser.parse(StringIO(string))

# this is the parser list used by the make_parser function if no
# alternatives are given as parameters to the function

default_parser_list = ["xml.sax.expatreader"]

import os, string, sys
if os.environ.has_key("PY_SAX_PARSER"):
    default_parser_list = string.split(os.environ["PY_SAX_PARSER"], ",")
del os

_key = "python.xml.sax.parser"
if sys.platform[:4] == "java" and sys.registry.containsKey(_key):
    default_parser_list = string.split(sys.registry.getProperty(_key), ",")
    
    
def make_parser(parser_list = []):
    """Creates and returns a SAX parser.

    Creates the first parser it is able to instantiate of the ones
    given in the list created by doing parser_list +
    default_parser_list.  The lists must contain the names of Python
    modules containing both a SAX parser and a create_parser function."""

    for parser_name in parser_list + default_parser_list:
        try:
            return _create_parser(parser_name)
        except ImportError,e:
            pass

    raise SAXException("No parsers found", None)  
    
# --- Internal utility methods used by make_parser

if sys.platform[ : 4] == "java":
    def _create_parser(parser_name):
        from org.python.core import imp
        drv_module = imp.importName(parser_name, 0, globals())
        return drv_module.create_parser()

else:
    import imp as _imp

    def _rec_find_module(module):
        "Improvement over imp.find_module which finds submodules."
        path=""
        for mod in string.split(module,"."):
            if path == "":
                info = (mod,) + _imp.find_module(mod)
            else:
                info = (mod,) + _imp.find_module(mod, [path])
                
            lastmod = _imp.load_module(*info)

            try:
                path = lastmod.__path__[0]
            except AttributeError, e:
                pass

        return info

    def _create_parser(parser_name):
        info = _rec_find_module(parser_name)
        drv_module = _imp.load_module(*info)
        return drv_module.create_parser()

del sys
