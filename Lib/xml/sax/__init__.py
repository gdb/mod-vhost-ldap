"""Simple API for XML (SAX) implementation for Python.

This module provides an implementation of the SAX 2 interface;
information about the Java version of the interface can be found at
http://www.megginson.com/SAX/.  The Python version of the interface is
documented at <...>.

This package contains the following modules:

saxutils -- Implementation of the convenience functions normally used
            to work with SAX.

saxlib -- Implementation of the shared SAX 2 classes.

drv_pyexpat -- Driver that allows use of the Expat parser with the classes
               defined in saxlib.

"""

from handler import *
from expatreader import *
from _exceptions import *
from saxutils import *
from _exceptions import SAXParseException
import xmlreader

def parse( filename_or_stream, handler, errorHandler=ErrorHandler() ):
    parser=ExpatParser()
    parser.setContentHandler( handler )
    parse.setErrorHandler( errorHandler )
    parser.parse( filename_or_stream )

# this may not work yet...Expat doesn't handle buffer inputs
def parseString( string, handler, errorHandler=ErrorHandler() ):
    try:
        import cStringIO
        stringio=cStringIO.StringIO
    except ImportError:
        import StringIO
        stringio=StringIO.StringIO
        
    bufsize=len( string )
    buf=stringio( string )
 
    parser=ExpatParser()
    parser.setContentHandler( handler )
    parse.setErrorHandler( errorHandler )
    parser.parse( buf )

