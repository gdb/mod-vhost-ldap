# Copyright (C) 2001,2002 Python Software Foundation
# Author: barry@zope.com (Barry Warsaw)

"""A package for parsing, handling, and generating email messages.
"""

__version__ = '2.4'

__all__ = ['Charset',
           'Encoders',
           'Errors',
           'Generator',
           'Header',
           'Iterators',
           'MIMEAudio',
           'MIMEBase',
           'MIMEImage',
           'MIMEMessage',
           'MIMEText',
           'Message',
           'Parser',
           'Utils',
           'base64MIME',
           'quopriMIME',
           'message_from_string',
           'message_from_file',
           ]


try:
    True, False
except NameError:
    True = 1
    False = 0



# Some convenience routines.  Don't import Parser and Message as side-effects
# of importing email since those cascadingly import most of the rest of the
# email package.
def message_from_string(s, _class=None, strict=False):
    """Parse a string into a Message object model.

    Optional _class and strict are passed to the Parser constructor.
    """
    from email.Parser import Parser
    if _class is None:
        from email.Message import Message
        _class = Message
    return Parser(_class, strict=strict).parsestr(s)

def message_from_file(fp, _class=None, strict=False):
    """Read a file and parse its contents into a Message object model.

    Optional _class and strict are passed to the Parser constructor.
    """
    from email.Parser import Parser
    if _class is None:
        from email.Message import Message
        _class = Message
    return Parser(_class, strict=strict).parse(fp)
