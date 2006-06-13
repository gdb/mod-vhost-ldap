######################################################################
#  This file should be kept compatible with Python 2.3, see PEP 291. #
######################################################################

# The most useful windows datatypes
from ctypes import *

BYTE = c_byte
WORD = c_ushort
DWORD = c_ulong

WCHAR = c_wchar
UINT = c_uint

DOUBLE = c_double

BOOLEAN = BYTE
BOOL = c_long

from ctypes import _SimpleCData
class VARIANT_BOOL(_SimpleCData):
    _type_ = "v"
    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.value)

ULONG = c_ulong
LONG = c_long

# in the windows header files, these are structures.
_LARGE_INTEGER = LARGE_INTEGER = c_longlong
_ULARGE_INTEGER = ULARGE_INTEGER = c_ulonglong

LPCOLESTR = LPOLESTR = OLESTR = c_wchar_p
LPCWSTR = LPWSTR = c_wchar_p
LPCSTR = LPSTR = c_char_p

WPARAM = c_uint
LPARAM = c_long

ATOM = WORD
LANGID = WORD

COLORREF = DWORD
LGRPID = DWORD
LCTYPE = DWORD

LCID = DWORD

################################################################
# HANDLE types
HANDLE = c_ulong # in the header files: void *

HACCEL = HANDLE
HBITMAP = HANDLE
HBRUSH = HANDLE
HCOLORSPACE = HANDLE
HDC = HANDLE
HDESK = HANDLE
HDWP = HANDLE
HENHMETAFILE = HANDLE
HFONT = HANDLE
HGDIOBJ = HANDLE
HGLOBAL = HANDLE
HHOOK = HANDLE
HICON = HANDLE
HINSTANCE = HANDLE
HKEY = HANDLE
HKL = HANDLE
HLOCAL = HANDLE
HMENU = HANDLE
HMETAFILE = HANDLE
HMODULE = HANDLE
HMONITOR = HANDLE
HPALETTE = HANDLE
HPEN = HANDLE
HRGN = HANDLE
HRSRC = HANDLE
HSTR = HANDLE
HTASK = HANDLE
HWINSTA = HANDLE
HWND = HANDLE
SC_HANDLE = HANDLE
SERVICE_STATUS_HANDLE = HANDLE

################################################################
# Some important structure definitions

class RECT(Structure):
    _fields_ = [("left", c_long),
                ("top", c_long),
                ("right", c_long),
                ("bottom", c_long)]
tagRECT = _RECTL = RECTL = RECT

class _SMALL_RECT(Structure):
    _fields_ = [('Left', c_short),
                ('Top', c_short),
                ('Right', c_short),
                ('Bottom', c_short)]
SMALL_RECT = _SMALL_RECT

class _COORD(Structure):
    _fields_ = [('X', c_short),
                ('Y', c_short)]

class POINT(Structure):
    _fields_ = [("x", c_long),
                ("y", c_long)]
tagPOINT = _POINTL = POINTL = POINT

class SIZE(Structure):
    _fields_ = [("cx", c_long),
                ("cy", c_long)]
tagSIZE = SIZEL = SIZE

def RGB(red, green, blue):
    return red + (green << 8) + (blue << 16)

class FILETIME(Structure):
    _fields_ = [("dwLowDateTime", DWORD),
                ("dwHighDateTime", DWORD)]
_FILETIME = FILETIME

class MSG(Structure):
    _fields_ = [("hWnd", HWND),
                ("message", c_uint),
                ("wParam", WPARAM),
                ("lParam", LPARAM),
                ("time", DWORD),
                ("pt", POINT)]
tagMSG = MSG
MAX_PATH = 260

class WIN32_FIND_DATAA(Structure):
    _fields_ = [("dwFileAttributes", DWORD),
                ("ftCreationTime", FILETIME),
                ("ftLastAccessTime", FILETIME),
                ("ftLastWriteTime", FILETIME),
                ("nFileSizeHigh", DWORD),
                ("nFileSizeLow", DWORD),
                ("dwReserved0", DWORD),
                ("dwReserved1", DWORD),
                ("cFileName", c_char * MAX_PATH),
                ("cAlternameFileName", c_char * 14)]

class WIN32_FIND_DATAW(Structure):
    _fields_ = [("dwFileAttributes", DWORD),
                ("ftCreationTime", FILETIME),
                ("ftLastAccessTime", FILETIME),
                ("ftLastWriteTime", FILETIME),
                ("nFileSizeHigh", DWORD),
                ("nFileSizeLow", DWORD),
                ("dwReserved0", DWORD),
                ("dwReserved1", DWORD),
                ("cFileName", c_wchar * MAX_PATH),
                ("cAlternameFileName", c_wchar * 14)]
