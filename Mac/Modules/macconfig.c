/***********************************************************
Copyright 1991-1997 by Stichting Mathematisch Centrum, Amsterdam,
The Netherlands.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the names of Stichting Mathematisch
Centrum or CWI not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior permission.

STICHTING MATHEMATISCH CENTRUM DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH CENTRUM BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

******************************************************************/

/* Macintosh Python configuration file */

#include "Python.h"
/* Table of built-in modules.
   These are initialized when first imported.
   Note: selection of optional extensions is now generally done by the
   makesetup script. */

extern void initarray();
extern void initmath();
#ifndef WITHOUT_COMPLEX
extern void initcmath();
#endif
extern void initparser();
extern void initmac();
extern void initMacOS();
extern void initregex();
extern void initstrop();
extern void initstruct();
extern void inittime();
extern void initdbm();
extern void initfcntl();
extern void initnis();
extern void initpwd();
extern void initgrp();
extern void initcrypt();
extern void initselect();
extern void initsocket();
extern void initaudioop();
extern void initimageop();
extern void initrgbimg();
#ifdef USE_STDWIN
extern void initstdwin();
#endif
extern void initmd5();
extern void initmpz();
extern void initrotor();
extern void inital();
extern void initcd();
extern void initcl();
extern void initfm();
extern void initgl();
extern void initimgfile();
extern void initimgformat();
extern void initsgi();
extern void initsv();
extern void initfl();
extern void initthread();
extern void inittiming();
extern void initsignal();
extern void initnew();
extern void initdl();
extern void initsyslog();
extern void initgestalt();
extern void initmacfs();
extern void initbinascii();
extern void initsoundex();
extern void initoperator();
extern void initerrno();
extern void initpcre();
extern void initunicodedata();
extern void init_codecs();
#ifdef THINK
extern void initmacconsole();
#endif
#ifdef USE_MACCTB
extern void initctb();
#endif
#ifdef USE_MACSPEECH
extern void initmacspeech();
#endif
#ifdef USE_MACTCP
extern void initmacdnr();
extern void initmactcp();
#endif
#ifdef USE_TOOLBOX
#ifndef USE_CORE_TOOLBOX
#define USE_CORE_TOOLBOX
#endif
extern void initAE();
extern void initApp();
extern void initEvt();
extern void initFm();
extern void initHelp();
extern void initIcn();
extern void initList();
extern void initSnd();
extern void initSndihooks();
extern void initScrap();
extern void initTE();
extern void initColorPicker();
extern void initPrinting();
extern void initDrag();
#endif
#ifdef USE_CORE_TOOLBOX
extern void initCtl();
extern void initDlg();
extern void initMenu();
extern void initQd();
extern void initRes();
extern void initWin();
extern void initNav();
#endif
#ifdef USE_QT
extern void initCm();
extern void initQt();
#endif

#ifdef USE_IMG
extern void initimgcolormap();
extern void initimgformat();
extern void initimggif();
extern void initimgjpeg();
extern void initimgpbm();
extern void initimgppm();
extern void initimgpgm();
extern void initimgtiff();
extern void initimgsgi();
extern void initimgpng();
extern void initimgop();
#endif
#ifdef USE_TK
extern void init_tkinter();
#endif
#ifdef USE_GUSI
extern void initsocket();
extern void initselect();
#endif
#ifdef USE_WASTE
extern void initwaste();
#endif
#ifdef USE_GDBM
extern void initgdbm();
#endif
#ifdef USE_ZLIB
extern void initzlib();
#endif
#ifdef WITH_THREAD
extern void initthread();
#endif

extern void initcPickle();
extern void initcStringIO();
extern void init_codecs();
/* -- ADDMODULE MARKER 1 -- */

extern void PyMarshal_Init();
extern void initimp();

struct _inittab _PyImport_Inittab[] = {

	{"array", initarray},
#ifndef SYMANTEC__CFM68K__
/* The math library seems mostly broken... */
	{"math", initmath},
#endif
#ifndef WITHOUT_COMPLEX
	{"cmath", initcmath},
#endif
	{"parser", initparser},
	{"mac", initmac},
	{"MacOS", initMacOS},
	{"regex", initregex},
	{"strop", initstrop},
	{"struct", initstruct},
	{"time", inittime},
	{"audioop", initaudioop},
	{"imageop", initimageop},
	{"rgbimg", initrgbimg},
#ifdef USE_STDWIN
	{"stdwin", initstdwin},
#endif
	{"md5", initmd5},
	{"rotor", initrotor},
	{"new", initnew},
	{"gestalt", initgestalt},
	{"macfs", initmacfs},
	{"binascii", initbinascii},
	{"soundex", initsoundex},
	{"operator", initoperator},
	{"errno", initerrno},
	{"pcre", initpcre},
	{"unicodedata", initunicodedata},
	{"_codecs", init_codecs},
#ifdef THINK_C
/* This is an interface to the Think runtime */
	{"macconsole", initmacconsole},
#endif
#ifdef USE_MACCTB
	{"ctb", initctb},
#endif
/* This could probably be made to work on other compilers... */
#ifdef USE_MACSPEECH
	{"macspeech", initmacspeech},
#endif
#ifdef USE_MACTCP
	{"macdnr", initmacdnr},
	{"mactcp", initmactcp},
#endif
#ifdef USE_CORE_TOOLBOX
	{"Ctl", initCtl},
	{"Dlg", initDlg},
	{"Menu", initMenu},
	{"Nav", initNav},
	{"Qd", initQd},
	{"Win", initWin},
	{"Res", initRes},
#endif
#ifdef USE_TOOLBOX
	{"AE", initAE},
	{"App", initApp},
	{"Evt", initEvt},
	{"Fm", initFm},
	{"Icn", initIcn},
	{"List", initList},
	{"Snd", initSnd},
	{"Sndihooks", initSndihooks},
	{"Scrap", initScrap},
	{"TE", initTE},
	{"ColorPicker", initColorPicker},
#ifndef TARGET_API_MAC_CARBON
	{"Help", initHelp},
	{"Printing", initPrinting},
#endif
	{"Drag", initDrag},
#endif
#ifdef USE_QT
	{"Cm", initCm},
	{"Qt", initQt},
#endif
#ifdef USE_IMG
	{"imgcolormap",	initimgcolormap},
	{"imgformat",	initimgformat},
	{"imggif",	initimggif},
	{"imgjpeg",	initimgjpeg},
	{"imgpbm",	initimgpbm},
	{"imgppm",	initimgppm},
	{"imgpgm",	initimgpgm},
	{"imgtiff",	initimgtiff},
	{"imgsgi",	initimgsgi},
	{"imgpng",	initimgpng},
	{"imgop",	initimgop},
#endif
#ifdef USE_TK
	{"_tkinter",	init_tkinter},
#endif
#ifdef USE_GUSI
	{"socket",	initsocket},
	{"select",	initselect},
#endif
#ifdef USE_WASTE
	{"waste",	initwaste},
#endif
#ifdef USE_GDBM
	{"gdbm",	initgdbm},
#endif /* USE_GDBM */
#ifdef USE_ZLIB
	{"zlib",	initzlib},
#endif
#ifdef WITH_THREAD
	{"thread",	initthread},
#endif
	{"cPickle",	initcPickle},
	{"cStringIO",	initcStringIO},
	{"_codecs", init_codecs},

/* -- ADDMODULE MARKER 2 -- */

	/* This module "lives in" with marshal.c */
	{"marshal", PyMarshal_Init},
	
	/* This module "lives in" with import.c */
	{"imp", initimp},

	/* These entries are here for sys.builtin_module_names */
	{"__main__", NULL},
	{"__builtin__", NULL},
	{"sys", NULL},

	/* Sentinel */
	{0, 0}
};
