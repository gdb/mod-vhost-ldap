# Microsoft Visual C++ generated build script - Do not modify

PROJ = PYTH_W31
DEBUG = 0
PROGTYPE = 3
CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = -d_DEBUG
R_RCDEFINES = -dNDEBUG
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = N:\PYTHON\PYTHON\PC\VC15_W31\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = MAIN.C      
FIRSTCPP =             
RC = rc
CFLAGS_D_WTTY = /nologo /G3 /Mq /W3 /Zi /AL /Gt9 /Od /D "_DEBUG" /D "HAVE_CONFIG_H" /I "..\src" /FR /Fd"PYTH_W31.PDB"
CFLAGS_R_WTTY = /nologo /Gs /G3 /Mq /W3 /AL /Gt9 /O2 /D "NDEBUG" /D "HAVE_CONFIG_H" /I "..\src" /FR 
LFLAGS_D_WTTY = /NOLOGO /NOD /PACKC:57344 /STACK:20000 /SEG:1024 /ALIGN:16 /ONERROR:NOEXE /CO /MAP 
LFLAGS_R_WTTY = /NOLOGO /NOD /PACKC:57344 /STACK:20000 /SEG:1024 /ALIGN:16 /ONERROR:NOEXE /MAP 
LIBS_D_WTTY = ..\vc15_lib\python.lib oldnames libw llibcewq winsock 
LIBS_R_WTTY = ..\vc15_lib\python.lib oldnames libw llibcewq winsock 
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
DEFFILE = ..\PYTH_W31.DEF
OBJS_EXT = 
LIBS_EXT = 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WTTY)
LFLAGS = $(LFLAGS_D_WTTY)
LIBS = $(LIBS_D_WTTY)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
DEFFILE=N:\PYTHON\PYTHON\PC\PYTH_W31.DEF
!else
CFLAGS = $(CFLAGS_R_WTTY)
LFLAGS = $(LFLAGS_R_WTTY)
LIBS = $(LIBS_R_WTTY)
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
DEFFILE=N:\PYTHON\PYTHON\PC\PYTH_W31.DEF
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = MAIN.SBR \
		GETOPT.SBR \
		SELECTMO.SBR \
		SOCKETMO.SBR


MAIN_DEP = n:\python\python\pc\src\python.h \
	n:\python\python\pc\src\allobjec.h \
	n:\python\python\pc\src\config.h \
	n:\python\python\pc\src\myproto.h \
	n:\python\python\pc\src\rename2.h \
	n:\python\python\pc\src\object.h \
	n:\python\python\pc\src\objimpl.h \
	n:\python\python\pc\src\pydebug.h \
	n:\python\python\pc\src\accessob.h \
	n:\python\python\pc\src\intobjec.h \
	n:\python\python\pc\src\longobje.h \
	n:\python\python\pc\src\floatobj.h \
	n:\python\python\pc\src\complexo.h \
	n:\python\python\pc\src\rangeobj.h \
	n:\python\python\pc\src\stringob.h \
	n:\python\python\pc\src\tupleobj.h \
	n:\python\python\pc\src\listobje.h \
	n:\python\python\pc\src\mappingo.h \
	n:\python\python\pc\src\methodob.h \
	n:\python\python\pc\src\moduleob.h \
	n:\python\python\pc\src\funcobje.h \
	n:\python\python\pc\src\classobj.h \
	n:\python\python\pc\src\thread.h \
	n:\python\python\pc\src\fileobje.h \
	n:\python\python\pc\src\cobject.h \
	n:\python\python\pc\src\tracebac.h \
	n:\python\python\pc\src\sliceobj.h \
	n:\python\python\pc\src\pyerrors.h \
	n:\python\python\pc\src\mymalloc.h \
	n:\python\python\pc\src\modsuppo.h \
	n:\python\python\pc\src\ceval.h \
	n:\python\python\pc\src\pythonru.h \
	n:\python\python\pc\src\sysmodul.h \
	n:\python\python\pc\src\intrchec.h \
	n:\python\python\pc\src\import.h \
	n:\python\python\pc\src\bltinmod.h \
	n:\python\python\pc\src\abstract.h


GETOPT_DEP = 

SELECTMO_DEP = n:\python\python\pc\src\allobjec.h \
	n:\python\python\pc\src\config.h \
	n:\python\python\pc\src\myproto.h \
	n:\python\python\pc\src\rename2.h \
	n:\python\python\pc\src\object.h \
	n:\python\python\pc\src\objimpl.h \
	n:\python\python\pc\src\pydebug.h \
	n:\python\python\pc\src\accessob.h \
	n:\python\python\pc\src\intobjec.h \
	n:\python\python\pc\src\longobje.h \
	n:\python\python\pc\src\floatobj.h \
	n:\python\python\pc\src\complexo.h \
	n:\python\python\pc\src\rangeobj.h \
	n:\python\python\pc\src\stringob.h \
	n:\python\python\pc\src\tupleobj.h \
	n:\python\python\pc\src\listobje.h \
	n:\python\python\pc\src\mappingo.h \
	n:\python\python\pc\src\methodob.h \
	n:\python\python\pc\src\moduleob.h \
	n:\python\python\pc\src\funcobje.h \
	n:\python\python\pc\src\classobj.h \
	n:\python\python\pc\src\thread.h \
	n:\python\python\pc\src\fileobje.h \
	n:\python\python\pc\src\cobject.h \
	n:\python\python\pc\src\tracebac.h \
	n:\python\python\pc\src\sliceobj.h \
	n:\python\python\pc\src\pyerrors.h \
	n:\python\python\pc\src\mymalloc.h \
	n:\python\python\pc\src\modsuppo.h \
	n:\python\python\pc\src\ceval.h \
	n:\python\python\pc\src\pythonru.h \
	n:\python\python\pc\src\sysmodul.h \
	n:\python\python\pc\src\intrchec.h \
	n:\python\python\pc\src\import.h \
	n:\python\python\pc\src\bltinmod.h \
	n:\python\python\pc\src\abstract.h \
	c:\msvc\include\winsock.h \
	n:\python\python\pc\src\myselect.h \
	n:\python\python\pc\src\mytime.h


SOCKETMO_DEP = n:\python\python\pc\src\python.h \
	n:\python\python\pc\src\allobjec.h \
	n:\python\python\pc\src\config.h \
	n:\python\python\pc\src\myproto.h \
	n:\python\python\pc\src\rename2.h \
	n:\python\python\pc\src\object.h \
	n:\python\python\pc\src\objimpl.h \
	n:\python\python\pc\src\pydebug.h \
	n:\python\python\pc\src\accessob.h \
	n:\python\python\pc\src\intobjec.h \
	n:\python\python\pc\src\longobje.h \
	n:\python\python\pc\src\floatobj.h \
	n:\python\python\pc\src\complexo.h \
	n:\python\python\pc\src\rangeobj.h \
	n:\python\python\pc\src\stringob.h \
	n:\python\python\pc\src\tupleobj.h \
	n:\python\python\pc\src\listobje.h \
	n:\python\python\pc\src\mappingo.h \
	n:\python\python\pc\src\methodob.h \
	n:\python\python\pc\src\moduleob.h \
	n:\python\python\pc\src\funcobje.h \
	n:\python\python\pc\src\classobj.h \
	n:\python\python\pc\src\thread.h \
	n:\python\python\pc\src\fileobje.h \
	n:\python\python\pc\src\cobject.h \
	n:\python\python\pc\src\tracebac.h \
	n:\python\python\pc\src\sliceobj.h \
	n:\python\python\pc\src\pyerrors.h \
	n:\python\python\pc\src\mymalloc.h \
	n:\python\python\pc\src\modsuppo.h \
	n:\python\python\pc\src\ceval.h \
	n:\python\python\pc\src\pythonru.h \
	n:\python\python\pc\src\sysmodul.h \
	n:\python\python\pc\src\intrchec.h \
	n:\python\python\pc\src\import.h \
	n:\python\python\pc\src\bltinmod.h \
	n:\python\python\pc\src\abstract.h \
	n:\python\python\pc\src\mytime.h \
	c:\msvc\include\winsock.h


all:	$(PROJ).EXE $(PROJ).BSC

MAIN.OBJ:	..\SRC\MAIN.C $(MAIN_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c ..\SRC\MAIN.C

GETOPT.OBJ:	..\SRC\GETOPT.C $(GETOPT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SRC\GETOPT.C

SELECTMO.OBJ:	..\SRC\SELECTMO.C $(SELECTMO_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SRC\SELECTMO.C

SOCKETMO.OBJ:	..\SRC\SOCKETMO.C $(SOCKETMO_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\SRC\SOCKETMO.C


$(PROJ).EXE::	MAIN.OBJ GETOPT.OBJ SELECTMO.OBJ SOCKETMO.OBJ $(OBJS_EXT) $(DEFFILE)
	echo >NUL @<<$(PROJ).CRF
MAIN.OBJ +
GETOPT.OBJ +
SELECTMO.OBJ +
SOCKETMO.OBJ +
$(OBJS_EXT)
$(PROJ).EXE
$(MAPFILE)
c:\msvc\lib\+
c:\msvc\mfc\lib\+
$(LIBS)
$(DEFFILE);
<<
	link $(LFLAGS) @$(PROJ).CRF
	$(RC) $(RESFLAGS) $@


run: $(PROJ).EXE
	$(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<
