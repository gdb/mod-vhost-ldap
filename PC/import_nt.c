/********************************************************************

 import_nt.c 

  Win32 specific import code.

*/

#include "Python.h"
#include "osdefs.h"
#include <windows.h>
#include "importdl.h"
#include "malloc.h" // for alloca

extern const char *PyWin_DLLVersionString; // a string loaded from the DLL at startup.

FILE *PyWin_FindRegisteredModule( const char *moduleName, struct filedescr **ppFileDesc, char *pathBuf, int pathLen)
{
	char *moduleKey;
	const char keyPrefix[] = "Software\\Python\\PythonCore\\";
	const char keySuffix[] = "\\Modules\\";
#ifdef _DEBUG
	// In debugging builds, we _must_ have the debug version registered.
	const char debugString[] = "\\Debug";
#else
	const char debugString[] = "";
#endif
	struct filedescr *fdp = NULL;
	FILE *fp;
	HKEY keyBase = HKEY_LOCAL_MACHINE;
	int modNameSize;
	long regStat;

	// Calculate the size for the sprintf buffer.
	// Get the size of the chars only, plus 1 NULL.
	size_t bufSize = sizeof(keyPrefix)-1 + strlen(PyWin_DLLVersionString) + sizeof(keySuffix) + strlen(moduleName) + sizeof(debugString) - 1;
	// alloca == no free required, but memory only local to fn, also no heap fragmentation!
	moduleKey = alloca(bufSize); 
	sprintf(moduleKey, "Software\\Python\\PythonCore\\%s\\Modules\\%s%s", PyWin_DLLVersionString, moduleName, debugString);

	modNameSize = pathLen;
	regStat = RegQueryValue(keyBase, moduleKey, pathBuf, &modNameSize);
	if (regStat!=ERROR_SUCCESS)
		return NULL;
	// use the file extension to locate the type entry.
	for (fdp = _PyImport_Filetab; fdp->suffix != NULL; fdp++) {
		size_t extLen = strlen(fdp->suffix);
		if (modNameSize>extLen && strnicmp(pathBuf+(modNameSize-extLen-1),fdp->suffix,extLen)==0)
			break;
	}
	if (fdp->suffix==NULL)
		return NULL;
	fp = fopen(pathBuf, fdp->mode);
	if (fp != NULL)
		*ppFileDesc = fdp;
	return fp;
}

