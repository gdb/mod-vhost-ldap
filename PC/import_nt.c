/********************************************************************

 importnt.c 

  Win32 specific import code.

*/

#include "allobjects.h"
#include "osdefs.h"
#include <windows.h>
#include "import.h"
#include "importdl.h"

#ifndef WIN32_PATCH_LEVEL
#define WIN32_PATCH_LEVEL "000"
#endif

extern BOOL PyWin_IsWin32s();

FILE *PyWin_FindRegisteredModule( const char *moduleName, struct filedescr **ppFileDesc, char *pathBuf, int pathLen)
{
	char moduleKey[128];
	struct filedescr *fdp = NULL;
	FILE *fp;
	int modNameSize = pathLen;
	HKEY keyBase = PyWin_IsWin32s() ? HKEY_CLASSES_ROOT : HKEY_LOCAL_MACHINE;
	strcpy(moduleKey, "Software\\Python\\PythonCore\\" WIN32_PATCH_LEVEL "\\Modules\\");
	strcat(moduleKey, moduleName);
	if (RegQueryValue(keyBase, moduleKey, pathBuf, &modNameSize)!=ERROR_SUCCESS)
		return NULL;
	// use the file extension to locate the type entry.
	for (fdp = import_filetab; fdp->suffix != NULL; fdp++) {
		int extLen=strlen(fdp->suffix);
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
