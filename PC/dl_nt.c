/*

Entry point for the Windows NT DLL.

About the only reason for having this, is so initall() can automatically
be called, removing that burden (and possible source of frustration if 
forgotten) from the programmer.

*/
#include "windows.h"

/* NT and Python share these */
#undef INCREF
#undef DECREF
#include "config.h"
#include "allobjects.h"

HMODULE PyWin_DLLhModule = NULL;

BOOL	WINAPI	DllMain (HANDLE hInst, 
						ULONG ul_reason_for_call,
						LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			PyWin_DLLhModule = hInst;
			initall();
			break;
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
