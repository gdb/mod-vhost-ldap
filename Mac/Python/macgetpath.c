#include "Python.h"
#include "osdefs.h"

#include "pythonresources.h"


/* Return the initial python search path.  This is called once from
** initsys() to initialize sys.path.
**
** If USE_BUILTIN_PATH is defined the path defined here is used
** (after prepending the python home dir to each item).
** If it is not defined the path is gotten from a resource in the
** Preferences file.
**
** XXXX This code needs cleaning up. The routines here have moved
** around quite a bit, and they're pretty messy for that reason.
*/

#include <Files.h>
#include <Aliases.h>
#include <Folders.h>
#include <Resources.h>
#include <TextUtils.h>

#define PYTHONPATH "\
:\n\
:Lib\n\
:Lib:stdwin\n\
:Lib:test\n\
:Lib:mac"


char *
getpythonpath()
{
	/* Modified by Jack to do something a bit more sensible:
	** - Prepend the python home-directory (which is obtained from a Preferences
	**   resource)
	** - Add :
	*/
	static char *pythonpath;
	char *curwd;
	char *p, *endp;
	int newlen;
	extern char *PyMac_GetPythonDir();
#ifndef USE_BUILTIN_PATH
	extern char *PyMac_GetPythonPath();
#endif
	
	if ( pythonpath ) return pythonpath;
	curwd = PyMac_GetPythonDir();
#ifndef USE_BUILTIN_PATH
	if ( pythonpath = PyMac_GetPythonPath(curwd) )
		return pythonpath;
	printf("Warning: No pythonpath resource found, using builtin default\n");
#endif
	p = PYTHONPATH;
	endp = p;
	pythonpath = malloc(2);
	if ( pythonpath == NULL ) return PYTHONPATH;
	strcpy(pythonpath, ":");
	while (*endp) {
		endp = strchr(p, '\n');
		if ( endp == NULL )
			endp = p + strlen(p);
		newlen = strlen(pythonpath) + 1 + strlen(curwd) + (endp-p);
		pythonpath = realloc(pythonpath, newlen+1);
		if ( pythonpath == NULL ) return PYTHONPATH;
		strcat(pythonpath, "\n");
		if ( *p == ':' ) {
			p++;
			strcat(pythonpath, curwd);
			strncat(pythonpath, p, (endp-p));
			newlen--;   /* Ok, ok, we've allocated one byte too much */
		} else {
			/* We've allocated too much in this case */
			newlen -= strlen(curwd);
			pythonpath = realloc(pythonpath, newlen+1);
			if ( pythonpath == NULL ) return PYTHONPATH;
			strncat(pythonpath, p, (endp-p));
		}
		pythonpath[newlen] = '\0';
		p = endp + 1;
	}
	return pythonpath;
}


/*
** Return the name of the Python directory
*/
char *
PyMac_GetPythonDir()
{
    int item;
    static char name[256];
    AliasHandle handle;
    FSSpec dirspec;
    int ok = 0;
    Boolean modified = 0, cannotmodify = 0;
    short oldrh, prefrh;
    short prefdirRefNum;
    long prefdirDirID;
    
    /*
    ** Remember old resource file and try to open preferences file
    ** in the preferences folder. If it doesn't exist we try to create
    ** it. If anything fails here we limp on, but set cannotmodify so
    ** we don't try to store things later on.
    */
    oldrh = CurResFile();
    if ( FindFolder(kOnSystemDisk, 'pref', kDontCreateFolder, &prefdirRefNum,
    				&prefdirDirID) != noErr ) {
    	/* Something wrong with preferences folder */
    	cannotmodify = 1;
    } else {
    	(void)FSMakeFSSpec(prefdirRefNum, prefdirDirID, "\pPython Preferences", &dirspec);
		prefrh = FSpOpenResFile(&dirspec, fsRdWrShPerm);
		if ( prefrh == -1 ) {
#ifdef USE_MAC_MODPREFS
			/* It doesn't exist. Try to create it */
			FSpCreateResFile(&dirspec, 'PYTH', 'pref', 0);
	  		prefrh = FSpOpenResFile(&dirspec, fsRdWrShPerm);
			if ( prefrh == -1 ) {
				/* This is strange, what should we do now? */
				cannotmodify = 1;
			} else {
				UseResFile(prefrh);
    		}
#else
			printf("Error: no Preferences file. Attempting to limp on...\n");
			name[0] = 0;
			getwd(name);
			return name;
#endif
    	}
    }
    /* So, we've opened our preferences file, we hope. Look for the alias */
    handle = (AliasHandle)Get1Resource('alis', PYTHONHOME_ID);
    if ( handle ) {
    	/* It exists. Resolve it (possibly updating it) */
    	if ( ResolveAlias(NULL, handle, &dirspec, &modified) == noErr ) {
    		ok = 1;
    	}
    }
    if ( !ok ) {
#ifdef USE_MAC_MODPREFS
    	/* No luck, so far. ask the user for help */
	    item = Alert(NOPYTHON_ALERT, NULL);
	    if ( item == YES_ITEM ) {
	    	/* The user wants to point us to a directory. Let her do so */
	    	ok = PyMac_GetDirectory(&dirspec);
	    	if ( ok )
	    		modified = 1;
	    } else if ( item == CURWD_ITEM ) {
	    	/* The user told us the current directory is fine. Build an FSSpec for it */
	    	if ( getwd(name) ) {
	    		if ( FSMakeFSSpec(0, 0, Pstring(name), &dirspec) == 0 ) {
	    			ok = 1;
	    			modified = 1;
	    		}
	    	}
	    }
	    if ( handle ) {
	    	/* Set the (old, invalid) alias record to the new data */
	    	UpdateAlias(NULL, &dirspec, handle, &modified);
	    }
#else
		printf("Error: corrupted Preferences file. Attempting to limp on...\n");
		name[0] = 0;
		getwd(name);
		return name;
#endif
    }
#ifdef USE_MAC_MODPREFS
    if ( ok && modified && !cannotmodify) {
    	/* We have a new, valid fsspec and we can update the preferences file. Do so. */
    	if ( !handle ) {
    		if (NewAlias(NULL, &dirspec, &handle) == 0 )
    			AddResource((Handle)handle, 'alis', PYTHONHOME_ID, "\p");
    	} else {
    		ChangedResource((Handle)handle);
    	}
    	UpdateResFile(prefrh);
    }
#endif
    if ( !cannotmodify ) {
    	/* This means we have the resfile open. Close it. */
    	CloseResFile(prefrh);
    }
    /* Back to the old resource file */
    UseResFile(oldrh);
    /* Now turn the fsspec into a path to give back to our caller */
    if ( ok ) {
    	ok = (nfullpath(&dirspec, name) == 0);
    	if ( ok ) strcat(name, ":");
    }
    if ( !ok ) {
		/* If all fails, we return the current directory */
		name[0] = 0;
		(void)getwd(name);
	}
	return name;
}

#ifndef USE_BUILTIN_PATH
char *
PyMac_GetPythonPath(dir)
char *dir;
{
    FSSpec dirspec;
    short oldrh, prefrh = -1;
    short prefdirRefNum;
    long prefdirDirID;
    char *rv;
    int i, newlen;
    Str255 pathitem;
    
    /*
    ** Remember old resource file and try to open preferences file
    ** in the preferences folder.
    */
    oldrh = CurResFile();
    if ( FindFolder(kOnSystemDisk, 'pref', kDontCreateFolder, &prefdirRefNum,
    				&prefdirDirID) == noErr ) {
    	(void)FSMakeFSSpec(prefdirRefNum, prefdirDirID, "\pPython Preferences", &dirspec);
		prefrh = FSpOpenResFile(&dirspec, fsRdWrShPerm);
    }
    /* At this point, we may or may not have the preferences file open, and it
    ** may or may not contain a sys.path STR# resource. We don't care, if it doesn't
    ** exist we use the one from the application (the default).
    ** We put an initial '\n' in front of the path that we don't return to the caller
    */
    if( (rv = malloc(2)) == NULL )
    	goto out;
    strcpy(rv, "\n");
    for(i=1; ; i++) {
    	GetIndString(pathitem, PYTHONPATH_ID, i);
    	if( pathitem[0] == 0 )
    		break;
    	if ( pathitem[0] >= 9 && strncmp((char *)pathitem+1, "$(PYTHON)", 9) == 0 ) {
    		/* We have to put the directory in place */
    		newlen = strlen(rv) + strlen(dir) + (pathitem[0]-9) + 2;
    		if( (rv=realloc(rv, newlen)) == NULL)
    			goto out;
    		strcat(rv, dir);
    		/* Skip a colon at the beginning of the item */
    		if ( pathitem[0] > 9 && pathitem[1+9] == ':' ) {
				memcpy(rv+strlen(rv), pathitem+1+10, pathitem[0]-10);
				newlen--;
			} else {
				memcpy(rv+strlen(rv), pathitem+1+9, pathitem[0]-9);
			}
    		rv[newlen-2] = '\n';
    		rv[newlen-1] = 0;
    	} else {
    		/* Use as-is */
    		newlen = strlen(rv) + (pathitem[0]) + 2;
    		if( (rv=realloc(rv, newlen)) == NULL)
    			goto out;
    		memcpy(rv+strlen(rv), pathitem+1, pathitem[0]);
    		rv[newlen-2] = '\n';
    		rv[newlen-1] = 0;
    	}
	}
	if( strlen(rv) == 1) {
		free(rv);
		rv = NULL;
	}
	if ( rv ) {
		rv[strlen(rv)-1] = 0;
		rv++;
	}
out:
	if ( prefrh ) {
		CloseResFile(prefrh);
		UseResFile(oldrh);
	}
	return rv;
}
#endif /* !USE_BUILTIN_PATH */

