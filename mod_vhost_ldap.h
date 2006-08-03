/* ============================================================
 * Copyright (c) 2003-2006, Ondrej Sury, Piotr Wadas
 * All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * NOTE: only static members must be "used" to build, 
 * so for time-to-time used routines we don't declare static 
 * mod_vhost_ldap.c --- read virtual host config from LDAP directory
 * version 2.0 - included ldap-based basic auth & authz
 * remember to add "-lcrypt" in Makefile if there's a need to generate new password
 * for now not needed (validation only), this below is almost copy-paste from apache source, htpasswd.c
 */

#define CORE_PRIVATE
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_ldap.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_reslist.h"
#include "util_ldap.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "unistd.h"
#include "crypt.h"

/* these are for checking unix crypt passwords */
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>

/*this functions are not needed, as apr_password_validate includes it on its own */
/*void to64(char *s, unsigned long v, int n)
{
    static unsigned char itoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    while (--n >= 0) {
       *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

char *htenc(const char *clearpasswd) {
	//this function creates password compatible with htpasswd 
    char *res;
    char salt[9];
    (void) srand((int) time((time_t *) NULL));
    to64(&salt[0], rand(), 8);
    salt[8] = '\0';
    res = crypt(clearpasswd, salt);
    return res;
}
*/
/******************************************************************/
//this function creates salt for unix password crypt md5
/*
char *crypt_make_salt (void)
{
		
        struct timeval tv;
        static char result[40];

        result[0] = '\0';
        strcpy (result, "$1$"); // magic for the new MD5 crypt() 

        gettimeofday (&tv, (struct timezone *) 0);
        strcat (result, l64a (tv.tv_usec));
        strcat (result, l64a (tv.tv_sec + getpid () + clock ()));

        if (strlen (result) > 3 + 8) result[11] = '\0';

        return result;
}
*/
#ifndef APU_HAS_LDAP
#fatal "mod_vhost_ldap requires APR util to have LDAP support built in"
#endif

#ifdef MD5_CRYPT_ENAB
#undef MD5_CRYPT_ENAB
#endif

#define MD5_CRYPT_ENAB yes
#include "unixd.h"		/* Contains the suexec_identity hook used on Unix and needed for crypt() */

#define strtrue(s) (s && *s)	/* do not accept empty "" strings */
#define MIN_UID 100
#define MIN_GID 100
#define FILTER_LENGTH MAX_STRING_LEN
#define MSL MAX_STRING_LEN

/******************************************************************/
//need this global due to apache API construction
int mvhl_conf_enabled 		= 1;
int mvhl_conf_binddn 		= 2;
int mvhl_conf_bindpw 		= 3;
int mvhl_conf_deref 		= 4;
int mvhl_conf_wlcbasedn 	= 5;
int mvhl_conf_wucbasedn 	= 6;
int mvhl_conf_fallback 		= 7;
int mvhl_conf_aliasbasedn	= 8;
int mvhl_alias_enabled		= 9;
int mvhl_loc_auth_enabled	= 10;
int mvhl_dir_auth_enabled	= 11;
/******************************************************************/
#define MVHL_ENABLED 		&mvhl_conf_enabled
#define MVHL_BINDDN 		&mvhl_conf_binddn
#define MVHL_BINDPW 		&mvhl_conf_bindpw
#define MVHL_DEREF 			&mvhl_conf_deref
#define MVHL_WLCBASEDN 		&mvhl_conf_wlcbasedn
#define MVHL_WUCBASEDN 		&mvhl_conf_wucbasedn
#define MVHL_FALLBACK		&mvhl_conf_fallback
#define MVHL_ALIASBASEDN 	&mvhl_conf_aliasbasedn
#define MVHL_ALIASENABLED	&mvhl_alias_enabled
#define MVHL_LAUTHENABLED	&mvhl_loc_auth_enabled
#define MVHL_DAUTHENABLED	&mvhl_dir_auth_enabled

/******************************************************************/
typedef struct mvhl_config 
{
	int				enabled;		/* Is vhost_ldap enabled? */
	char 			*url;			/* String representation of LDAP URL */
	char 			*host;			/* Name of the LDAP server (or space separated list) */
	char			*fallback;		/* Name of the fallback vhost to return not-found info */
	int 			port;			/* Port of the LDAP server */
	char 			*basedn;		/* Base DN to do all searches from */
	int 			scope;			/* Scope of the search */
	char 			*filter;		/* Filter to further limit the search  */
	deref_options 	deref;			/* how to handle alias dereferening */
	char 			*binddn;		/* DN to bind to server (can be NULL) */
	char 			*bindpw;		/* Password to bind to server (can be NULL)  xx */
	int 			have_deref;		/* Set if we have found an Deref option */
	int 			have_ldap_url;	/* Set if we have found an LDAP url */
	char 			*wlcbasedn;		/* Base DN to do all location config searches */
	char 			*wucbasedn;		/* Base DN to do all webuser config searches */
	char			*aliasesbasedn;	/* Base DN to do all aliases config objects searches */
	int 			secure;			/* True if SSL connections are requested */
	int				alias_enabled;	/* 0 - disabled, 1 - enabled */
	int				loc_auth_enabled;	/* 0 - disabled, 1 - enabled */
	int				dir_auth_enabled;	/* 0 - disabled, 1 - enabled */
} mvhl_config;
/******************************************************************/
typedef struct mvhl_request 
{
	char	 			*dn;				/* The saved dn from a successful search */
	char 				*name;				/* apacheServerName */
	char 				*admin;				/* apacheServerAdmin */
	char 				*docroot;			/* apacheDocumentRoot */
	char 				*uid;				/* Suexec Uid */
	char 				*gid;				/* Suexec Gid */
	int 				has_reqlines;		/* we have require lines (1) or not (0) */
	int 				has_aliaslines;		/* we have aliases lines (1) or not (0) */
	apr_array_header_t 	*serveralias;		/* apacheServerAlias values */
	apr_array_header_t 	*rqlocationlines;	/* apacheExtConfigOptionsDn values */
	apr_array_header_t 	*aliaseslines;		/* apacheAliasesConfigOptionsDn values */
	
} mvhl_request;
/******************************************************************/
typedef struct mvhl_extconfig_object 
{	
	/* we use apr_array_header_t for multi-value attributed, 
	 * parsed later (yuck!) from ";" separated string
	 */
	char *extconfname;				/* apacheExtConfigObjectName, single-value, syntax SUP cn */
	apr_array_header_t *exturi;		/* apacheExtConfigUri MULTI-value, uri for which this settings are here
				 		 			 * should be used in combine with extconfig server name 
				 		 			 */
	apr_array_header_t *extdir;
	int extconftype;				/* apacheExtConfigRequireValidUser, single-value bool, 
				 		 			 * if TRUE then require valid-user, if FALSE userlist-type config 
				 		 			 */
	apr_array_header_t *extservername;	/* apacheExtConfigServerName" MULTI-value, */ 
	apr_array_header_t *extusers;		/* "apacheExtConfigUserDn"  MULTI-value, syntax SUP DN */

} mvhl_extconfig_object;
/******************************************************************/
typedef struct mvhl_aliasconf_object 
{	
	char *aliasconfname;						/* apacheAliasConfigObjectName, single value */
	apr_array_header_t *aliassourceuri;			/* apacheAliasConfigSourceUri */
	char *aliastargetdir;						/* apacheAliasConfigTargetDir */
	apr_array_header_t *aliasconfservername;	/* apacheAliasConfigServerName MULTI-value*/
} mvhl_aliasconf_object;
/******************************************************************/
typedef struct mvhl_webuser 
{
	char *webusername;						/* apacheExtConfigUserName, single-value */
	apr_array_header_t *webuserpassword;	/* userPassword, multi-value */
	apr_array_header_t *webuserserver;		/* apacheExtConfigUserServerName, server of this user, multi-value */
	apr_array_header_t *webuserlocationuri;	/* apacheExtConfigUserServerName, server of this user, multi-value */
	apr_array_header_t *webuserdirectory;	/* apacheExtConfigUserDirectoryName, server of this user, multi-value */
} mvhl_webuser;
