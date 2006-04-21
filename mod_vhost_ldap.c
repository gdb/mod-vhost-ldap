/* ============================================================
 * Copyright (c) 2003-2006, Ondrej Sury, Piotr Wadas
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

/* NOTE: only static members must be "used" to build, so for time-to-time used routines we don't declare static */

/*
 * mod_vhost_ldap.c --- read virtual host config from LDAP directory
 * version 2.0 - included ldap-based basic auth & authz
 */

//remember to add "-lcrypt" in Makefile if there's a need to generate new password
// for now not needed (validation only), this below is almost copy-paste from apache source, htpasswd.c
/* 

#include "crypt.h"
#include "time.h"

void to64(char *s, unsigned long v, int n)
{
    static unsigned char itoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    while (--n >= 0) {
       *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

char *htenc(const char *clearpasswd) {
    char *res;
    char salt[9];
    (void) srand((int) time((time_t *) NULL));
    to64(&salt[0], rand(), 8);
    salt[8] = '\0';
    res = crypt(clearpasswd, salt);
    return res;
}

*/

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_ldap.h"
#include "apr_strings.h"
#include "apr_reslist.h"
#include "util_ldap.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "unistd.h"

#ifndef APU_HAS_LDAP
#fatal "mod_vhost_ldap requires APR util to have LDAP support built in"
#endif

#if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
#define HAVE_UNIX_SUEXEC
#endif

#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"		/* Contains the suexec_identity hook used on Unix */
#endif

/* do not accept empty "" strings */
#define strtrue(s) (s && *s)

#define MIN_UID 100
#define MIN_GID 100
#define FILTER_LENGTH MAX_STRING_LEN

module AP_MODULE_DECLARE_DATA vhost_ldap_module;

typedef enum mod_vhost_ldap_status_e {
	MVL_UNSET,
	MVL_DISABLED,
	MVL_ENABLED
} mod_vhost_ldap_status_e;
typedef struct mod_vhost_ldap_config_t {
	mod_vhost_ldap_status_e enabled;	/* Is vhost_ldap enabled? */

	char *url;		/* String representation of LDAP URL */
	char *host;		/* Name of the LDAP server (or space separated list) */
	int port;		/* Port of the LDAP server */
	char *basedn;		/* Base DN to do all searches from */
	int scope;		/* Scope of the search */
	char *filter;		/* Filter to further limit the search  */
	deref_options deref;	/* how to handle alias dereferening */
	char *binddn;		/* DN to bind to server (can be NULL) */
	char *bindpw;		/* Password to bind to server (can be NULL)  xx */
	int have_deref;		/* Set if we have found an Deref option */
	int have_ldap_url;	/* Set if we have found an LDAP url */
	char *wlcbasedn;	/* Base DN to do all location config searches */
	char *wucbasedn;	/* Base DN to do all webuser config searches */
	int secure;		/* True if SSL connections are requested */
} mod_vhost_ldap_config_t;
typedef struct mod_vhost_ldap_request_t {
	char *dn;		/* The saved dn from a successful search */
	char *name;		/* apacheServerName */
	char *admin;		/* apacheServerAdmin */
	char *docroot;		/* apacheDocumentRoot */
	char *uid;		/* Suexec Uid */
	char *gid;		/* Suexec Gid */
	int has_reqlines;	/* placeholder */
	apr_array_header_t *serveralias;	/* apacheServerAlias */
	apr_array_header_t *rqlocationlines;	/* apacheServerAlias */

} mod_vhost_ldap_request_t;
typedef struct mod_vhost_ldap_extconfig_object_t {	/* what the hell this "t" means ??. eh, whatever ;) */
	//we use apr_array_header_t for multi-value attributed, parsed later (yuck!) from grr ";" separated string
	char *extconfname;	/* apacheExtConfigObjectName, single-value, syntax SUP cn */
	char *exturi;		/* apacheExtConfigUri, single-value, uri for which this settings are here
				 * should be used in combine with extconfig server name */
	int extconftype;	/* apacheExtConfigRequireValidUser, single-value bool, 
				 * if TRUE then require valid-user, if FALSE userlist-type config 
				 */

	apr_array_header_t *extservername;	/* apacheExtConfigServerName",MULTI-value, 
						 * e.g. for http://anyserver/statistics (?), syntax SUP cn 
						 */
	apr_array_header_t *extusers;	/* "apacheExtConfigUserDn",  MULTI-value, syntax SUP DN */

} mod_vhost_ldap_extconfig_object_t;
typedef struct mod_vhost_ldap_webuser_t {

	char *webusername;	/* apacheExtConfigUserName, single-value */
	apr_array_header_t *webuserpassword;	/* userPassword, multi-value */
	char *webuserserver;	/* apacheExtConfigUserServerName, server of this user, multi-value */

} mod_vhost_ldap_webuser_t;
static int strschrcount(apr_pool_t * p, const char *src, const char *delim)
{
	int i = 1;
	int x = 0;
	while(*src++) {
		if(strcasecmp(apr_pstrndup(p, src, i), (char *) delim) == 0) {
			x++;
		}
	}
	return x;
}
void log_dump_apr_array(request_rec * r, apr_array_header_t * arr, const char *prefix)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Entering log_dump_apr_array");
    int x = 0;
    char **aliases = (char **) arr->elts;
    for (x = 0; x < arr->nelts; x++) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " log_dump_apr_array val %d %s %s", x, prefix, aliases[x]);
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Leaving log_dump_apr_array");
}
static apr_array_header_t *get_parsed_string_atrr_arr(request_rec * r, const char *server_alias_attrvar_line,
						      const char *delim)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Entering get_parsed_string_atrr_arr |%s|", server_alias_attrvar_line);
	if(server_alias_attrvar_line) {

		apr_collapse_spaces((char *) server_alias_attrvar_line, server_alias_attrvar_line);
		int ccount = strschrcount(r->pool, server_alias_attrvar_line, delim) + 1;

		apr_array_header_t *aliases_arr = apr_array_make(r->pool, ccount, sizeof(char *));
		char **curralias;
		curralias = (char **) apr_array_push(aliases_arr);

		char *curr_server_alias = ap_getword(r->pool, &server_alias_attrvar_line, ';');
		char *tmp = apr_pstrdup(r->pool, (char *) curr_server_alias);;
		*curralias = tmp;


		while(server_alias_attrvar_line[0]) {
			curr_server_alias = ap_getword(r->pool, &server_alias_attrvar_line, ';');
			curralias = (char **) apr_array_push(aliases_arr);
			tmp = apr_pstrdup(r->pool, (char *) curr_server_alias);
			*curralias = tmp;
		}
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Leaving get_parsed_string_atrr_arr OK");
		return aliases_arr;
	}
	else
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Leaving get_parsed_string_atrr_arr NULL");
		return NULL;
}
static apr_array_header_t *get_ap_reqs(apr_pool_t * p, mod_vhost_ldap_extconfig_object_t * extreqc,
				       char *mainservername, char *userlist)
{

    ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL," get_ap_reqs Entering");

	apr_array_header_t *res = apr_array_make(p, 2, sizeof(require_line));

	require_line *rline;
	apr_int64_t limited = -1;

	rline = (require_line *) apr_array_push(res);

	//currently we don't support playing with request types
	rline->method_mask = limited;

	if(extreqc->extconftype == 1) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, " get_ap_reqs require valid-user = TRUE server %s",mainservername);
		rline->requirement = apr_pstrdup(p, (char *) "valid-user");
	}
	else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, " get_ap_reqs require valid-user = FALSE server %s",mainservername);
		
		rline->requirement = apr_pstrdup(p, userlist);
	}
    ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL," Leaving get_ap_reqs, returning require line |require %s|", rline->requirement);
	return res;
}
static void mod_vhost_ldap_dovhostconfig(request_rec * r, char *attributes[], const char **vals,
					 mod_vhost_ldap_request_t * reqc)
{

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " dovhostconfig Entering ");
	int i = 0;
	while(attributes[i]) {

		if(strcasecmp(attributes[i], "apacheServerName") == 0) {
			reqc->name = apr_pstrdup(r->pool, vals[i]);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " %d apacheServerName %s", i, reqc->name);
		}

		if(strcasecmp(attributes[i], "apacheServerAdmin") == 0) {
			reqc->admin = apr_pstrdup(r->pool, vals[i]);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, " %d apacheServerAdmin %s", i, reqc->admin);    
		}

		if(strcasecmp(attributes[i], "apacheDocumentRoot") == 0) {
			reqc->docroot = apr_pstrdup(r->pool, vals[i]);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "  %d apacheDocumentRoot %s", i, reqc->docroot);    
		}

		if(strcasecmp(attributes[i], "apacheSuexecUid") == 0) {
			reqc->uid = apr_pstrdup(r->pool, vals[i]);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "  %d apacheSuexecUid %s", i, reqc->uid);    
		}

		if(strcasecmp(attributes[i], "apacheSuexecGid") == 0) {
			reqc->gid = apr_pstrdup(r->pool, vals[i]);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "  %d apacheSuexecGid %s", i, reqc->gid);                
		}

		if(strcasecmp(attributes[i], "apacheExtConfigHasRequireLine") == 0) {
			if(vals[i]) {
				reqc->has_reqlines = strcasecmp("TRUE", apr_pstrdup(r->pool, vals[i])) == 0 ? 1 : 0;

				if(reqc->has_reqlines) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " %d Vhost %s has extended access configuration", i, reqc->name);
				}
			}
			else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " %d Vhost %s doesn't have extended access configuration", i, reqc->name);
			}
		}

		if(strcasecmp(attributes[i], "apacheServerAlias") == 0) {
			if(vals[i]) {
				reqc->serveralias =
					(apr_array_header_t *) get_parsed_string_atrr_arr(r, vals[i],
											  (const char *) ";");
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "  %d apacheServerAlias is set", i);                
			}
			else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "  %d No apacheServerAlias for this vhost found", i);                
				reqc->serveralias = NULL;
			}
		}

		if(strcasecmp(attributes[i], "apacheLocationOptionsDn") == 0) {
			if(vals[i]) {
				reqc->rqlocationlines =
					(apr_array_header_t *) get_parsed_string_atrr_arr(r, vals[i],
											  (const char *) ";");
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "  %d apacheLocationOptionsDn is set", i);
			}
			else {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " host %s marked ext-configured but no attributes pointing extConfig !! ldap scheme should avoid it !!", reqc->name);
				reqc->rqlocationlines = NULL;
			}
		}
		i++;
	}
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " dovhostconfig Leaving ");
}
static void mod_vhost_ldap_doextconfig(request_rec * r, char *extconfigattributes[], const char **extconfvals,
				       mod_vhost_ldap_extconfig_object_t * extreqc)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " doextconfig Entering ");
	int i = 0;

	while(extconfigattributes[i]) {
		if(strcasecmp(extconfigattributes[i], "apacheExtConfigObjectName") == 0) {
			extreqc->extconfname = apr_pstrdup(r->pool, extconfvals[i]);
		}

		if(strcasecmp(extconfigattributes[i], "apacheExtConfigUri") == 0) {
			extreqc->exturi = apr_pstrdup(r->pool, extconfvals[i]);
		}

		if(strcasecmp(extconfigattributes[i], "apacheExtConfigRequireValidUser") == 0) {
			if(extconfvals[i]) {

				//this value determines whether we have "require valid-user" object  (TRUE) , 
				//or (FALSE) object "require user johny mary dorothy witch"
				//here set retrieved value, regardless what it is, to play with it later.
				extreqc->extconftype =
					strcasecmp("TRUE", apr_pstrdup(r->pool, extconfvals[i])) == 0 ? 1 : 0;
    				ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Set require valid-user to %d (%s)", extreqc->extconftype, (char *) apr_pstrdup(r->pool, extconfvals[i]));
			}
			else {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " For this ext config require valid-user is not set");
			}
		}

		if(strcasecmp(extconfigattributes[i], "apacheExtConfigServerName") == 0) {

			if(extconfvals[i]) {
				extreqc->extservername =
					(apr_array_header_t *) get_parsed_string_atrr_arr(r, extconfvals[i],
											  (const char *) ";");
			}
			else {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
					      " No ExtServerName values found");
				extreqc->extservername = NULL;
			}
		}

		if(strcasecmp(extconfigattributes[i], "apacheExtConfigUserDn") == 0) {

			if(extconfvals[i]) {
				extreqc->extusers =
					(apr_array_header_t *) get_parsed_string_atrr_arr(r, extconfvals[i],
											  (const char *) ";");
			}
			else {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
					      " apacheExtConfigUserDn values NOT found (any valid-user or no users specified.");
				extreqc->extusers = NULL;
			}
		}

		i++;
	}
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " doextconfig Leaving ");
}
static void mod_vhost_ldap_doextuserconfig(request_rec * r, char *ldap_webuser_attributes[], const char **extuservals,
					   mod_vhost_ldap_webuser_t * extuserreqc)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " doextuserconfig Entering");
	int i = 0;
	while(ldap_webuser_attributes[i]) {
		if(strcasecmp(ldap_webuser_attributes[i], "apacheExtConfigUserName") == 0) {
			extuserreqc->webusername = apr_pstrdup(r->pool, extuservals[i]);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
				      "%d apacheExtConfigUserName set to %s", i, extuserreqc->webusername);
		}
		if(strcasecmp(ldap_webuser_attributes[i], "apacheExtConfigUserServerName") == 0) {
			extuserreqc->webuserserver = apr_pstrdup(r->pool, extuservals[i]);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
				      "%d apacheExtConfigUserServerName set to %s", i, extuserreqc->webuserserver);
		}
		if(strcasecmp(ldap_webuser_attributes[i], "userPassword") == 0) {
			extuserreqc->webuserpassword =
				(apr_array_header_t *) get_parsed_string_atrr_arr(r, extuservals[i],
										  (const char *) ";");
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
                      "%d userPassword retrievied", i);                                          
		}
		i++;
	}
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " doextuserconfig Leaving");
}
static int mod_vhost_ldap_authenticate_basic_user(request_rec * r)
{
	const char *sent_pw;
    mod_vhost_ldap_webuser_t *extuserreqc;
    extuserreqc = (mod_vhost_ldap_webuser_t *) apr_pcalloc(r->pool, sizeof(mod_vhost_ldap_webuser_t));
	int rc = ap_get_basic_auth_pw(r, &sent_pw);
	if(rc != OK)
		return rc;
	if(strtrue(r->user) && strtrue(sent_pw)) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Entering mod_vhost_ldap_authenticate_basic_user");

		char userfilter[FILTER_LENGTH];
		mod_vhost_ldap_config_t *conf =
			(mod_vhost_ldap_config_t *) ap_get_module_config(r->server->module_config, &vhost_ldap_module);

		const char *dn = NULL;
		util_ldap_connection_t *ldc = NULL;
		const char **extuservals = NULL;
		int result = 0;
		char *ldap_webuser_attributes[] =
			{ "apacheExtConfigUserName", "apacheExtConfigUserServerName", "userPassword", 0 };

		apr_snprintf(userfilter, FILTER_LENGTH, "(&(apacheExtConfigUserName=%s)(apacheExtConfigUserServerName=%s))", r->user,r->server->server_hostname);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " AuthUser search filter: %s", userfilter);
		ldc = util_ldap_connection_find(r, conf->host, conf->port, conf->binddn, conf->bindpw, conf->deref,
						conf->secure);
		result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->wucbasedn, conf->scope,
						   ldap_webuser_attributes, userfilter, &dn, &extuservals);
		util_ldap_connection_close(ldc);

		if(extuservals) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " User %s found.", r->user);

			mod_vhost_ldap_doextuserconfig(r, ldap_webuser_attributes, extuservals, extuserreqc);

			int x = 0;
			char **passwords = (char **) extuserreqc->webuserpassword->elts;
			for (x = 0; x < extuserreqc->webuserpassword->nelts; x++) {
				if ( ( apr_password_validate(sent_pw, passwords[x]) == OK) || strcasecmp(sent_pw,passwords[x]) == 0 ) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, " Authentication for user %s at %s successful.", extuserreqc->webusername, r->server->server_hostname);
					return OK;
				}
			}

		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, r, " User %s at %s not found", extuserreqc->webusername, r->server->server_hostname);
			return HTTP_UNAUTHORIZED;
		}
	}
	else {
		ap_note_basic_auth_failure(r);
		ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
			      ": Both a username and password must be provided : authentication for user %s at %s failed.",
                              extuserreqc->webusername, r->server->server_hostname);
		return HTTP_UNAUTHORIZED;
	}
    ap_note_basic_auth_failure(r);
    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, "Authentication for user %s at %s failed.",
            extuserreqc->webusername, r->server->server_hostname);
	return HTTP_UNAUTHORIZED;

}
static int check_mod_vhost_ldap_auth_require(char *user, const char *t, request_rec * r)
{
	const char *w;
	w = ap_getword(r->pool, &t, ' ');
	if(!strcmp(w, "valid-user")) {

    		return OK;
	}

	if(!strcmp(w, "user")) {
		while(t[0]) {
			w = ap_getword_conf(r->pool, &t);
			if(!strcmp(user, w)) {

				return OK;

			}
		}
		return HTTP_UNAUTHORIZED;
	}
	else {

		return HTTP_INTERNAL_SERVER_ERROR;
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		      ": %s : Reached end of check_mod_vhost_ldap_auth_require!", r->server->server_hostname);
	return HTTP_INTERNAL_SERVER_ERROR;
}
static int mod_vhost_ldap_check_auth(request_rec * r)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
              ": mod_vhost_ldap_check_auth, parsing existing ap_requires for %s at %s ", r->user, r->server->server_hostname);
	char *user = r->user;
	int rv;
	register int x;
	const char *t;
	const apr_array_header_t *reqs_arr = ap_requires(r);

	require_line *reqs;
	reqs = (require_line *) reqs_arr->elts;

	for (x = 0; x < reqs_arr->nelts; x++) {
		t = reqs[x].requirement;
		if((rv = check_mod_vhost_ldap_auth_require(user, t, r)) != HTTP_UNAUTHORIZED) {
			return rv;
		}
	}


	ap_note_basic_auth_failure(r);
	return HTTP_UNAUTHORIZED;
}
static void *mod_vhost_ldap_create_server_config(apr_pool_t * p, server_rec * s)
{

	mod_vhost_ldap_config_t *conf = (mod_vhost_ldap_config_t *) apr_pcalloc(p, sizeof(mod_vhost_ldap_config_t));
	conf->enabled = MVL_UNSET;
	conf->have_ldap_url = 0;
	conf->have_deref = 0;
	conf->binddn = NULL;
	conf->bindpw = NULL;
	conf->deref = always;
	conf->wlcbasedn = NULL;
	conf->wucbasedn = NULL;

	return conf;
}
static void *mod_vhost_ldap_merge_server_config(apr_pool_t * p, void *parentv, void *childv)
{
	mod_vhost_ldap_config_t *parent = (mod_vhost_ldap_config_t *) parentv;
	mod_vhost_ldap_config_t *child = (mod_vhost_ldap_config_t *) childv;
	mod_vhost_ldap_config_t *conf = (mod_vhost_ldap_config_t *) apr_pcalloc(p, sizeof(mod_vhost_ldap_config_t));

	conf->enabled = (child->enabled == MVL_UNSET ? parent->enabled : child->enabled);

	if(child->have_ldap_url) {
		conf->have_ldap_url = child->have_ldap_url;
		conf->url = child->url;
		conf->host = child->host;
		conf->port = child->port;
		conf->basedn = child->basedn;
		conf->scope = child->scope;
		conf->filter = child->filter;
		conf->secure = child->secure;
		conf->wlcbasedn = child->wlcbasedn;
		conf->wucbasedn = child->wucbasedn;
	}
	else {
		conf->have_ldap_url = parent->have_ldap_url;
		conf->url = parent->url;
		conf->host = parent->host;
		conf->port = parent->port;
		conf->basedn = parent->basedn;
		conf->scope = parent->scope;
		conf->filter = parent->filter;
		conf->secure = parent->secure;
		conf->wlcbasedn = parent->wlcbasedn;
		conf->wucbasedn = parent->wucbasedn;

	}
	if(child->have_deref) {
		conf->have_deref = child->have_deref;
		conf->deref = child->deref;
	}
	else {
		conf->have_deref = parent->have_deref;
		conf->deref = parent->deref;
	}

	conf->binddn = (child->binddn ? child->binddn : parent->binddn);
	conf->bindpw = (child->bindpw ? child->bindpw : parent->bindpw);
	return conf;
}
static const char *mod_vhost_ldap_parse_url(cmd_parms * cmd, void *dummy, const char *url)
{
	int result;
	apr_ldap_url_desc_t *urld;

	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *) ap_get_module_config(cmd->server->module_config, &vhost_ldap_module);

	result = apr_ldap_url_parse(url, &(urld));

	if(result != LDAP_SUCCESS) {
		switch (result) {
		case LDAP_URL_ERR_NOTLDAP:
			return "LDAP URL does not begin with ldap://";
		case LDAP_URL_ERR_NODN:
			return "LDAP URL does not have a DN";
		case LDAP_URL_ERR_BADSCOPE:
			return "LDAP URL has an invalid scope";
		case LDAP_URL_ERR_MEM:
			return "Out of memory parsing LDAP URL";
		default:
			return "Could not parse LDAP URL";
		}
	}
	conf->url = apr_pstrdup(cmd->pool, url);

	/* Set all the values, or at least some sane defaults */
	if(conf->host) {
		char *p = apr_palloc(cmd->pool, strlen(conf->host) + strlen(urld->lud_host) + 2);
		strcpy(p, urld->lud_host);
		strcat(p, " ");
		strcat(p, conf->host);
		conf->host = p;
	}
	else {
		conf->host = urld->lud_host ? apr_pstrdup(cmd->pool, urld->lud_host) : "localhost";
	}
	conf->basedn = urld->lud_dn ? apr_pstrdup(cmd->pool, urld->lud_dn) : "";

	conf->scope = urld->lud_scope == LDAP_SCOPE_ONELEVEL ? LDAP_SCOPE_ONELEVEL : LDAP_SCOPE_SUBTREE;

	if(urld->lud_filter) {
		if(urld->lud_filter[0] == '(') {
			/* 
			 * Get rid of the surrounding parens; later on when generating the
			 * filter, they'll be put back.
			 */
			conf->filter = apr_pstrdup(cmd->pool, urld->lud_filter + 1);
			conf->filter[strlen(conf->filter) - 1] = '\0';
		}
		else {
			conf->filter = apr_pstrdup(cmd->pool, urld->lud_filter);
		}
	}
	else {
		conf->filter = "objectClass=apacheConfig";
	}

	/* "ldaps" indicates secure ldap connections desired
	 */
	if(strncasecmp(url, "ldaps", 5) == 0) {
		conf->secure = 1;
		conf->port = urld->lud_port ? urld->lud_port : LDAPS_PORT;

	}
	else {
		conf->secure = 0;
		conf->port = urld->lud_port ? urld->lud_port : LDAP_PORT;
	}

	conf->have_ldap_url = 1;
	apr_ldap_free_urldesc(urld);
	return NULL;
}
static const char *mod_vhost_ldap_set_enabled(cmd_parms * cmd, void *dummy, int enabled)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *) ap_get_module_config(cmd->server->module_config, &vhost_ldap_module);
	conf->enabled = (enabled) ? MVL_ENABLED : MVL_DISABLED;
	return NULL;
}
static const char *mod_vhost_ldap_set_binddn(cmd_parms * cmd, void *dummy, const char *binddn)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *) ap_get_module_config(cmd->server->module_config, &vhost_ldap_module);
	conf->binddn = apr_pstrdup(cmd->pool, binddn);
	return NULL;
}
static const char *mod_vhost_ldap_set_wucbasedn(cmd_parms * cmd, void *dummy, const char *wucbasedn)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *) ap_get_module_config(cmd->server->module_config, &vhost_ldap_module);
	conf->wucbasedn = apr_pstrdup(cmd->pool, wucbasedn);
	return NULL;
}
static const char *mod_vhost_ldap_set_wlcbasedn(cmd_parms * cmd, void *dummy, const char *wlcbasedn)
{

	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *) ap_get_module_config(cmd->server->module_config, &vhost_ldap_module);
	conf->wlcbasedn = apr_pstrdup(cmd->pool, wlcbasedn);
	return NULL;
}
static const char *mod_vhost_ldap_set_bindpw(cmd_parms * cmd, void *dummy, const char *bindpw)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *) ap_get_module_config(cmd->server->module_config, &vhost_ldap_module);
	conf->bindpw = apr_pstrdup(cmd->pool, bindpw);
	return NULL;
}
static const char *mod_vhost_ldap_set_deref(cmd_parms * cmd, void *dummy, const char *deref)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *) ap_get_module_config(cmd->server->module_config, &vhost_ldap_module);
	if(deref) {
		if(strcmp(deref, "never") == 0 || strcmp(deref, "searching") == 0 || strcmp(deref, "finding") == 0
		   || strcmp(deref, "always") == 0) {
			conf->deref = *deref;
			conf->have_deref = 1;
		}
		else {
			return "Unrecognized value for VhostLDAPAliasDereference directive";
		}
	}
	return NULL;
}



static int mod_vhost_ldap_translate_name(request_rec * r)
{
	char filtbuf[FILTER_LENGTH];
	char extconffiltbuf[FILTER_LENGTH];
	apr_table_t *e;
	request_rec *top;
	mod_vhost_ldap_config_t *conf;
	mod_vhost_ldap_request_t *reqc;
	mod_vhost_ldap_extconfig_object_t *extreqc;
	core_server_config *core;

	util_ldap_connection_t *ldc = NULL;
	const char **vals, **extconfvals = NULL;
	const char *dn = NULL;
	const char *hostname = NULL;
	int failures = 0;
	int i = 0;
	int result = 0;

	/* 
	 * more info about attributes in typedefs definitions and schema desc
	 * PS. Did You ever wonder why they used this damned weird "\0", instead,
	 * let's say, '$' or 'EndOfWord' or whatever ??
	 */

	char *attributes[] = { "apacheServerName", "apacheServerAlias", "apacheDocumentRoot",
		"apacheSuexecUid", "apacheSuexecGid", "apacheServerAdmin",
		"apacheExtConfigHasRequireLine", "apacheLocationOptionsDn",
		0
	};

	char *extconfigattributes[] = { "apacheExtConfigUri", "apacheExtConfigRequireValidUser",
		"apacheExtConfigServerName", "apacheExtConfigObjectName",
		"apacheExtConfigUserDn",
		0
	};

	//we assume we're in trouble, and will change it, if not.
	result = LDAP_SERVER_DOWN;

	top = r->main ? r->main : r;
	hostname = r->hostname;

	//get our module config options
	conf = (mod_vhost_ldap_config_t *) ap_get_module_config(r->server->module_config, &vhost_ldap_module);

	//a reference to core config
	core = (core_server_config *) ap_get_module_config(r->server->module_config, &core_module);

	//and some variable initialization
	reqc = (mod_vhost_ldap_request_t *) apr_pcalloc(r->pool, sizeof(mod_vhost_ldap_request_t));
	extreqc = (mod_vhost_ldap_extconfig_object_t *) apr_pcalloc(r->pool, sizeof(mod_vhost_ldap_extconfig_object_t));

	//current request config get set 
	ap_set_module_config(r->request_config, &vhost_ldap_module, reqc);

	// mod_vhost_ldap is disabled or we don't have LDAP Url
	if((conf->enabled != MVL_ENABLED) || (!conf->have_ldap_url)) {
		return DECLINED;
	}

	if(conf->host) {

		apr_snprintf(filtbuf, FILTER_LENGTH, "(&(%s)(|(apacheServerName=%s)(apacheServerAlias=%s)))",
			     conf->filter, hostname, hostname);

		while(failures++ <= 5 && result == LDAP_SERVER_DOWN) {
			//searching for connection
			ldc = util_ldap_connection_find(r, conf->host, conf->port, conf->binddn, conf->bindpw,
							conf->deref, conf->secure);
			result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->basedn, conf->scope, attributes,
							   filtbuf, &dn, &vals);
			util_ldap_connection_close(ldc);
		}
	}
	else {
		return DECLINED;
	}

	if(result != LDAP_SUCCESS) {
		return DECLINED;
	}

	reqc->dn = apr_pstrdup(r->pool, dn);

	if(vals) {
		//this translate_name function we're in is long enough, don't You think?
		//we set all into reqc struct
		mod_vhost_ldap_dovhostconfig(r, attributes, vals, reqc);
	}

	if((reqc->name == NULL) || (reqc->docroot == NULL)) {

		return DECLINED;
	}

	if(r->uri[0] == '/') {
		r->filename = apr_pstrcat(r->pool, reqc->docroot, r->uri, NULL);
	}
	else {
		return DECLINED;
	}

	if(reqc->has_reqlines == 1 && reqc->rqlocationlines) {

		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
			      "This vhost has access control configured, need to check if it's enabled for current uri");
		result = 0;
		i = 0;

		//we have mercy, and do not open a connection for each uri search ;)

		ldc = util_ldap_connection_find(r, conf->host, conf->port, conf->binddn, conf->bindpw, conf->deref,
						conf->secure);

		//ask Your programming teacher, what's all about with 
		// these "NO, TRY _VERY_ HARD, AND THEN TRY AGAIN _NOT_ TO USE BREAK FOR LOOP LEAVING" ;)
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Entering extConfig Objects search");
		while(i <= strlen(apr_pstrdup(r->pool, r->uri)) && !extconfvals) {
			i++;
			char *buff = apr_pstrndup(r->pool, r->uri, i);
			//ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"Searching for hostname %s and URI %s, origname is %s", hostname, buff, reqc->name);
			//uncomment this, if You'd like to see in log how uri gets checked
			//ap_log_error(APLOG_MARK,APLOG_DEBUG,OK,NULL,"%s", buff);

			//well, we must had been connecting already, so we don't do more ldap server connection checks,
			//and we're doing a search with cache_getuser instead of using extConfigObject dn apacheConfig object attribute value(s),
			//because there's no convenient function in apr api.
			//vhost location RDN attribute is used actually by some GUI to make things easier
			//TODO: use some generic ldap functions (?) classic search or implement more ldap routines for apr

			//so, we do a search below locationDnBase for config object with matches current hostname and uri..
			//note, that we took our current uri, and we're searching starting from / adding one by one chararacter
			//to match config object - access config is always the same as first matching upper url access config.
			//and more - if someone defined accessobject for /main and /main/subdir, the first one is used.
			//when upper is deleted - next below is returned, and so far..
			//and more - if there are two or more extConfig object for the same combination of server/uri,
			//then first found is returned and search isn't processed further.

			//we do a search based on original reqc->name instead of current hostname, to apply rules even if we're accessing
			//site via ServerAlias name
			apr_snprintf(extconffiltbuf, FILTER_LENGTH,
				     "(&(apacheExtConfigServerName=%s)(apacheExtConfigUri=%s))", reqc->name, buff);

			result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->wlcbasedn, conf->scope,
							   extconfigattributes, extconffiltbuf, &dn, &extconfvals);

			//matched URI, if found, is returned anyway with extconfvals as ldap attribute value.
		}
		//ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Closing LDAP Connection");
		util_ldap_connection_close(ldc);

		if(result != LDAP_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
				      "This vhost has access control, but probably not for this URI, access config entry not found");
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
				      "Tried with ldap search filter: %s", extconffiltbuf);
		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
				      "This uri has access control, configuration object is found");

			if(extconfvals) {
				//this translate_name function we're in is long enough, don't You think?
				//we set all into extreqc struct
				//ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Entering extconfig buffer fill");
				mod_vhost_ldap_doextconfig(r, extconfigattributes, extconfvals, extreqc);
			}

			ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "Entering ap_requires generation process");

			core_dir_config *coredirconf =
				(core_dir_config *) ap_get_module_config(r->per_dir_config, &core_module);
			coredirconf->ap_auth_name = extreqc->extconfname;
			coredirconf->ap_auth_type = (char *) "basic";
			char *userlist = "user nobody";

			if(extreqc->extusers) {
				mod_vhost_ldap_webuser_t *extuserreqc;
				extuserreqc =
					(mod_vhost_ldap_webuser_t *) apr_pcalloc(r->pool,
										 sizeof(mod_vhost_ldap_webuser_t));
				char *ldap_webuser_attributes[] =
					{ "apacheExtConfigUserName", "apacheExtConfigUserServerName", "userPassword",
					0
				};
				ldc = util_ldap_connection_find(r, conf->host, conf->port, conf->binddn, conf->bindpw,
								conf->deref, conf->secure);
				int i = 0;
				for (i = 0; i < extreqc->extusers->nelts; i++) {
					char userfilter[FILTER_LENGTH];

					const char **extuservals = NULL;
					int result = 0;
					apr_snprintf(userfilter, FILTER_LENGTH,
						     "(&(objectClass=apacheExtendedConfigUserObject)(apacheExtConfigUserServerName=%s))",
						     reqc->name);
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
						      "User search filter: %s", userfilter);
					result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->wucbasedn,
									   conf->scope, ldap_webuser_attributes,
									   userfilter, &dn, &extuservals);
					if(extuservals) {
						mod_vhost_ldap_doextuserconfig(r, ldap_webuser_attributes, extuservals,
									       extuserreqc);
					}
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
						      "current username: %s", extuserreqc->webusername);

					userlist = apr_pstrcat(r->pool, userlist, " ", extuserreqc->webusername, NULL);

					ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
						      "current userlist: %s", userlist);
				}

				util_ldap_connection_close(ldc);
			}
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "final userlist: %s ", userlist);


			ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "AuthName set to %s", coredirconf->ap_auth_name);
			ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "AuthType set to %s", coredirconf->ap_auth_type);
			ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "Preparing access control line");
			coredirconf->ap_requires =
				(apr_array_header_t *) get_ap_reqs(r->pool, extreqc, reqc->name, userlist);

		}
	}
	else {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
			      "This vhost is not configured for access control, or it is disabled via apacheExtConfigHasRequireLine = FALSE skipping..");
	}

	top->server->server_hostname = apr_pstrdup(top->pool, reqc->name);


	if(reqc->admin) {
		top->server->server_admin = apr_pstrdup(top->pool, reqc->admin);
	}

	// set environment variables
	e = top->subprocess_env;
	apr_table_addn(e, "SERVER_ROOT", reqc->docroot);
	core->ap_document_root = apr_pstrdup(top->pool, reqc->docroot);
	return OK;
}

#ifdef HAVE_UNIX_SUEXEC
static ap_unix_identity_t *mod_vhost_ldap_get_suexec_id_doer(const request_rec * r)
{
	ap_unix_identity_t *ugid = NULL;
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *) ap_get_module_config(r->server->module_config, &vhost_ldap_module);
	mod_vhost_ldap_request_t *req =
		(mod_vhost_ldap_request_t *) ap_get_module_config(r->request_config, &vhost_ldap_module);

	uid_t uid = -1;
	gid_t gid = -1;

	// mod_vhost_ldap is disabled or we don't have LDAP Url
	if((conf->enabled != MVL_ENABLED) || (!conf->have_ldap_url)) {
		return NULL;
	}

	if((req == NULL) || (req->uid == NULL) || (req->gid == NULL)) {
		return NULL;
	}

	if((ugid = apr_palloc(r->pool, sizeof(ap_unix_identity_t))) == NULL) {
		return NULL;
	}

	uid = (uid_t) atoll(req->uid);
	gid = (gid_t) atoll(req->gid);

	if((uid < MIN_UID) || (gid < MIN_GID)) {
		return NULL;
	}

	ugid->uid = uid;
	ugid->gid = gid;
	ugid->userdir = 0;

	return ugid;
}
#endif

static int mod_vhost_ldap_post_config(apr_pool_t * p, apr_pool_t * plog, apr_pool_t * ptemp, server_rec * s)
{
	/* make sure that mod_ldap (util_ldap) is loaded */
	if(ap_find_linked_module("util_ldap.c") == NULL) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ap_add_version_component(p, MOD_VHOST_LDAP_VERSION);
	return OK;
}

static void mod_vhost_ldap_register_hooks(apr_pool_t * p)
{
	ap_hook_post_config(mod_vhost_ldap_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(mod_vhost_ldap_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef HAVE_UNIX_SUEXEC
	ap_hook_get_suexec_identity(mod_vhost_ldap_get_suexec_id_doer, NULL, NULL, APR_HOOK_MIDDLE);
#endif
	ap_hook_check_user_id(mod_vhost_ldap_authenticate_basic_user, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(mod_vhost_ldap_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec mod_vhost_ldap_cmds[] = {

	AP_INIT_TAKE1("VhostLDAPURL", mod_vhost_ldap_parse_url, NULL, RSRC_CONF,
		      "URL to define LDAP connection. This should be an RFC 2255 compliant\n"
		      "URL of the form ldap://host[:port]/basedn[?attrib[?scope[?filter]]].\n"
		      "<ul>\n"
		      "<li>Host is the name of the LDAP server. Use a space separated list of hosts \n"
		      "to specify redundant servers.\n"
		      "<li>Port is optional, and specifies the port to connect to.\n"
		      "<li>basedn specifies the base DN to start searches from\n" "</ul>\n"),

	AP_INIT_TAKE1("VhostLDAPBindDN", mod_vhost_ldap_set_binddn, NULL, RSRC_CONF,
		      "DN to use to bind to LDAP server. If not provided, will do an anonymous bind."),

	AP_INIT_TAKE1("VhostLDAPBindPassword", mod_vhost_ldap_set_bindpw, NULL, RSRC_CONF,
		      "Password to use to bind to LDAP server. If not provided, will do an anonymous bind."),

	AP_INIT_FLAG("VhostLDAPEnabled", mod_vhost_ldap_set_enabled, NULL, RSRC_CONF,
		     "Set to off to disable vhost_ldap, even if it's been enabled in a higher tree"),

	AP_INIT_TAKE1("VhostLDAPDereferenceAliases", mod_vhost_ldap_set_deref, NULL, RSRC_CONF,
		      "Determines how aliases are handled during a search. Can be one of the"
		      "values \"never\", \"searching\", \"finding\", or \"always\". " "Defaults to always."),

	AP_INIT_TAKE1("VhostLDAPWebLocationConfigBaseDn", mod_vhost_ldap_set_wlcbasedn, NULL, RSRC_CONF,
		      "Base DN to do all location config searches."),

	AP_INIT_TAKE1("VhostLDAPWebUsersBaseDn", mod_vhost_ldap_set_wucbasedn, NULL, RSRC_CONF,
		      "Base DN to do all location config searches"),

	{NULL}
};

module AP_MODULE_DECLARE_DATA vhost_ldap_module = {
	STANDARD20_MODULE_STUFF,	// jakas lista
	NULL,			// create per-directory config structure
	NULL,			// merge per-directory config structures, default is to override
	mod_vhost_ldap_create_server_config,	// called when module configuration data needs to be created/allocated.
	mod_vhost_ldap_merge_server_config,	// merge per-server config structures
	mod_vhost_ldap_cmds,	// Here we pass in the list of new configuration directives.
	mod_vhost_ldap_register_hooks,	// register me in apache core
};
