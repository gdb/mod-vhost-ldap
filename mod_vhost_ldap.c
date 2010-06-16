/* ============================================================
 * Copyright (c) 2003-2004, Ondrej Sury
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

/*
 * mod_vhost_ldap.c --- read virtual host config from LDAP directory
 */

#define CORE_PRIVATE

#include <unistd.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_version.h"
#include "apr_ldap.h"
#include "apr_strings.h"
#include "apr_reslist.h"
#include "util_ldap.h"

#if !defined(APU_HAS_LDAP) && !defined(APR_HAS_LDAP)
#error mod_vhost_ldap requires APR-util to have LDAP support built in
#endif

#if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
#define HAVE_UNIX_SUEXEC
#endif

#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"              /* Contains the suexec_identity hook used on Unix */
#endif

#define MIN_UID 100
#define MIN_GID 100
const char USERDIR[] = "web_scripts";

module AP_MODULE_DECLARE_DATA vhost_ldap_module;

typedef enum {
    MVL_UNSET, MVL_DISABLED, MVL_ENABLED
} mod_vhost_ldap_status_e;

typedef struct mod_vhost_ldap_config_t {
    mod_vhost_ldap_status_e enabled;			/* Is vhost_ldap enabled? */

    /* These parameters are all derived from the VhostLDAPURL directive */
    char *url;				/* String representation of LDAP URL */

    char *host;				/* Name of the LDAP server (or space separated list) */
    int port;				/* Port of the LDAP server */
    char *basedn;			/* Base DN to do all searches from */
    int scope;				/* Scope of the search */
    char *filter;			/* Filter to further limit the search  */
    deref_options deref;		/* how to handle alias dereferening */

    char *binddn;			/* DN to bind to server (can be NULL) */
    char *bindpw;			/* Password to bind to server (can be NULL) */

    int have_deref;                     /* Set if we have found an Deref option */
    int have_ldap_url;			/* Set if we have found an LDAP url */

    int secure;				/* True if SSL connections are requested */

    char *fallback;                     /* Fallback virtual host */
    apr_array_header_t *attributes;     /* Attributes to pull from LDAP */
    apr_hash_t *overrides;              /* Directives that are overriden by LDAP */
} mod_vhost_ldap_config_t;

typedef struct mod_vhost_ldap_request_t {
    char *dn;				/* The saved dn from a successful search */
    char *name;				/* ServerName */
    char *admin;			/* ServerAdmin */
    char *docroot;			/* DocumentRoot */
    char *cgiroot;			/* ScriptAlias */
    char *uid;				/* Suexec Uid */
    char *gid;				/* Suexec Gid */
} mod_vhost_ldap_request_t;

char *common_attributes[] =
  { "apacheServerName", "apacheDocumentRoot", "apacheScriptAlias", "apacheSuexecUid", "apacheSuexecGid", "apacheServerAdmin", 0 };

static int total_modules;

#if (APR_MAJOR_VERSION >= 1)
static APR_OPTIONAL_FN_TYPE(uldap_connection_close) *util_ldap_connection_close;
static APR_OPTIONAL_FN_TYPE(uldap_connection_find) *util_ldap_connection_find;
static APR_OPTIONAL_FN_TYPE(uldap_cache_comparedn) *util_ldap_cache_comparedn;
static APR_OPTIONAL_FN_TYPE(uldap_cache_compare) *util_ldap_cache_compare;
static APR_OPTIONAL_FN_TYPE(uldap_cache_checkuserid) *util_ldap_cache_checkuserid;
static APR_OPTIONAL_FN_TYPE(uldap_cache_getuserdn) *util_ldap_cache_getuserdn;
static APR_OPTIONAL_FN_TYPE(uldap_ssl_supported) *util_ldap_ssl_supported;

static void ImportULDAPOptFn(void)
{
    util_ldap_connection_close  = APR_RETRIEVE_OPTIONAL_FN(uldap_connection_close);
    util_ldap_connection_find   = APR_RETRIEVE_OPTIONAL_FN(uldap_connection_find);
    util_ldap_cache_comparedn   = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_comparedn);
    util_ldap_cache_compare     = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_compare);
    util_ldap_cache_checkuserid = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_checkuserid);
    util_ldap_cache_getuserdn   = APR_RETRIEVE_OPTIONAL_FN(uldap_cache_getuserdn);
    util_ldap_ssl_supported     = APR_RETRIEVE_OPTIONAL_FN(uldap_ssl_supported);
}
#endif 

static int mod_vhost_ldap_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    module **m;

    /* Stolen from modules/generators/mod_cgid.c */
    total_modules = 0;
    for (m = ap_preloaded_modules; *m != NULL; m++)
	total_modules++;

    /* make sure that mod_ldap (util_ldap) is loaded */
    if (ap_find_linked_module("util_ldap.c") == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, s,
                     "Module mod_ldap missing. Mod_ldap (aka. util_ldap) "
                     "must be loaded in order for mod_vhost_ldap to function properly");
        return HTTP_INTERNAL_SERVER_ERROR;

    }

    ap_add_version_component(p, MOD_VHOST_LDAP_VERSION);

    return OK;
}

static void *
mod_vhost_ldap_create_server_config (apr_pool_t *p, server_rec *s)
{
    mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)apr_pcalloc(p, sizeof (mod_vhost_ldap_config_t));

    conf->enabled = MVL_UNSET;
    conf->have_ldap_url = 0;
    conf->have_deref = 0;
    conf->binddn = NULL;
    conf->bindpw = NULL;
    conf->deref = always;
    conf->fallback = NULL;

    conf->attributes = apr_array_make(p, 7, sizeof(char *));
    char **attr;
    for (attr = common_attributes; *attr != NULL; attr++) {
      char **next = (char **) apr_array_push(conf->attributes);
      *next = *attr;
    }
    char **terminator = (char **) apr_array_push(conf->attributes);
    *terminator = NULL;
    conf->overrides = apr_hash_make(p);

    return conf;
}

static void *
mod_vhost_ldap_merge_server_config(apr_pool_t *p, void *parentv, void *childv)
{
    mod_vhost_ldap_config_t *parent = (mod_vhost_ldap_config_t *) parentv;
    mod_vhost_ldap_config_t *child  = (mod_vhost_ldap_config_t *) childv;
    mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)apr_pcalloc(p, sizeof(mod_vhost_ldap_config_t));

    if (child->enabled == MVL_UNSET) {
	conf->enabled = parent->enabled;
    } else {
	conf->enabled = child->enabled;
    }

    if (child->have_ldap_url) {
	conf->have_ldap_url = child->have_ldap_url;
	conf->url = child->url;
	conf->host = child->host;
	conf->port = child->port;
	conf->basedn = child->basedn;
	conf->scope = child->scope;
	conf->filter = child->filter;
	conf->secure = child->secure;
    } else {
	conf->have_ldap_url = parent->have_ldap_url;
	conf->url = parent->url;
	conf->host = parent->host;
	conf->port = parent->port;
	conf->basedn = parent->basedn;
	conf->scope = parent->scope;
	conf->filter = parent->filter;
	conf->secure = parent->secure;
    }
    if (child->have_deref) {
	conf->have_deref = child->have_deref;
	conf->deref = child->deref;
    } else {
	conf->have_deref = parent->have_deref;
	conf->deref = parent->deref;
    }

    conf->binddn = (child->binddn ? child->binddn : parent->binddn);
    conf->bindpw = (child->bindpw ? child->bindpw : parent->bindpw);

    conf->fallback = (child->fallback ? child->fallback : parent->fallback);

    conf->attributes = (child->attributes ? child->attributes : parent->attributes);
    conf->overrides = (child->overrides ? child->overrides : parent->overrides);

    return conf;
}

/* 
 * Use the ldap url parsing routines to break up the ldap url into
 * host and port.
 */
static const char *mod_vhost_ldap_parse_url(cmd_parms *cmd, 
					    void *dummy,
					    const char *url)
{
    int result;
    apr_ldap_url_desc_t *urld;
#if (APR_MAJOR_VERSION >= 1)
    apr_ldap_err_t *result_err;
#endif

    mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[mod_vhost_ldap.c] url parse: `%s'", 
	         url);
    
#if (APR_MAJOR_VERSION >= 1)    /* for apache >= 2.2 */
    result = apr_ldap_url_parse(cmd->pool, url, &(urld), &(result_err));
    if (result != LDAP_SUCCESS) {
        return result_err->reason;
    }
#else
    result = apr_ldap_url_parse(url, &(urld));
    if (result != LDAP_SUCCESS) {
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
#endif
    conf->url = apr_pstrdup(cmd->pool, url);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[mod_vhost_ldap.c] url parse: Host: %s", urld->lud_host);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[mod_vhost_ldap.c] url parse: Port: %d", urld->lud_port);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[mod_vhost_ldap.c] url parse: DN: %s", urld->lud_dn);
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[mod_vhost_ldap.c] url parse: attrib: %s", urld->lud_attrs? urld->lud_attrs[0] : "(null)");
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[mod_vhost_ldap.c] url parse: scope: %s", 
	         (urld->lud_scope == LDAP_SCOPE_SUBTREE? "subtree" : 
		 urld->lud_scope == LDAP_SCOPE_BASE? "base" : 
		 urld->lud_scope == LDAP_SCOPE_ONELEVEL? "onelevel" : "unknown"));
    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	         cmd->server, "[mod_vhost_ldap.c] url parse: filter: %s", urld->lud_filter);

    /* Set all the values, or at least some sane defaults */
    if (conf->host) {
        char *p = apr_palloc(cmd->pool, strlen(conf->host) + strlen(urld->lud_host) + 2);
        strcpy(p, urld->lud_host);
        strcat(p, " ");
        strcat(p, conf->host);
        conf->host = p;
    }
    else {
        conf->host = urld->lud_host? apr_pstrdup(cmd->pool, urld->lud_host) : "localhost";
    }
    conf->basedn = urld->lud_dn? apr_pstrdup(cmd->pool, urld->lud_dn) : "";

    conf->scope = urld->lud_scope == LDAP_SCOPE_ONELEVEL ?
        LDAP_SCOPE_ONELEVEL : LDAP_SCOPE_SUBTREE;

    if (urld->lud_filter) {
        if (urld->lud_filter[0] == '(') {
            /* 
	     * Get rid of the surrounding parens; later on when generating the
	     * filter, they'll be put back.
             */
            conf->filter = apr_pstrdup(cmd->pool, urld->lud_filter+1);
            conf->filter[strlen(conf->filter)-1] = '\0';
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
    if (strncasecmp(url, "ldaps", 5) == 0)
    {
        conf->secure = 1;
        conf->port = urld->lud_port? urld->lud_port : LDAPS_PORT;
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server,
                     "LDAP: vhost_ldap using SSL connections");
    }
    else
    {
        conf->secure = 0;
        conf->port = urld->lud_port? urld->lud_port : LDAP_PORT;
        ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server, 
                     "LDAP: vhost_ldap not using SSL connections");
    }

    conf->have_ldap_url = 1;
#if (APR_MAJOR_VERSION < 1) /* free only required for older apr */
    apr_ldap_free_urldesc(urld);
#endif
    return NULL;
}

static const char *mod_vhost_ldap_set_enabled(cmd_parms *cmd, void *dummy, int enabled)
{
    mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    conf->enabled = (enabled) ? MVL_ENABLED : MVL_DISABLED;

    return NULL;
}

static const char *mod_vhost_ldap_set_binddn(cmd_parms *cmd, void *dummy, const char *binddn)
{
    mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    conf->binddn = apr_pstrdup(cmd->pool, binddn);
    return NULL;
}

static const char *mod_vhost_ldap_set_bindpw(cmd_parms *cmd, void *dummy, const char *bindpw)
{
    mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    conf->bindpw = apr_pstrdup(cmd->pool, bindpw);
    return NULL;
}

static const char *mod_vhost_ldap_set_deref(cmd_parms *cmd, void *dummy, const char *deref)
{
    mod_vhost_ldap_config_t *conf = 
	(mod_vhost_ldap_config_t *)ap_get_module_config (cmd->server->module_config,
							 &vhost_ldap_module);

    if (strcmp(deref, "never") == 0 || strcasecmp(deref, "off") == 0) {
        conf->deref = never;
	conf->have_deref = 1;
    }
    else if (strcmp(deref, "searching") == 0) {
        conf->deref = searching;
	conf->have_deref = 1;
    }
    else if (strcmp(deref, "finding") == 0) {
        conf->deref = finding;
	conf->have_deref = 1;
    }
    else if (strcmp(deref, "always") == 0 || strcasecmp(deref, "on") == 0) {
        conf->deref = always;
	conf->have_deref = 1;
    }
    else {
        return "Unrecognized value for VhostLDAPAliasDereference directive";
    }
    return NULL;
}

static const char *mod_vhost_ldap_set_fallback(cmd_parms *cmd, void *dummy, const char *fallback)
{
    mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);

    conf->fallback = apr_pstrdup(cmd->pool, fallback);
    return NULL;
}

enum parse_state {
    PS_LITERAL,
    PS_PERCENT,
    PS_VARIABLE
};

enum token_type {
    TT_LITERAL,
    TT_VARIABLE
};

struct parse_result {
    enum token_type type;
    char *data;
};

static const char *mod_vhost_ldap_set_attributes(cmd_parms *cmd, void *dummy, const char *directive,
						 const char *template)
{
    char *next;
    const char *curr;
    char **attr;
    struct parse_result *successor;
    enum parse_state state;
    apr_array_header_t *parsed, *accum;

    mod_vhost_ldap_config_t *conf = 
	(mod_vhost_ldap_config_t *)ap_get_module_config (cmd->server->module_config,
							 &vhost_ldap_module);

    parsed = apr_array_make(cmd->pool, 0, sizeof(struct parse_result));
    accum = apr_array_make(cmd->pool, 0, sizeof(char));
    
    /* Pop the NULL off the end */
    apr_array_pop(conf->attributes);

    state = PS_LITERAL;
    for (curr = template; *curr; curr++) {
        switch(state) {
	case PS_LITERAL:
  	    if(*curr == '%') {
	        state = PS_PERCENT;
	    } else {
	        next = (char *) apr_array_push(accum);
		*next = *curr;
	    }
            break;
        case PS_PERCENT:
            if (*curr == '(') {
                state = PS_VARIABLE;
                if (accum->nelts) {
                    successor = (struct parse_result *) apr_array_push(parsed);
                    successor->type = TT_LITERAL;
                    successor->data = apr_pstrndup(cmd->pool, (char *) accum->elts, accum->nelts);
                    ap_str_tolower(successor->data);
                }
                accum = apr_array_make(cmd->pool, 0, sizeof(char));
            } else {
                /* This has the right semantics for unescaped '%'s: We
                   tolerate them as long as they are not followed by
                   an '('. */
                state = PS_LITERAL;
                next = (char *) apr_array_push(accum);
                *next = *curr;
            }
            break;
        case PS_VARIABLE:
            if(*curr == ')') {
                state = PS_LITERAL;
                if (accum->nelts) {
                    successor = (struct parse_result *) apr_array_push(parsed);
                    successor->type = TT_VARIABLE;
                    successor->data = apr_pstrndup(cmd->pool, (char *) accum->elts, accum->nelts);
                    ap_str_tolower(successor->data);

                    /* TODO: uniqify array of LDAP attributes */
                    attr = (char **) apr_array_push(conf->attributes);
                    *attr = successor->data;
                }
                accum = apr_array_make(cmd->pool, 0, sizeof(char));
            } else {
	        next = (char *) apr_array_push(accum);
		*next = *curr;
            }
            break;
        }
    }

    if (accum->nelts) {
        successor = (struct parse_result *) apr_array_push(parsed);
        successor->type = state == PS_LITERAL ? TT_LITERAL : TT_VARIABLE;
        successor->data = apr_pstrndup(cmd->pool, (char *) accum->elts, accum->nelts);
        ap_str_tolower(successor->data);
    }

    /* NULL terminate the attribute list again */
    attr = (char **) apr_array_push(conf->attributes);
    *attr = NULL;

    if (state != PS_LITERAL)
        ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, cmd->server,
                     "[mod_vhost_ldap.c] malformed template \"%s\"", template);

    apr_hash_set(conf->overrides, directive, APR_HASH_KEY_STRING, parsed);
    return NULL;
}


command_rec mod_vhost_ldap_cmds[] = {
    AP_INIT_TAKE1("VhostLDAPURL", mod_vhost_ldap_parse_url, NULL, RSRC_CONF,
                  "URL to define LDAP connection. This should be an RFC 2255 compliant\n"
                  "URL of the form ldap://host[:port]/basedn[?attrib[?scope[?filter]]].\n"
                  "<ul>\n"
                  "<li>Host is the name of the LDAP server. Use a space separated list of hosts \n"
                  "to specify redundant servers.\n"
                  "<li>Port is optional, and specifies the port to connect to.\n"
                  "<li>basedn specifies the base DN to start searches from\n"
                  "</ul>\n"),

    AP_INIT_TAKE1 ("VhostLDAPBindDN", mod_vhost_ldap_set_binddn, NULL, RSRC_CONF,
		   "DN to use to bind to LDAP server. If not provided, will do an anonymous bind."),
    
    AP_INIT_TAKE1("VhostLDAPBindPassword", mod_vhost_ldap_set_bindpw, NULL, RSRC_CONF,
                  "Password to use to bind to LDAP server. If not provided, will do an anonymous bind."),

    AP_INIT_FLAG("VhostLDAPEnabled", mod_vhost_ldap_set_enabled, NULL, RSRC_CONF,
                 "Set to off to disable vhost_ldap, even if it's been enabled in a higher tree"),

    AP_INIT_TAKE1("VhostLDAPDereferenceAliases", mod_vhost_ldap_set_deref, NULL, RSRC_CONF,
                  "Determines how aliases are handled during a search. Can be one of the"
                  "values \"never\", \"searching\", \"finding\", or \"always\". "
                  "Defaults to always."),

    AP_INIT_TAKE1("VhostLDAPFallback", mod_vhost_ldap_set_fallback, NULL, RSRC_CONF,
		  "Set default virtual host which will be used when requested hostname"
		  "is not found in LDAP database. This option can be used to display"
		  "\"virtual host not found\" type of page."),
    /* TODO: finish this comment */
    AP_INIT_TAKE2("VhostLDAPConfig", mod_vhost_ldap_set_attributes, NULL, RSRC_CONF,
                  "Determine the set of configuration variables used to override core Apache\n"
                  "directive using a template populated from LDAP.\n"
                  "Must provide the directive name and the template; the latter should be\n"
                  "of the form \"literal%(attribute)moreliteral\".  \"%%\" is parsed as a\n"
                  "literal percent."),
    {NULL}
};

#define FILTER_LENGTH MAX_STRING_LEN
static int mod_vhost_ldap_translate_name(request_rec *r)
{
    mod_vhost_ldap_request_t *reqc;
    apr_table_t *e;
    int failures = 0;
    const char **vals = NULL;
    char filtbuf[FILTER_LENGTH];
    mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(r->server->module_config, &vhost_ldap_module);
    core_server_config * core =
	(core_server_config *) ap_get_module_config(r->server->module_config, &core_module);
    util_ldap_connection_t *ldc = NULL;
    int result = 0;
    const char *dn = NULL;
    char *cgi;
    const char *hostname = NULL;
    int is_fallback = 0;

    reqc =
	(mod_vhost_ldap_request_t *)apr_pcalloc(r->pool, sizeof(mod_vhost_ldap_request_t));
    memset(reqc, 0, sizeof(mod_vhost_ldap_request_t)); 

    ap_set_module_config(r->request_config, &vhost_ldap_module, reqc);

    // mod_vhost_ldap is disabled or we don't have LDAP Url
    if ((conf->enabled != MVL_ENABLED)||(!conf->have_ldap_url)) {
	return DECLINED;
    }

start_over:

    if (conf->host) {
        ldc = util_ldap_connection_find(r, conf->host, conf->port,
					conf->binddn, conf->bindpw, conf->deref,
					conf->secure);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, 
                      "[mod_vhost_ldap.c] translate: no conf->host - weird...?");
        return DECLINED;
    }

    hostname = r->hostname;
    if (hostname == NULL || hostname[0] == '\0')
	goto null;

fallback:

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		   "[mod_vhost_ldap.c]: translating %s", r->uri);

    struct berval hostnamebv, shostnamebv;
    ber_str2bv(hostname, 0, 0, &hostnamebv);
    if (ldap_bv2escaped_filter_value(&hostnamebv, &shostnamebv) != 0)
	goto null;
    apr_snprintf(filtbuf, FILTER_LENGTH, "(&(%s)(|(apacheServerName=%s)(apacheServerAlias=%s)))", conf->filter, shostnamebv.bv_val, shostnamebv.bv_val);
    ber_memfree(shostnamebv.bv_val);

    result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->basedn, conf->scope,
				       (char **) conf->attributes->elts, filtbuf, &dn, &vals);

    util_ldap_connection_close(ldc);

    /* sanity check - if server is down, retry it up to 5 times */
    if (result == LDAP_SERVER_DOWN) {
        if (failures++ <= 5) {
            goto start_over;
        }
    }

    if ((result == LDAP_NO_SUCH_OBJECT)) {
	if (strcmp(hostname, "*") != 0) {
	    if (strncmp(hostname, "*.", 2) == 0)
		hostname += 2;
	    hostname += strcspn(hostname, ".");
	    hostname = apr_pstrcat(r->pool, "*", hostname, NULL);
	    ap_log_rerror(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, r,
		          "[mod_vhost_ldap.c] translate: "
			  "virtual host not found, trying wildcard %s",
			  hostname);
	    goto fallback;
	}

    null:
	if (conf->fallback && (is_fallback++ <= 0)) {
	    ap_log_rerror(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, r,
			  "[mod_vhost_ldap.c] translate: "
			  "virtual host %s not found, trying fallback %s",
			  hostname, conf->fallback);
	    hostname = conf->fallback;
	    goto fallback;
	}

	ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r,
		      "[mod_vhost_ldap.c] translate: "
		      "virtual host %s not found",
		      hostname);

	return DECLINED;
    }

    /* handle bind failure */
    if (result != LDAP_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, 
                      "[mod_vhost_ldap.c] translate: "
                      "translate failed; virtual host %s; URI %s [%s]",
		      hostname, r->uri, ldap_err2string(result));
	return DECLINED;
    }

    /* mark the user and DN */
    reqc->dn = apr_pstrdup(r->pool, dn);

    /* Optimize */
    apr_hash_t *params = NULL;
    // TODO: check for errors
    params = apr_hash_make(r->pool);

    if (vals) {
	int i = 0;
        char **attributes = (char **) conf->attributes->elts;
        while(attributes[i]) {
            char *attribute = apr_pstrdup(r->pool, ((char **) conf->attributes->elts)[i]);
            ap_str_tolower(attribute);
            char *val = apr_pstrdup(r->pool, vals[i]);

	    if (strcasecmp (attribute, "apacheServerName") == 0) {
		reqc->name = apr_pstrdup (r->pool, val);
	    }
	    else if (strcasecmp (attribute, "apacheServerAdmin") == 0) {
		reqc->admin = apr_pstrdup (r->pool, val);
	    }
	    else if (strcasecmp (attribute, "apacheDocumentRoot") == 0) {
		reqc->docroot = apr_pstrdup (r->pool, val);
	    }
	    else if (strcasecmp (attribute, "apacheScriptAlias") == 0) {
		reqc->cgiroot = apr_pstrdup (r->pool, val);
	    }
	    else if (strcasecmp (attribute, "apacheSuexecUid") == 0) {
		reqc->uid = apr_pstrdup(r->pool, val);
	    }
	    else if (strcasecmp (attribute, "apacheSuexecGid") == 0) {
		reqc->gid = apr_pstrdup(r->pool, val);
	    }

            apr_hash_set(params, attribute, APR_HASH_KEY_STRING, val);
	    i++;
	}
    }

    apr_hash_index_t *idx;
    apr_array_header_t *retrieved = apr_array_make(r->pool, 0, sizeof(char *));
    for(idx = apr_hash_first(r->pool, params); idx; idx = apr_hash_next(idx)) {
        char **attr = (char **) apr_array_push(retrieved);
        char **colon = (char **) apr_array_push(retrieved);
        char **val = (char **) apr_array_push(retrieved);
        char **term = (char **) apr_array_push(retrieved);

        *colon = ": ";
        *term = ", ";
        apr_hash_this(idx, (const void **) attr, NULL, (void **) val);
        /* TODO: don't have a trailing comma. */
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		  "[mod_vhost_ldap.c]: loaded from ldap: %s",
                  apr_array_pstrcat(r->pool, retrieved, '\0'));

    for(idx = apr_hash_first(r->pool, conf->overrides); idx; idx = apr_hash_next(idx)) {
        apr_array_header_t *interpolated = apr_array_make(r->pool, 0, sizeof(char *));
        char *dir;
        apr_array_header_t *parse;
        apr_hash_this(idx, (const void **) &dir, NULL, (void **) &parse);
        struct parse_result entry;
        int i;
        for(i = 0; i < parse->nelts; i++) {
            entry = ((struct parse_result *) parse->elts)[i];
            char **next = (char **) apr_array_push(interpolated);
            switch(entry.type) {
            case(TT_LITERAL): *next = entry.data; break;
            case(TT_VARIABLE): *next = (char *) apr_hash_get(params,
                                                             (const void *) entry.data,
                                                             APR_HASH_KEY_STRING);
            }
        }
        char *val = apr_array_pstrcat(r->pool, interpolated, '\0');
        /* TODO: This spew is probably excessive */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                      "[mod_vhost_ldap.c]: setting %s to %s",
                      dir, val);

        ap_directive_t dir_s;
        dir_s.directive = dir;
        dir_s.args = val;
        dir_s.next = NULL;
        dir_s.first_child = NULL;
        dir_s.parent = NULL;
        dir_s.data = NULL;
        dir_s.filename = NULL;
        dir_s.line_num = 0;
        cmd_parms parms;
        parms.server = r->server;
        parms.pool   = r->pool;
        ap_walk_config(&dir_s,
                       &parms,
                       r->request_config);
    
        if(!strcasecmp(dir, "ErrorLog")) {
            r->server->error_fname = val;
            if ( ap_run_open_logs(r->pool, r->pool, r->pool, r->server) != OK) {
                ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR,
                             0, NULL, "Unable to open reopen log");
            }
        } else if(!strcasecmp(dir, "ServerAdmin")) {
            r->server->server_admin = val;
        }
    }

    if ((reqc->name == NULL)||(reqc->docroot == NULL)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
                      "[mod_vhost_ldap.c] translate: "
                      "translate failed; ServerName or DocumentRoot not defined");
	return DECLINED;
    }

    cgi = NULL;
  
#if 0
    if (reqc->cgiroot) {
	cgi = strstr(r->uri, "cgi-bin/");
	if (cgi && (cgi != r->uri + strspn(r->uri, "/"))) {
	    cgi = NULL;
	}
    }
    if (cgi) {
	r->filename = apr_pstrcat (r->pool, reqc->cgiroot, cgi + strlen("cgi-bin"), NULL);
	r->handler = "cgi-script";
	apr_table_setn(r->notes, "alias-forced-type", r->handler);
#endif
    /* This is a quick, dirty hack. I should be shot for taking 6.170
     * this term and being willing to write a quick, dirty hack. */
    
    if (strncmp(r->uri, "/~", 2) == 0) {
	char *username;
	uid_t uid = (uid_t)atoll(reqc->uid);
	if (apr_uid_name_get(&username, uid, r->pool) != APR_SUCCESS) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
		          "could not get username for uid %d", uid);
	    return DECLINED;
	}
	if (strncmp(r->uri + 2, username, strlen(username)) == 0 &&
	    (r->uri[2 + strlen(username)] == '/' ||
	     r->uri[2 + strlen(username)] == '\0')) {
	    char *homedir;
	    if (apr_uid_homepath_get(&homedir, username, r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			      "could not get home directory for user %s", username);
		return DECLINED;
	    }
	    r->filename = apr_pstrcat(r->pool, homedir, "/", USERDIR, r->uri + 2 + strlen(username), NULL);
	}
    } else if (r->uri[0] == '/') {
	r->filename = apr_pstrcat (r->pool, reqc->docroot, r->uri, NULL);
    } else {
	return DECLINED;
    }

    if ((r->server = apr_pmemdup(r->pool, r->server,
				 sizeof(*r->server))) == NULL)
	return HTTP_INTERNAL_SERVER_ERROR;

    r->server->server_hostname = reqc->name;

    if (reqc->admin) {
	r->server->server_admin = reqc->admin;
    }

    // set environment variables
    e = r->subprocess_env;
    apr_table_addn (e, "SERVER_ROOT", reqc->docroot);

    if ((r->server->module_config =
	 apr_pmemdup(r->pool, r->server->module_config,
		     sizeof(void *) *
		     (total_modules + DYNAMIC_MODULE_LIMIT))) == NULL)
	return HTTP_INTERNAL_SERVER_ERROR;

    if ((core = apr_pmemdup(r->pool, core, sizeof(*core))) == NULL)
	return HTTP_INTERNAL_SERVER_ERROR;
    ap_set_module_config(r->server->module_config, &core_module, core);

    core->ap_document_root = reqc->docroot;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		  "[mod_vhost_ldap.c]: translated to %s", r->filename);

    return OK;
}

#ifdef HAVE_UNIX_SUEXEC
static ap_unix_identity_t *mod_vhost_ldap_get_suexec_id_doer(const request_rec * r)
{
  ap_unix_identity_t *ugid = NULL;
  mod_vhost_ldap_config_t *conf = 
      (mod_vhost_ldap_config_t *)ap_get_module_config(r->server->module_config,
						      &vhost_ldap_module);
  mod_vhost_ldap_request_t *req =
      (mod_vhost_ldap_request_t *)ap_get_module_config(r->request_config,
						       &vhost_ldap_module);

  uid_t uid = -1;
  gid_t gid = -1;

  // mod_vhost_ldap is disabled or we don't have LDAP Url
  if ((conf->enabled != MVL_ENABLED)||(!conf->have_ldap_url)) {
      return NULL;
  }

  if ((req == NULL)||(req->uid == NULL)||(req->gid == NULL)) {
      return NULL;
  }

  if ((ugid = apr_palloc(r->pool, sizeof(ap_unix_identity_t))) == NULL) {
      return NULL;
  }

  uid = (uid_t)atoll(req->uid);
  gid = (gid_t)atoll(req->gid);

  if ((uid < MIN_UID)||(gid < MIN_GID)) {
      return NULL;
  }

  ugid->uid = uid;
  ugid->gid = gid;
  ugid->userdir = 0;
  
  return ugid;
}
#endif

static void
mod_vhost_ldap_register_hooks (apr_pool_t * p)
{
    ap_hook_post_config(mod_vhost_ldap_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(mod_vhost_ldap_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
#ifdef HAVE_UNIX_SUEXEC
    ap_hook_get_suexec_identity(mod_vhost_ldap_get_suexec_id_doer, NULL, NULL, APR_HOOK_MIDDLE);
#endif
#if (APR_MAJOR_VERSION >= 1)
    ap_hook_optional_fn_retrieve(ImportULDAPOptFn,NULL,NULL,APR_HOOK_MIDDLE);
#endif
}

module AP_MODULE_DECLARE_DATA vhost_ldap_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  mod_vhost_ldap_create_server_config,
  mod_vhost_ldap_merge_server_config,
  mod_vhost_ldap_cmds,
  mod_vhost_ldap_register_hooks,
};
