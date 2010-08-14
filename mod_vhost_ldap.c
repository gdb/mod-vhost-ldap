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
#include "apr_fnmatch.h"
#include "apr_ldap.h"
#include "apr_reslist.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "util_ldap.h"
#include "util_script.h"

#if !defined(APU_HAS_LDAP) && !defined(APR_HAS_LDAP)
#error mod_vhost_ldap requires APR-util to have LDAP support built in
#endif

#if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
#define HAVE_UNIX_SUEXEC
#endif

#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"              /* Contains the suexec_identity hook used on Unix */
#endif

static int mod_vhost_ldap_push_once(apr_array_header_t *, apr_hash_t *, const char *);
static void mod_vhost_ldap_array_set(apr_array_header_t *, void *, int);


#define MIN_UID 100
#define MIN_GID 100
const char USERDIR[] = "web_scripts";

#define MAX_FAILURES 5

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
    apr_array_header_t *attributes;     /* NULL-terminated list of LDAP attributes to look up */
    apr_hash_t *attr_idx;               /* Map from attributes -> indices in attributes array */
    apr_array_header_t *directives;     /* Apache directives that will be overriden by LDAP  */
    apr_hash_t *dir_idx;                /* Map from directives -> indices in directives array */
    apr_array_header_t *overrides;      /* Parsed templates for the new value of directives  */
    apr_array_header_t *validators;             /* Regexes to validate interpolated attributes */
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

enum token_type {
    TT_LITERAL,
    TT_VARIABLE
};

struct parse_result {
    enum token_type type;
    union {
        char *literal;    /* Section of literal text, used if type == TT_LITERAL */
        int offset;       /* Offset into the attributes array for a variable, used if type == TT_VARIBALE */
    } data;
};

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
    APR_ARRAY_PUSH(conf->attributes, char *) = NULL;
    conf->attr_idx = apr_hash_make(p);
    conf->directives = apr_array_make(p, 0, sizeof(char *));
    conf->dir_idx = apr_hash_make(p);
    conf->overrides = apr_array_make(p, 0, sizeof(apr_array_header_t *));
    conf->validators = apr_array_make(p, 0, sizeof(ap_regex_t *));

    return conf;
}

static void
mod_vhost_ldap_merge_onto(apr_pool_t *p, mod_vhost_ldap_config_t *source,
                          mod_vhost_ldap_config_t *target)
{
    int i, j, newidx, pos;
    struct parse_result res;
    apr_array_header_t *newary;
    apr_array_header_t *subary;
    ap_regex_t *regex;

    /* Skip the null terminator */
    apr_array_pop(target->attributes);
    for (i = 0; i < source->attributes->nelts - 1; i++)
        mod_vhost_ldap_push_once(target->attributes, target->attr_idx,
                                 APR_ARRAY_IDX(source->attributes, i, char *));
    APR_ARRAY_PUSH(target->attributes, char *) = NULL;
    /* We take advantage of the invariant the the directives array is always
     at least as long as the overrides or validators arrays. */
    for (i = 0; i < source->directives->nelts; i++) {
        pos = mod_vhost_ldap_push_once(target->directives, target->dir_idx,
                                       APR_ARRAY_IDX(source->directives, i, char *));
        newary = apr_array_make(p, 0, sizeof(struct parse_result));
        if ((subary = APR_ARRAY_IDX(source->overrides, i, apr_array_header_t *)) != NULL) {
            for (j = 0; j < subary->nelts; j++) {
                res = APR_ARRAY_IDX(subary, j, struct parse_result);
                switch(res.type) {
                case(TT_LITERAL):
                    APR_ARRAY_PUSH(newary, struct parse_result) = res;
                    break;
                case(TT_VARIABLE):
                    /* All attributes should have been pushed above; we just do a lookup here.*/
                    newidx = mod_vhost_ldap_push_once(target->attributes, target->attr_idx,
                                                      APR_ARRAY_IDX(source->attributes,
                                                                    res.data.offset, char *));
                    APR_ARRAY_PUSH(newary, struct parse_result) =
                        (struct parse_result) { .type = res.type, .data.offset = newidx };
                    break;
                }
                mod_vhost_ldap_array_set(target->overrides, newary, pos);
            }
        }

        if ((regex = APR_ARRAY_IDX(source->validators, i, ap_regex_t *)) != NULL)
            mod_vhost_ldap_array_set(target->validators, regex, pos);
    }
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

    conf->attributes = apr_array_make(p, 0, sizeof(char *));
    /* maintain the invariant that the array is NULL-terminated */
    APR_ARRAY_PUSH(conf->attributes, char *) = NULL;
    conf->attr_idx = apr_hash_make(p);
    conf->directives = apr_array_make(p, 0, sizeof(char *));
    conf->dir_idx = apr_hash_make(p);
    conf->overrides = apr_array_make(p, 0, sizeof(apr_array_header_t *));
    conf->validators = apr_array_make(p, 0, sizeof(ap_regex_t *));
    mod_vhost_ldap_merge_onto(p, parent, conf);
    mod_vhost_ldap_merge_onto(p, child, conf);

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

static int mod_vhost_ldap_push_once(apr_array_header_t *names,
                                    apr_hash_t *offsets, const char *name)
{
    int pos;
    void *relpos = apr_hash_get(offsets, name, APR_HASH_KEY_STRING);
    if (relpos == NULL) {
        APR_ARRAY_PUSH(names, const char *) = name;
        pos = names->nelts - 1;
        apr_hash_set(offsets, name, APR_HASH_KEY_STRING, ((void *) names) + pos);
    } else {
        pos = relpos - ((void *) names);
    }
    return pos;
}

static void mod_vhost_ldap_array_set(apr_array_header_t *ary, void *value, int pos)
{
    while (ary->nelts < pos + 1) {
        APR_ARRAY_PUSH(ary, void *) = NULL;
    }
    APR_ARRAY_IDX(ary, pos, void *) = value;
}

static void *mod_vhost_ldap_array_get(apr_array_header_t *ary, int pos)
{
    if (pos < ary->nelts)
        return APR_ARRAY_IDX(ary, pos, void *);
    else
        return NULL;
}

static const char *mod_vhost_ldap_set_attributes(cmd_parms *cmd, void *dummy, const char *directive,
						 const char *template)
{
    const char *p;
    apr_array_header_t *parsed;
    char *end;
    char *variable;
    int pos;

    mod_vhost_ldap_config_t *conf = 
	(mod_vhost_ldap_config_t *)ap_get_module_config (cmd->server->module_config,
							 &vhost_ldap_module);

    parsed = apr_array_make(cmd->pool, 0, sizeof(struct parse_result));
    
    /* Pop the NULL off the end */
    apr_array_pop(conf->attributes);

    p = template;
    while (*p != '\0') {
        switch (*p) {
        case '%':
            p++;
            switch (*p) {
            case '(':
                p++;
                end = strchrnul(p, ')');
                if (*end != ')')
                    return "Unterminated substitution variable in VhostLDAPConfig template";
                variable = apr_pstrndup(cmd->pool, p, end - p);
                ap_str_tolower(variable);
                pos = mod_vhost_ldap_push_once(conf->attributes, conf->attr_idx, variable);
                APR_ARRAY_PUSH(parsed, struct parse_result) =
                    (struct parse_result) { .type = TT_VARIABLE, .data.offset = pos };
                p = end + 1;
                break;
            case '%':
                APR_ARRAY_PUSH(parsed, struct parse_result) =
                    (struct parse_result) { .type = TT_LITERAL, .data.literal = "%" };
                p++;
                break;
            default:
                return "Unescaped use of literal '%' in VhostLDAPConfig template";
            }
            break;
        default:
            end = strchrnul(p, '%');
            variable = apr_pstrndup(cmd->pool, p, end - p);
            APR_ARRAY_PUSH(parsed, struct parse_result) =
                (struct parse_result) { .type = TT_LITERAL, .data.literal = variable };
            p = end;
        }
    }

    /* NULL terminate the attribute list again */
    APR_ARRAY_PUSH(conf->attributes, char *) = NULL;
    pos = mod_vhost_ldap_push_once(conf->directives, conf->dir_idx, directive);
    mod_vhost_ldap_array_set(conf->overrides, parsed, pos);
    return NULL;
}

static char *mod_vhost_ldap_interpolate(apr_pool_t *p, apr_array_header_t *parse, const char **vals)
{
    apr_array_header_t *interpolated = apr_array_make(p, 0, sizeof(char *));
    struct parse_result entry;
    int i;
    for (i = 0; i < parse->nelts; i++) {
        entry = APR_ARRAY_IDX(parse, i, struct parse_result);
        switch(entry.type) {
        case(TT_LITERAL): APR_ARRAY_PUSH(interpolated, char *) = entry.data.literal; break;
        case(TT_VARIABLE):
	  if (vals[entry.data.offset] != NULL)
              APR_ARRAY_PUSH(interpolated, const char *) = vals[entry.data.offset];
          else
              return NULL;
        }
    }

    return apr_array_pstrcat(p, interpolated, '\0');
}

static const char *mod_vhost_ldap_set_validator(cmd_parms *cmd, void *dummy, const char *directive,
                                                const char *regex)
{
    mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config,
							&vhost_ldap_module);
    ap_regex_t *compiled = apr_palloc(cmd->pool, sizeof(ap_regex_t));
    int pos;
    if (ap_regcomp(compiled, regex, 0) != 0)
        return "Invalid VhostLDAPRegex specified";
    pos = mod_vhost_ldap_push_once(conf->directives, conf->dir_idx, directive);
    mod_vhost_ldap_array_set(conf->validators, compiled, pos);
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
    AP_INIT_TAKE2("VhostLDAPRegex", mod_vhost_ldap_set_validator, NULL, RSRC_CONF,
                  "Provide a directive and a regex that directive must match when\n"
                  "interpolated.  Used to prevent limit the damage that injection\n"
                  "from LDAP can cause."),
    {NULL}
};

#define FILTER_LENGTH MAX_STRING_LEN
static int mod_vhost_ldap_translate_name(request_rec *r)
{
    server_rec *clone;
    const char *error;
    mod_vhost_ldap_request_t *reqc;
    int failures = 0;
    const char **vals = NULL;
    char filtbuf[FILTER_LENGTH];
    mod_vhost_ldap_config_t *conf;

    util_ldap_connection_t *ldc = NULL;
    int result = 0;
    const char *dn = NULL;
    char *cgi;
    const char *hostname = "";
    int is_fallback = 0;
    int sleep0 = 0;
    int sleep1 = 1;
    int sleep;
    struct berval hostnamebv, shostnamebv;
    int ret = DECLINED;

    /* TODO: should we use the actual hostname here?  TODO: move this lower? */
    if ((error = ap_init_virtual_host(r->pool, hostname, r->server, &clone)) != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
		      "[mod_vhost_ldap.c]: Could not initialize a new VirtualHost: %s",
		      error);
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    conf = ap_get_module_config(r->server->module_config, &vhost_ldap_module);

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
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    hostname = r->hostname;
    if (hostname == NULL || hostname[0] == '\0')
        goto null;

fallback:

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		  "[mod_vhost_ldap.c]: translating hostname [%s], uri [%s]",
		  hostname, r->uri);

    ber_str2bv(hostname, 0, 0, &hostnamebv);
    if (ldap_bv2escaped_filter_value(&hostnamebv, &shostnamebv) != 0)
	goto null;
    apr_snprintf(filtbuf, FILTER_LENGTH, "(&(%s)(|(apacheServerName=%s)(apacheServerAlias=%s)))", conf->filter, shostnamebv.bv_val, shostnamebv.bv_val);
    ber_memfree(shostnamebv.bv_val);

    result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->basedn, conf->scope,
				       (char **) conf->attributes->elts, filtbuf, &dn, &vals);

    util_ldap_connection_close(ldc);

    /* sanity check - if server is down, retry it up to 5 times */
    if (AP_LDAP_IS_SERVER_DOWN(result) ||
	(result == LDAP_TIMEOUT) ||
	(result == LDAP_CONNECT_ERROR)) {
        sleep = sleep0 + sleep1;
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r,
		      "[mod_vhost_ldap.c]: lookup failure, retry number #[%d], sleeping for [%d] seconds",
		      failures, sleep);
        if (failures++ < MAX_FAILURES) {
	    /* Back-off exponentially */
	    apr_sleep(apr_time_from_sec(sleep));
	    sleep0 = sleep1;
	    sleep1 = sleep;
            goto start_over;
        } else {
	    return HTTP_GATEWAY_TIME_OUT;
	}
    }

    if (result == LDAP_NO_SUCH_OBJECT) {
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

	return HTTP_BAD_REQUEST;
    }

    /* handle bind failure */
    if (result != LDAP_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, 
                      "[mod_vhost_ldap.c] translate: "
                      "translate failed; virtual host %s; URI %s [%s]",
		      hostname, r->uri, ldap_err2string(result));
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* mark the user and DN */
    reqc->dn = apr_pstrdup(r->pool, dn);

    int i;
    for (i = 0; i < conf->directives->nelts; i++) {
        char *val;
        char *dir = APR_ARRAY_IDX(conf->directives, i, char *);
        const char *error;
        apr_array_header_t *parse;
        if((parse = mod_vhost_ldap_array_get(conf->overrides, i)) == NULL)
            continue;

        if ((val = mod_vhost_ldap_interpolate(r->pool, parse, vals)) == NULL)
            continue;

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                      "[mod_vhost_ldap.c]: setting %s to \"%s\"",
                      dir, val);

        ap_regex_t *regex;
        if ((regex = mod_vhost_ldap_array_get(conf->validators, i)) != NULL &&
            ap_regexec(regex, val, 0, NULL, 0) != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                          "[mod_vhost_ldap.c]: value for %s was \"%s\", which does not match its regex",
                          dir, val);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

	/* Pseudo-directives (hopefully a temporary hack) */
	if (!strcasecmp(dir, "SuexecUid")) {
	    reqc->uid = val;
	    continue;
	} else if (!strcasecmp(dir, "SuexecGid")) {
	    reqc->gid = val;
	    continue;
	} else if (!strcasecmp(dir, "CGIRoot")) {
	    reqc->cgiroot = val;
	    continue;
	}

        if ((error = ap_reconfigure_directive(r->pool, clone, dir, val)) != NULL) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                          "[mod_vhost_ldap.c]: error while reconfiguring %s: %s",
                          dir, error);
            return HTTP_INTERNAL_SERVER_ERROR;
	}

        /* Special cases */
        if (!strcasecmp(dir, "ErrorLog")) {
            apr_file_t* error_log;
            apr_status_t status;
            char error[512];
            if ((status = apr_file_open(&error_log, clone->error_fname,
                                        APR_APPEND|APR_WRITE|APR_CREATE,
                                        APR_FPROT_OS_DEFAULT,
                                        r->pool)) != APR_SUCCESS) {
                apr_strerror(status, error, sizeof(error));
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                              "[mod_vhost_ldap.c] could not open error log \"%s\": %s",
                              clone->error_fname, error);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            clone->error_log = error_log;
        } else if (!strcasecmp(dir, "ServerName")) {
            reqc->name = val;
        } else if (!strcasecmp(dir, "DocumentRoot")) {
            reqc->docroot = val;
        }
        /* TODO: add customlog*/
    }

    if ((reqc->name == NULL)||(reqc->docroot == NULL)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
                      "[mod_vhost_ldap.c] translate: "
                      "translate failed; ServerName or DocumentRoot not defined");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    cgi = NULL;

    if (reqc->cgiroot) {
	cgi = strstr(r->uri, "cgi-bin/");
	if (cgi && (cgi != r->uri + strspn(r->uri, "/"))) {
	    cgi = NULL;
	}
    }
    if (cgi) {
        /* Set exact filename for CGI script */
        cgi = apr_pstrcat(r->pool, reqc->cgiroot, cgi + strlen("cgi-bin"), NULL);
        if ((cgi = ap_server_root_relative(r->pool, cgi))) {
	  ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
			"[mod_vhost_ldap.c]: ap_document_root is: %s",
			ap_document_root(r));
	  r->filename = cgi;
	  r->handler = "cgi-script";
	  apr_table_setn(r->notes, "alias-forced-type", r->handler);
	  ret = OK;
	}
    } else if (strncmp(r->uri, "/~", 2) == 0) {
        /* This is a quick, dirty hack. I should be shot for taking 6.170
         * this term and being willing to write a quick, dirty hack. */    
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
	    ret = OK;
	}
    } else if (r->uri[0] == '/') {
        /* we don't set r->filename here, and let other modules do it
         * this allows other modules (mod_rewrite.c) to work as usual
	 */
        /* r->filename = apr_pstrcat (r->pool, reqc->docroot, r->uri, NULL); */
    } else {
        /* We don't handle non-file requests here */
	return DECLINED;
    }

    ap_fixup_virtual_host(r->pool, r->server, clone);
    r->server = clone;

    /* Hack to allow post-processing by other modules (mod_rewrite, mod_alias) */
    return ret;
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

    /*
     * Run before mod_rewrite
     */
    static const char * const aszRewrite[]={ "mod_rewrite.c", NULL };

    ap_hook_post_config(mod_vhost_ldap_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(mod_vhost_ldap_translate_name, NULL, aszRewrite, APR_HOOK_FIRST);
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
