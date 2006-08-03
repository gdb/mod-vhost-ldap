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
 
#include "mod_vhost_ldap.h"

module AP_MODULE_DECLARE_DATA vhost_ldap_module;
/******************************************************************/
char *pw_encrypt (const char *clear, const char *salt)
{
		//this function encrypts password in unix crypt md5 way
		extern char *crypt (__const char *__key, __const char *__salt);
        static char cipher[128];
        char *cp = crypt (clear, salt);
        strcpy (cipher, cp);
        return cipher;
}
/******************************************************************/
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
/******************************************************************/
static void *mvhl_dump_config_request ( mvhl_config *currentconf, request_rec *r) {
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "BaseDn: %s", currentconf->basedn);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "BindDn: %s", currentconf->binddn);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "BindPw: %s", currentconf->bindpw);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Deref: %d", currentconf->deref);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Enabled: %d", currentconf->enabled);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "UserFilter: %s", currentconf->filter);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "HaveLdapUrl: %d", currentconf->have_ldap_url);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "HaveDeref: %d", currentconf->have_deref);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Url: %s", currentconf->url);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Port: %d", currentconf->port);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Scope: %d", currentconf->scope);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Fallback: %s", currentconf->fallback);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "WucBaseDn: %s", currentconf->wucbasedn);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "WlcBaseDn: %s", currentconf->wlcbasedn);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "AliasesBaseDn: %s", currentconf->aliasesbasedn);
	return NULL;
}
/******************************************************************/
int header_trace(void *data, const char *key, const char *val)
{
   //usage: 
   //apr_table_do(header_trace, r, r->headers_out);
   //apr_table_do(header_trace, (void*)r, r->headers_out,"Content-type", "Content-length", NULL);
   request_rec *r = (request_rec *)data;
   ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Header Field %s == %s", key, val);
   return TRUE;
}
/******************************************************************/
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
/******************************************************************/
static apr_array_header_t *get_parsed_string_atrr_arr(request_rec * r, const char *server_alias_attrvar_line, const char *delim)
{
	/*
	 * This little piece of code creates apr_array from the string seperated by delim.
	 * It's primary usage is to get array of ldap one attribute values, which is
	 * retrieved (when multi-value) as ";" separated string.
	 */
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
/******************************************************************/
static apr_array_header_t *get_ap_reqs(apr_pool_t * p, mvhl_extconfig_object * extreqc, char *mainservername, char *userlist)
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
/******************************************************************/
static void mvhl_dovhostconfig(request_rec * r, char *attributes[], const char **vals, mvhl_request * reqc)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Entering vhost configuration");
	/*
	 * we got 10 attributes to search for, counting from 0 to 9
	 */
	int i;
	for ( i = 0; i <= 9; i++ ) {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " VhostConfig Iteration %d :: will get %s", i, attributes[i]);
      switch (i) {
      	/* 0 apacheServerName */
		case 0: reqc->name = apr_pstrdup(r->pool, vals[i]);	break;
	   	/* 1 apacheServerAlias - may be null */	
		case 1: reqc->serveralias = (vals[i]) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, vals[i],(const char *) ";") : NULL; break;
		/* 2 apacheDocumentRoot */
		case 2:	reqc->docroot = apr_pstrdup(r->pool, vals[i]); break;
		/* 3 apacheSuexecUid */
		case 3: reqc->uid = (vals[i]) ? apr_pstrdup(r->pool, vals[i]) : reqc->uid ; break;
		/* 4 apacheSuexecGid */
		case 4: reqc->gid = (vals[i]) ? apr_pstrdup(r->pool, vals[i]): reqc->gid ; break;
		/* 5 apacheServerAdmin */			
		case 5:	reqc->admin = (vals[i]) ? apr_pstrdup(r->pool, vals[i]) : NULL ; break;
		/* 6 apacheExtConfigHasRequireLine */
		//if there's no HasRequireLine attribute set we assume we don't have reqlines			
		case 6:	reqc->has_reqlines = (vals[i] && strcasecmp("TRUE", apr_pstrdup(r->pool, vals[i])) == 0) ?  1 : 0; break;			
		/* 7 apacheLocationOptionsDn */
		case 7:	reqc->rqlocationlines = (vals[i]) ? reqc->rqlocationlines = (apr_array_header_t *) get_parsed_string_atrr_arr(r, vals[i], (const char *) ";") : NULL ; break;			
		/* 8 apacheAliasesConfigEnabled */
		case 8: reqc->has_aliaslines = ( vals[i] && strcasecmp("TRUE", apr_pstrdup(r->pool, vals[i])) == 0 ) ? 1 : 0; break; 				
		/* 9 apacheAliasConfigOptionsDn */							
		case 9: reqc->aliaseslines = (vals[i]) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, vals[i], (const char *) ";") : NULL;	
	  }
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Leaving vhost configuration , exit assignments: ");
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, " apacheServerName \'%s\'", reqc->name);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, " apacheServerAdmin \'%s\'", reqc->admin);    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, " apacheDocumentRoot \'%s\'", reqc->docroot);    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, " apacheSuexecUid \'%s\'", reqc->uid);    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, " apacheSuexecGid \'%s\'", reqc->gid);
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
    	/* following three lines evaluates to one string in which final argument (fourth line) is substituted */ 
    	(reqc->has_reqlines && reqc->rqlocationlines ) ? 
    	apr_pstrdup(r->pool, "vhost \'%s\' has access control") : 
    	apr_pstrdup(r->pool, " vhost \'%s\' doesn't have access control"), 
    	reqc->name);
    		
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
   		/* following three lines evaluates to one string in which final argument (fourth line) is substituted */ 
   		(reqc->has_aliaslines && reqc->has_aliaslines ) ? 
   		apr_pstrdup(r->pool, "vhost \'%s\' has dir aliases") : 
   		apr_pstrdup(r->pool, " vhost \'%s\' doesn't have dir aliases"), 
   		reqc->name);    
}
/******************************************************************/
static void mvhl_doextconfig(request_rec * r, char *extconfigattributes[], const char **extconfvals, mvhl_extconfig_object * extreqc)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Entering Access Control config");
	/*
	 * we got 6 attributes to search for, counting from 0 to 5
	 */
	int i = 0;
	for ( i = 0; i <= 5; i++ ) {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Vhost Access Control Iteration %d :: will get %s", i, extconfigattributes[i]);
      switch (i) {
	/* 0 apacheExtConfigUri */
		case 0:	extreqc->exturi = (extconfvals[i]) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, extconfvals[i], (const char *) ";") : NULL ; break;
	/* 1 apacheExtConfigRequireValidUser 
		 * this value determines whether we have "require valid-user" object  (TRUE) , 
		 * or (FALSE) object "require user johny mary dorothy witch"
		 * here set retrieved value, regardless what it is, to play with it later.
		 */	
		case 1:	extreqc->extconftype = (extconfvals[i] && strcasecmp("TRUE", apr_pstrdup(r->pool, extconfvals[i])) == 0) ? 1 : 0; break; 
	/* 2 apacheExtConfigServerName */
		case 2:	extreqc->extservername = (extconfvals[i]) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, extconfvals[i], (const char *) ";") : NULL ; break; 
	/* 3 apacheExtConfigObjectName */
		case 3:	extreqc->extconfname = apr_pstrdup(r->pool, extconfvals[i]); break;
	/* 4 apacheExtConfigUserDn */
		case 4:
		extreqc->extusers = (extconfvals[i]) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, extconfvals[i], (const char *) ";") : NULL; break;
	/* 5 apacheExtConfigPath */
		case 5:
		extreqc->extdir = (extconfvals[i]) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, extconfvals[i], (const char *) ";") : NULL ; break;
      }
	}
	
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Leaving Access Control config :: exit assignments");
	
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " This Access Object prompt is \'%s\'", extreqc->extconfname);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		(extreqc->exturi ) ?
		apr_pstrdup(r->pool, " \'%s\' extConfigUri has at least one URI value") : 
    	apr_pstrdup(r->pool, " \'%s\' has no extConfigUri assigned"), 
		extreqc->extconfname);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		(extreqc->extdir ) ?
		apr_pstrdup(r->pool, " \'%s\' extConfigPath has at least one directory value") : 
    	apr_pstrdup(r->pool, " \'%s\' has no extConfig assigned"), 
		extreqc->extconfname);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		/* following three lines evaluates to one string in which final argument (fourth line) is substituted */ 
		(extreqc->extconftype) ? 
    	apr_pstrdup(r->pool, " \'%s\' requires valid-user") : 
    	apr_pstrdup(r->pool, " \'%s\' requires user from userlist"), 
    	extreqc->extconfname) ;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		/* following three lines evaluates to one string in which final argument (fourth line) is substituted */	 
		(extreqc->extservername ) ?
    	apr_pstrdup(r->pool, " \'%s\' has at least one serverName assigned") : 
    	apr_pstrdup(r->pool, " \'%s\' has no assigned serverNames"), 
    	extreqc->extconfname);
   	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		/* following three lines evaluates to one string in which final argument (fourth line) is substituted */   	 
   		(extreqc->extusers ) ? 
    	apr_pstrdup(r->pool, " \'%s\' has at least one webuser object assigned") : 
    	apr_pstrdup(r->pool, " \'%s\' has no assigned webusers objects"),
    	extreqc->extconfname );
    
}
/******************************************************************/
static void mvhl_doextuserconfig(request_rec * r, char *ldap_webuser_attributes[], const char **extuservals, mvhl_webuser * extuserreqc, char * prefix)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Entering extwebuser Config");
    /*
	 * we got 5 attributes to search for, counting from 0 to 4
	 */
	int i = 0;
	for ( i = 0; i <= 4; i++ ) {
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "%s Web user Iteration %d :: will get %s", prefix, i, ldap_webuser_attributes[i]);
      switch (i) {
    	/* 0 apacheExtConfigUserName */
		case 0:	
			extuserreqc->webusername = apr_pstrdup(r->pool, extuservals[i]);
			break;
		/* 1 apacheExtConfigUserServerName */
		case 1: 
			extuserreqc->webuserserver = ( extuservals[i] ) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, extuservals[i], (const char *) ";") : NULL;
			break;
		/* 2 apacheExtConfigUserDirectoryName */
		case 2: 
			extuserreqc->webuserdirectory =	( extuservals[i] ) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, extuservals[i], (const char *) ";") : NULL;
			break;
		case 3:
		/* 3 apacheExtConfigUserLocationUri */
			extuserreqc->webuserlocationuri = ( extuservals[i] ) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, extuservals[i], (const char *) ";") : NULL;
			break;
		/* 4 userPassword */
		case 4: 
			extuserreqc->webuserpassword =	( extuservals[i] ) ? (apr_array_header_t *) get_parsed_string_atrr_arr(r, extuservals[i], (const char *) ";") : NULL;
			break;
		}
	}
     ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "  Leaving extwebuser Config :: exit assignments");
     ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " This webuser name is \'%s\'", extuserreqc->webusername);
     ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
         /* following three lines evaluates to one string in which final argument (fourth line) is substituted */ 
     	( extuserreqc->webuserserver ) ? 	
     	apr_pstrdup(r->pool, " \'%s\' has at least one server assigned") : 
    	apr_pstrdup(r->pool, " \'%s\' has no serverNames assigned"), 
    	extuserreqc->webusername );
     ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
     	/* following three lines evaluates to one string in which final argument (fourth line) is substituted */ 
     	( extuserreqc->webuserpassword ) ? 	
     	apr_pstrdup(r->pool, " \'%s\' has at least one password assigned") : 
    	apr_pstrdup(r->pool, " \'%s\' has no passwords assigned"), 
    	extuserreqc->webusername );
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
     	/* following three lines evaluates to one string in which final argument (fourth line) is substituted */ 
     	( extuserreqc->webuserdirectory ) ? 	
     	apr_pstrdup(r->pool, " \'%s\' has at least one physical directory assigned") : 
    	apr_pstrdup(r->pool, " \'%s\' has no physical directories assigned"), 
    	extuserreqc->webusername );
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
     	/* following three lines evaluates to one string in which final argument (fourth line) is substituted */ 
     	( extuserreqc->webuserlocationuri ) ? 	
     	apr_pstrdup(r->pool, " \'%s\' has at least one location assigned") : 
    	apr_pstrdup(r->pool, " \'%s\' has no locations assigned"), 
    	extuserreqc->webusername );
	
}
/******************************************************************/
static void mvhl_doaliasesconfig(request_rec * r, char *aliases_attributes[], const char **aliasesvals, mvhl_aliasconf_object * aliasreqc){
	
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Entering aliasObject Config");
    /*
	 * we got 4 attributes to search for, counting from 0 to 3
	 */
	int i = 0;

	for (i = 0; i <= 3; i++ ) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Alias config Iteration %d :: will get %s", i, aliases_attributes[i]);
		switch (i) {
		/* 0 apacheAliasConfigSourceUri */
		case 0:	
			aliasreqc->aliassourceuri = (apr_array_header_t *) get_parsed_string_atrr_arr(r, aliasesvals[i], (const char *) ";");
			//aliasreqc->aliassourceuri = apr_pstrdup(r->pool, aliasesvals[i]);
			break;
		/* 1 apacheAliasConfigServerName - MULTI-VALUE */
		case 1: 
			aliasreqc->aliasconfservername = (apr_array_header_t *) get_parsed_string_atrr_arr(r, aliasesvals[i], (const char *) ";");
			break;
		/* 2 apacheAliasConfigTargetDir */
		case 2: 
			aliasreqc->aliastargetdir = apr_pstrdup(r->pool, aliasesvals[i]);
			break;
		/* 3 apacheAliasConfigObjectName */
		case 3:
			aliasreqc->aliasconfname = apr_pstrdup(r->pool, aliasesvals[i]);
			break;
		}
	}
	 ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "  Leaving alias Config :: exit assignments");
	 /* defined ldap schema force alias object to have all of these attributes, so there's no way for existing object without any of them*/
     ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " This alias config object name is \'%s\'", aliasreqc->aliasconfname);
     ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " \'%s\' has at least one SourceUri assigned", aliasreqc->aliasconfname);
     ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " \'%s\' target dir is \'%s\'", aliasreqc->aliasconfname, aliasreqc->aliastargetdir);
	 ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, apr_pstrdup(r->pool, " \'%s\' has at least one serverName assigned"), aliasreqc->aliasconfname );
}
/******************************************************************/
static int mvhl_authenticate_basic_user(request_rec * r)
{
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " Entering mvhl_authenticate_basic_user");
	const char *sent_pw;
    mvhl_webuser *extuserreqc = (mvhl_webuser *) apr_pcalloc(r->pool, sizeof(mvhl_webuser));
	int rc = ap_get_basic_auth_pw(r, &sent_pw);
	if(rc != OK) return rc;

	if(strtrue(r->user) && strtrue(sent_pw)) {
		int result = 0;
		char userfilter[FILTER_LENGTH];
		const char *dn = NULL;
		const char **extuservals = NULL;
		util_ldap_connection_t *ldc = NULL;
		char *prefix = "mvhl_authenticate.. :";
		char *ldap_webuser_attributes[] = { "apacheExtConfigUserName","apacheExtConfigUserServerName","apacheExtConfigUserDirectoryName","apacheExtConfigUserLocationUri","userPassword",0};
		mvhl_config *conf = (mvhl_config *) ap_get_module_config(r->server->module_config, &vhost_ldap_module);
		
		apr_snprintf(userfilter, FILTER_LENGTH, "(&(%s)(objectClass=apacheExtendedConfigUserObject)(apacheExtConfigUserName=%s))", conf->filter, r->user);
		
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " AuthUser search filter: %s", userfilter);
		ldc = util_ldap_connection_find(r, conf->host, conf->port, conf->binddn, conf->bindpw, conf->deref, conf->secure);
		result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->wucbasedn, conf->scope, ldap_webuser_attributes, userfilter, &dn, &extuservals);
		util_ldap_connection_close(ldc);

		if(extuservals) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, " User %s found.", r->user);

			mvhl_doextuserconfig(r, ldap_webuser_attributes, extuservals, extuserreqc, prefix);

			int x = 0;
			//we're checking for each password - if any matches, then we return immediately
			char **passwords = (char **) extuserreqc->webuserpassword->elts;

			for (x = 0; x < extuserreqc->webuserpassword->nelts; x++) {
				if ( apr_password_validate(sent_pw, passwords[x]) == OK ) 
				{
				ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, " APR authentication for user %s at %s successful.", extuserreqc->webusername, r->server->server_hostname);
				return OK; 
				}
				
				char *prefix = "{CRYPT}";
				int prefixlen = 7;
				if ( strcasecmp( apr_pstrndup(r->pool, passwords[x], prefixlen ), prefix ) == 0 ) {
					char *stripped = passwords[x] + prefixlen;
					char *userinputhash = pw_encrypt (sent_pw, stripped );
					ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, " User entered: \'%s\' ", sent_pw );				
					ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, " Retrieved value: \'%s\'", passwords[x] );
					ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, " Retrieved value (stripped): \'%s\'", stripped );
					ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, " User input hash: \'%s\'", userinputhash );
					if ( strcasecmp( userinputhash , stripped ) == 0 ) 
					{
						ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, " Unix authentication for user %s at %s successful.", extuserreqc->webusername, r->server->server_hostname);
						return OK; 
					}
				}
				
				if ( strcasecmp(sent_pw,passwords[x]) == 0 ) 
				{
				ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, " Clear text authentication for user %s at %s successful.", extuserreqc->webusername, r->server->server_hostname);
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
/******************************************************************/
static int check_mvhl_auth_require(char *user, const char *t, request_rec * r)
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
		      ": %s : Reached end of check_mvhl_auth_require!", r->server->server_hostname);
	return HTTP_INTERNAL_SERVER_ERROR;
}
/******************************************************************/
static int mvhl_check_auth(request_rec * r)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
              ": mvhl_check_auth, parsing existing ap_requires for %s at %s ", r->user, r->server->server_hostname);
	char *user = r->user;
	int rv;
	register int x;
	const char *t;
	const apr_array_header_t *reqs_arr = ap_requires(r);

	require_line *reqs;
	reqs = (require_line *) reqs_arr->elts;

	for (x = 0; x < reqs_arr->nelts; x++) {
		t = reqs[x].requirement;
		if((rv = check_mvhl_auth_require(user, t, r)) != HTTP_UNAUTHORIZED) {
			return rv;
		}
	}


	ap_note_basic_auth_failure(r);
	return HTTP_UNAUTHORIZED;
}
/******************************************************************/
static void *mvhl_create_sconfig(apr_pool_t * p, server_rec * s)
{
	//ldap://host[:port]/basedn[?attrib[?scope[?filter]]]
	mvhl_config *conf 	= (mvhl_config *) apr_pcalloc(p, sizeof(mvhl_config));
	conf->enabled 		= 0;
	conf->have_ldap_url = 0;
	conf->have_deref 	= 0;
	conf->scope			= LDAP_SCOPE_SUBTREE;
	conf->deref			= never;
	conf->host			= NULL;
	conf->port			= 389;
	conf->url			= NULL;
	conf->filter		= NULL;
	conf->binddn 		= NULL;
	conf->bindpw 		= NULL;
	conf->basedn		= NULL;
	conf->wlcbasedn 	= NULL;
	conf->wucbasedn 	= NULL;
	conf->aliasesbasedn = NULL;
	conf->fallback		= NULL;
	conf->secure			= 0;
	conf->alias_enabled		= 0;
	conf->loc_auth_enabled 	= 0;
	conf->dir_auth_enabled 	= 0;
	return conf;
}
/******************************************************************/
static void *mvhl_merge_sconfig(apr_pool_t * p, void *parentv, void *childv)
{
	mvhl_config *parent = (mvhl_config *) parentv;
	mvhl_config *child = (mvhl_config *) childv;
	mvhl_config *conf = (mvhl_config *) apr_pcalloc(p, sizeof(mvhl_config));
	
	conf->enabled 		= (child->enabled 		? child->enabled : parent->enabled);
	conf->binddn 		= (child->binddn 		? child->binddn : parent->binddn);
	conf->bindpw 		= (child->bindpw 		? child->bindpw : parent->bindpw);
	conf->fallback 		= (child->fallback 		? child->fallback : parent->fallback);
	conf->alias_enabled = (child->alias_enabled ? child->alias_enabled : parent->alias_enabled);
	conf->loc_auth_enabled 	= (child->loc_auth_enabled 	? child->loc_auth_enabled : parent->loc_auth_enabled);
	conf->dir_auth_enabled 	= (child->dir_auth_enabled 	? child->dir_auth_enabled : parent->dir_auth_enabled);

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
		conf->aliasesbasedn = child->aliasesbasedn;
	}
	else 
	{
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
		conf->aliasesbasedn = parent->aliasesbasedn;
	}
	if(child->have_deref) {
		conf->have_deref = child->have_deref;
		conf->deref = child->deref;
	}
	else 
	{
		conf->have_deref = parent->have_deref;
		conf->deref = parent->deref;
	}
	return conf;
}
/******************************************************************/
static const char *conf_mvhl_url(cmd_parms * cmd, void *dummy, const char *url)
{
	int result;
	apr_ldap_url_desc_t *urld;

	mvhl_config *conf =	(mvhl_config *) ap_get_module_config(cmd->server->module_config, &vhost_ldap_module);
	result = apr_ldap_url_parse(url, &(urld));
	
	if(result != LDAP_SUCCESS) {
		switch (result) {
			case LDAP_URL_ERR_MEM: 			return "0x01 can't allocate memory space";
			case LDAP_URL_ERR_PARAM: 		return "0x02 parameter is bad";
			case LDAP_URL_ERR_BADSCHEME: 	return "0x03 URL doesn't begin with ldap[si]://";
			case LDAP_URL_ERR_BADENCLOSURE: return "0x04 URL is missing trailing >";
			case LDAP_URL_ERR_BADURL: 		return "0x05 URL is bad";
			case LDAP_URL_ERR_BADHOST: 		return "0x06 host port is bad";
			case LDAP_URL_ERR_BADATTRS: 	return "0x07 bad (or missing) attributes";
			case LDAP_URL_ERR_BADSCOPE: 	return "0x08 scope string is invalid (or missing)";
			case LDAP_URL_ERR_BADFILTER: 	return "0x09 bad or missing filter";
			case LDAP_URL_ERR_BADEXTS: 		return "0x0a bad or missing extensions";
			default:						return "Could not parse LDAP URL";
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
			 * Get rid of the surrounding parentheses; 
			 * later on when generating the
			 * filter, they'll be put back.
			 */
			conf->filter = apr_pstrdup(cmd->pool, urld->lud_filter + 1);
			conf->filter[strlen(conf->filter) - 1] = '\0';
		}
		else {
			conf->filter = apr_pstrdup(cmd->pool, urld->lud_filter);
		}
	}
	/*else {
		conf->filter = "objectClass=apacheConfig";
	}*/

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
/******************************************************************/
static const char *conf_mvhl(cmd_parms *cmd, void *dummy, const char *confval) {
	
	if ( strlen(confval) == 0 ) { return NULL; }
	  
	{
		//we're getting currently set (or default from mvhl_create_config if not set already)
		mvhl_config *conf = (mvhl_config *) ap_get_module_config(cmd->server->module_config, &vhost_ldap_module);
		int *cmdtype = (int *) cmd->info;
		char *currval = apr_pstrdup(cmd->pool, confval);
		switch (*cmdtype) {
			case 1:
				conf->enabled = ( strcmp(currval,"On") == 0 )? 1 : 0;	
				break;
			case 2:
				conf->binddn = currval;
				break;
			case 3: 
				conf->bindpw = currval;
				break;
			case 4: 
				//const values: never =  0, searching = 1, finding = 2, always = 3
				if ( strcmp(currval,"never") 	== 0 ) { conf->deref = never; conf->have_deref 		= 1;}
				if ( strcmp(currval,"searching")== 0 ) { conf->deref = searching; conf->have_deref 	= 1;}
				if ( strcmp(currval,"finding") 	== 0 ) { conf->deref = finding; conf->have_deref 	= 1;}
				if ( strcmp(currval,"always") 	== 0 ) { conf->deref = always; conf->have_deref 	= 1;}
				break;				
			case 5:	
				conf->wlcbasedn = currval;
				break;
			case 6:	
				conf->wucbasedn = currval;
				break;
			case 7:
				conf->fallback = currval;
				break;
			case 8:
				conf->aliasesbasedn = currval;
				break;
			case 9:
				conf->alias_enabled = ( strcmp(currval,"On") == 0 )? 1 : 0 ;
				break;
			case 10:
				conf->loc_auth_enabled = ( strcmp(currval,"On") == 0 )? 1 : 0;
				break;
			case 11:
				conf->dir_auth_enabled = ( strcmp(currval,"On") == 0 )? 1 : 0;
				break;
		}
		return NULL;
	}
	
}
/******************************************************************/
static int apply_vhost(mvhl_config *conf, const char *hostname, request_rec * r, util_ldap_connection_t *ldc, const char *dn, mvhl_request *reqc  ) {

	char filtbuf[FILTER_LENGTH];
	apr_snprintf(filtbuf, FILTER_LENGTH, "(&(%s)(|(apacheServerName=%s)(apacheServerAlias=%s)))", conf->filter, hostname, hostname);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"Server search filter: %s", filtbuf);
	const char **vals 				= NULL;
	char *attributes[] 				= { "apacheServerName", "apacheServerAlias", "apacheDocumentRoot", "apacheSuexecUid","apacheSuexecGid","apacheServerAdmin","apacheExtConfigHasRequireLine","apacheLocationOptionsDn","apacheAliasesConfigEnabled","apacheAliasConfigOptionsDn",0 };
	int failures 	= 0;
	int result 		= LDAP_SERVER_DOWN;
	while(failures++ <= 5 && result == LDAP_SERVER_DOWN) {
		result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->basedn, conf->scope, attributes, filtbuf, &dn, &vals);
	}

	/* 
     * we don't test conf->host nor connection, because if these failed, declined was already returned
     * instead, we do a search for specified fallback vhost
     */ 
    if ( result == LDAP_NO_SUCH_OBJECT ) 
    {
    	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Vhost %s not found, will try to fall-back to defined vhost: %s", hostname, conf->fallback);
    	hostname = conf->fallback;
		apr_snprintf(filtbuf, FILTER_LENGTH, "(&(%s)(|(apacheServerName=%s)(apacheServerAlias=%s)))", conf->filter, hostname, hostname);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"Server search filter: %s", filtbuf);
		result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->basedn, conf->scope, attributes, filtbuf, &dn, &vals);
    }
    
	if(result != LDAP_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"Vhost %s defined as fallback not found, err %s", hostname, ldap_err2string(result));
		return 0; 
	}

	reqc->dn = apr_pstrdup(r->pool, dn);
	if (vals) { mvhl_dovhostconfig(r, attributes, vals, reqc); }

	if( (reqc->name == NULL) || (reqc->docroot == NULL) || ! (r->uri[0] == '/') ) return 0;
	r->filename = apr_pstrcat(r->pool, reqc->docroot, r->uri, NULL);
	return 1;
	
}
/******************************************************************/
static void apply_aliasing(mvhl_request *reqc, request_rec * r, mvhl_config *conf, util_ldap_connection_t *ldc, const char *dn) {

	if(reqc->has_aliaslines == 1 && reqc->aliaseslines ) {
		const char **aliasesconfvals	= NULL;
		char aliasesfilter[FILTER_LENGTH];
		char *aliases_attributes[] 		= { "apacheAliasConfigSourceUri", "apacheAliasConfigServerName", "apacheAliasConfigTargetDir", "apacheAliasConfigObjectName",0 };
		mvhl_aliasconf_object *aliasreqc = (mvhl_aliasconf_object *) apr_pcalloc(r->pool, sizeof(mvhl_aliasconf_object));
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"This vhost has alias configuration, need to check if for current uri");
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Original r->filename: %s", r->filename);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Original r->uri: %s", r->uri);
		int i = 0;	
		int result = 0;

		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Entering Alias Objects search");
		while(i <= strlen(apr_pstrdup(r->pool, r->uri)) && !aliasesconfvals ) {
			i++;
			char *aliasbuff = apr_pstrndup(r->pool, r->uri, i);
			apr_snprintf(aliasesfilter, FILTER_LENGTH,"(&(%s)(apacheAliasConfigServerName=%s)(apacheAliasConfigSourceUri=%s))", conf->filter, reqc->name, aliasbuff);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"Alias Object search filter: %s", aliasesfilter);
			/* we reuse ldap connection opened previously with alias entries, 
	 		* access control entries and webusers entries searches changing used filter as needed (!!) */
			result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->aliasesbasedn, conf->scope, aliases_attributes, aliasesfilter, &dn, &aliasesconfvals);
		}
		
		if(result != LDAP_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"This vhost aliases config, but probably not for this URI, alias config entry not found");
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"Tried with ldap search filter: %s", aliasesfilter);
		}
		else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"This uri has aliases config, configuration object found");
			if(aliasesconfvals) { mvhl_doaliasesconfig(r, aliases_attributes, aliasesconfvals, aliasreqc); }
			ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "Entering alias substitution");
			r->filename = apr_pstrcat (r->pool, aliasreqc->aliastargetdir , r->uri + i, NULL);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Final filename r->filename: %s", r->filename);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Final uri (unchanged) r->uri: %s", r->uri);
		}
		
	}
	else
	{
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "This vhost has no aliases, or it is disabled via apacheAliasesConfigEnabled = (FALSE|not set) skipping..");
	} 
}
/******************************************************************/
static void apply_location_access_control(mvhl_request *reqc, request_rec * r, mvhl_config *conf, util_ldap_connection_t *ldc, const char *dn) {

	if(reqc->has_reqlines == 1 && reqc->rqlocationlines) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"LAC: This vhost has location access control configured, need to check if it's enabled for current uri");
		int result = 0;
		int i = 0;
		char extconffiltbuf[FILTER_LENGTH];
		const char **extconfvals 		= NULL;
		char *extconfigattributes[] 	= { "apacheExtConfigUri","apacheExtConfigRequireValidUser","apacheExtConfigServerName","apacheExtConfigObjectName","apacheExtConfigUserDn","apacheExtConfigPath",0}; 
		mvhl_extconfig_object *extreqc = (mvhl_extconfig_object *) apr_pcalloc(r->pool, sizeof(mvhl_extconfig_object));
		char *buff =  NULL;
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "LAC: Entering extConfig Location Objects search");
		while(i <= strlen(apr_pstrdup(r->pool, r->uri)) && !extconfvals) {
			i++;
			buff = apr_pstrndup(r->pool, r->uri, i);
			/*
			 * ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"Searching for hostname %s and URI %s, origname is %s", hostname, buff, reqc->name);
			 * uncomment this, if You'd like to see in log how uri gets checked
			 * ap_log_error(APLOG_MARK,APLOG_DEBUG,OK,NULL,"%s", buff);

			 * well, we must had been connecting already, so we don't do more ldap server connection checks,
			 * and we're doing a search with cache_getuser instead of using extConfigObject dn apacheConfig object attribute value(s),
			 * because there's no convenient function in apr api.
			 * vhost location RDN attribute is used actually by some GUI to make things easier
			 * TODO: use some generic ldap functions (?) classic search or implement more ldap routines for apr

			 * so, we do a search below locationDnBase for config object with matches current hostname and uri..
			 * note, that we took our current uri, and we're searching starting from / adding one by one chararacter
			 * to match config object - access config is always the same as first matching upper url access config.
			 * and more - if someone defined accessobject for /main and /main/subdir, the first one is used.
			 * when upper is deleted - next below is returned, and so far..
			 * and more - if there are two or more extConfig object for the same combination of server/uri,
			 * then first found is returned and search isn't processed further.

			 * we do a search based on original reqc->name instead of current hostname, to apply rules even if we're accessing
			 * site via ServerAlias name
			 */
			apr_snprintf(extconffiltbuf, FILTER_LENGTH,"(&(%s)(apacheExtConfigServerName=%s)(apacheExtConfigUri=%s))", conf->filter, reqc->name, buff);
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"LAC: ExtConfig Location Object search filter: %s", extconffiltbuf);
			result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->wlcbasedn, conf->scope, extconfigattributes, extconffiltbuf, &dn, &extconfvals);
			//matched URI, if found, is returned anyway with extconfvals as ldap attribute value.
		}

		if(result != LDAP_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"LAC: This vhost has access control, but probably not for this URI, access config entry not found");
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"LAC: Tried with ldap search filter: %s", extconffiltbuf);
		}
		else 
		{
			
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"LAC: This uri has access control, configuration object is found");
			//we set all into extreqc struct
			//ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Entering extconfig buffer fill");
			if(extconfvals) { mvhl_doextconfig(r, extconfigattributes, extconfvals, extreqc); }

			ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "LAC: Entering ap_requires generation process");
			core_dir_config *coredirconf = (core_dir_config *) ap_get_module_config(r->per_dir_config, &core_module);
			coredirconf->ap_auth_name = extreqc->extconfname;
			coredirconf->ap_auth_type = (char *) "basic";
			char *userlist = "user nobody";

            /*
            st = (util_ldap_state_t *)ap_get_module_config(r->server->module_config, &ldap_module);
            st->search_cache_ttl = 0;
            */
            char userfilter[FILTER_LENGTH];
            /* we'll search for user object with custom filter applied, which has assigned matched location name and which has assigned current servername */
            apr_snprintf(userfilter, FILTER_LENGTH, "(&(%s)(objectClass=apacheExtendedConfigUserObject)(apacheExtConfigUserServerName=%s)(apacheExtConfigUserLocationUri=%s))", conf->filter, reqc->name, buff);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"LAC: User search filter: %s", userfilter);

            mvhl_webuser *extuserreqc = (mvhl_webuser *) apr_pcalloc(r->pool, sizeof(mvhl_webuser));
            int i = 0;    
			if(extreqc->extusers) {
                log_dump_apr_array(r,extreqc->extusers,"extUser");
                char **extuserdns = (char **) extreqc->extusers->elts;
				for (i = 0; i < extreqc->extusers->nelts; i++) {
					const char **extuservals = NULL;
					int result = 0;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "LAC: User search basedn: %s", extuserdns[i]);
                    //we don't use wucbasedn as we already know what webuser distinguishedname can be
					char *ldap_webuser_attributes[] = { "apacheExtConfigUserName","apacheExtConfigUserServerName","apacheExtConfigUserDirectoryName","apacheExtConfigUserLocationUri","userPassword",0};
					result = util_ldap_cache_getuserdn(r, ldc, conf->url, extuserdns[i], LDAP_SCOPE_BASE, ldap_webuser_attributes, userfilter, &dn, &extuservals);
					if(extuservals) {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "LAC: Val 0: %s", extuservals[0]);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "LAC: Val 1: %s", extuservals[1]);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "LAC: Val 2: %s", extuservals[2]);
                        char *prefix = "LAC: ";
						mvhl_doextuserconfig(r, ldap_webuser_attributes, extuservals, extuserreqc,prefix);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "LAC: current username: %s", extuserreqc->webusername);
                        userlist = apr_pstrcat(r->pool, userlist, " ", extuserreqc->webusername, NULL);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "LAC: current userlist: %s", userlist);
					}
				}
			}
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "LAC: final userlist: %s ", userlist);
			ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "LAC: AuthName set to %s", coredirconf->ap_auth_name);
			ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "LAC: AuthType set to %s", coredirconf->ap_auth_type);
			ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "LAC: Preparing access control line");
			coredirconf->ap_requires = (apr_array_header_t *) get_ap_reqs(r->pool, extreqc, reqc->name, userlist);
		}
	}
	else {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "LAC: This vhost is not configured for access control, or it is disabled via apacheExtConfigHasRequireLine = ( FALSE|not set) skipping..");
	}
}
/******************************************************************/
static void apply_directory_access_control(mvhl_request *reqc, request_rec * r, mvhl_config *conf, util_ldap_connection_t *ldc, const char *dn) {

	int result = 0;
	int i = 0;
	char extconffiltbuf[FILTER_LENGTH];
	const char **extconfvals 		= NULL;
	char *extconfigattributes[] 	= { "apacheExtConfigUri","apacheExtConfigRequireValidUser","apacheExtConfigServerName","apacheExtConfigObjectName","apacheExtConfigUserDn","apacheExtConfigPath",0}; 
	mvhl_extconfig_object *extreqc 	= (mvhl_extconfig_object *) apr_pcalloc(r->pool, sizeof(mvhl_extconfig_object));
	char *buff = NULL;
	
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "DAC: Entering extConfig Directory Objects search");
	while(i <= strlen(apr_pstrdup(r->pool, r->filename)) && !extconfvals) {
		i++;
		buff = apr_pstrndup(r->pool, r->filename, i);
		/*
		 * ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"Searching for hostname %s and URI %s, origname is %s", hostname, buff, reqc->name);
		 * uncomment this, if You'd like to see in log how uri gets checked
		 * ap_log_error(APLOG_MARK,APLOG_DEBUG,OK,NULL,"%s", buff);

		 * well, we must had been connecting already, so we don't do more ldap server connection checks,
		 * and we're doing a search with cache_getuser instead of using extConfigObject dn apacheConfig object attribute value(s),
		 * because there's no convenient function in apr api.
		 * vhost location RDN attribute is used actually by some GUI to make things easier
		 * TODO: use some generic ldap functions (?) classic search or implement more ldap routines for apr

		 * so, we do a search below locationDnBase for config object with matches current hostname and uri..
		 * note, that we took our current uri, and we're searching starting from / adding one by one chararacter
		 * to match config object - access config is always the same as first matching upper url access config.
		 * and more - if someone defined accessobject for /main and /main/subdir, the first one is used.
		 * when upper is deleted - next below is returned, and so far..
		 * and more - if there are two or more extConfig object for the same combination of server/uri,
		 * then first found is returned and search isn't processed further.

		 * we do a search based on original reqc->name instead of current hostname, to apply rules even if we're accessing
		 * site via ServerAlias name
		 */
		apr_snprintf(extconffiltbuf, FILTER_LENGTH,"(&(%s)(apacheExtConfigPath=%s))", conf->filter, buff);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"DAC: ExtConfig Directory Object search filter: %s", extconffiltbuf);
		result = util_ldap_cache_getuserdn(r, ldc, conf->url, conf->wlcbasedn, conf->scope, extconfigattributes, extconffiltbuf, &dn, &extconfvals);
		//matched dir, if found, is returned anyway with extconfvals as ldap attribute value.
	}

	if(result != LDAP_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"DAC: For current directory access config entry is not found");
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"DAC: Tried with ldap search filter: %s", extconffiltbuf);
	}
	else 
	{
		
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"DAC: This directory has access control, configuration object is found");
		//we set all into extreqc struct
		//ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Entering extconfig buffer fill");
		if(extconfvals) { mvhl_doextconfig(r, extconfigattributes, extconfvals, extreqc); }

		ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "DAC: Entering ap_requires generation process");
		core_dir_config *coredirconf = (core_dir_config *) ap_get_module_config(r->per_dir_config, &core_module);
		coredirconf->ap_auth_name = extreqc->extconfname;
		coredirconf->ap_auth_type = (char *) "basic";
		char *userlist = "user nobody";

        /*
        st = (util_ldap_state_t *)ap_get_module_config(r->server->module_config, &ldap_module);
        st->search_cache_ttl = 0;
        */
        char userfilter[FILTER_LENGTH];
        /* we'll search for user object with custom filter applied, which has assigned matched directory name */
        apr_snprintf(userfilter, FILTER_LENGTH, "(&(%s)(objectClass=apacheExtendedConfigUserObject)(apacheExtConfigUserDirectoryName=%s))", conf->filter, buff);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,"DAC: User search filter: %s", userfilter);

        mvhl_webuser *extuserreqc = (mvhl_webuser *) apr_pcalloc(r->pool, sizeof(mvhl_webuser));
		char *ldap_webuser_attributes[] = { "apacheExtConfigUserName","apacheExtConfigUserServerName","apacheExtConfigUserDirectoryName","apacheExtConfigUserLocationUri","userPassword",0};

        int i = 0;    
		if(extreqc->extusers) {
            log_dump_apr_array(r,extreqc->extusers,"extUser");
            char **extuserdns = (char **) extreqc->extusers->elts;
			for (i = 0; i < extreqc->extusers->nelts; i++) {
				const char **extuservals = NULL;
				int result = 0;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "DAC: User search basedn: %s", extuserdns[i]);
                //we don't use wucbasedn as we already know what webuser distinguishedname can be

				result = util_ldap_cache_getuserdn(r, ldc, conf->url, extuserdns[i], LDAP_SCOPE_BASE, ldap_webuser_attributes, userfilter, &dn, &extuservals);
				if(extuservals) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "DAC: Val 0: %s", extuservals[0]);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "DAC: Val 1: %s", extuservals[1]);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "DAC: Val 2: %s", extuservals[2]);
					char *prefix = "DAC: ";
					mvhl_doextuserconfig(r, ldap_webuser_attributes, extuservals, extuserreqc, prefix);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "DAC: current username: %s", extuserreqc->webusername);
                    userlist = apr_pstrcat(r->pool, userlist, " ", extuserreqc->webusername, NULL);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "DAC: current userlist: %s", userlist);
				}
			}
		}
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "final userlist: %s ", userlist);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "DAC: AuthName set to %s", coredirconf->ap_auth_name);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "DAC: AuthType set to %s", coredirconf->ap_auth_type);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, OK, NULL, "DAC: Preparing access control line");
		coredirconf->ap_requires = (apr_array_header_t *) get_ap_reqs(r->pool, extreqc, reqc->name, userlist);
		
	}
	
}
/******************************************************************/
static int mvhl_translate_name(request_rec * r)
{
	request_rec *top 			= r->main ? r->main : r;
	apr_table_t *e 				= top->subprocess_env;
	apr_table_do(header_trace, r, r->headers_in, NULL);
	
	//module config and current request config objects
	mvhl_config *conf 			= (mvhl_config *) ap_get_module_config(r->server->module_config, &vhost_ldap_module);
	mvhl_dump_config_request(conf, r);	//debug
	// mod_vhost_ldap is disabled or we don't have LDAP Url, we check these as soon as we can (after debugging dump)
	if(( conf->enabled == 0) || (! conf->have_ldap_url) || ( ! conf->host ) ) return DECLINED;

	//get core config and current request config, then set current request config
	core_server_config *core 	= (core_server_config *) ap_get_module_config(r->server->module_config, &core_module);
	mvhl_request *reqc 			= (mvhl_request *) apr_pcalloc(r->pool, sizeof(mvhl_request));
	ap_set_module_config(r->request_config, &vhost_ldap_module, reqc);

	const char *hostname = r->hostname;
	const char *dn 	= NULL;

	//we'll reuse ldap connection opened here
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Opening LDAP Connection");
	util_ldap_connection_t *ldc  	= util_ldap_connection_find(r, conf->host, conf->port, conf->binddn, conf->bindpw,conf->deref, conf->secure);

	//heart of the system :)	
	if ( conf->enabled == 0 || ! apply_vhost(conf, hostname, r, ldc, dn, reqc ) )  return DECLINED;  
	if (conf->alias_enabled > 0 ) apply_aliasing(reqc, r, conf, ldc, dn);
	
	if (conf->loc_auth_enabled > 0 ) apply_location_access_control(reqc, r, conf, ldc, dn);
	if (conf->dir_auth_enabled > 0 ) apply_directory_access_control(reqc, r, conf, ldc, dn);
	
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, "Closing LDAP Connection");
	util_ldap_connection_close(ldc);
	
	/* finished with Access control for location **********************************/
	top->server->server_hostname = apr_pstrdup(top->pool, reqc->name);
	if(reqc->admin) {top->server->server_admin = apr_pstrdup(top->pool, reqc->admin); }

	// set environment variables
	apr_table_addn(e, "SERVER_ROOT", reqc->docroot);	
	core->ap_document_root = apr_pstrdup(top->pool, reqc->docroot);
	
	//apr_table_set(r->err_headers_out, "Content-type", "Content-type: text/html; charset=UTF-8");
	//apr_table_set(r->headers_out, "Content-type", "Content-type: text/html; charset=UTF-8");
	
	return OK;
}
/******************************************************************/
static ap_unix_identity_t *mvhl_suexec_doer(const request_rec * r)
{
	ap_unix_identity_t *ugid = NULL;
	mvhl_config *conf = (mvhl_config *) ap_get_module_config(r->server->module_config, &vhost_ldap_module);
	mvhl_request *req = (mvhl_request *) ap_get_module_config(r->request_config, &vhost_ldap_module);

	uid_t uid = -1;
	gid_t gid = -1;

	uid = (uid_t) atoll(req->uid);
	gid = (gid_t) atoll(req->gid);

	// mod_vhost_ldap is disabled or we don't have LDAP Url
	if(
		(uid < MIN_UID) || 
		(gid < MIN_GID) ||
		( conf->enabled == 0 ) || 
		(!conf->have_ldap_url) || 
		(req == NULL) || 
		(req->uid == NULL) || 
		(req->gid == NULL) ||
		(ugid = apr_palloc(r->pool, sizeof(ap_unix_identity_t))) == NULL
	) {	return NULL; }

	ugid->uid = uid;
	ugid->gid = gid;
	ugid->userdir = 0;
	return ugid;
}
/******************************************************************/
static int mvhl_post_config(apr_pool_t * p, apr_pool_t * plog, apr_pool_t * ptemp, server_rec * s)
{
	/* make sure that mod_ldap (util_ldap) is loaded */
	if(ap_find_linked_module("util_ldap.c") == NULL) {return HTTP_INTERNAL_SERVER_ERROR;}
	ap_add_version_component(p, MOD_VHOST_LDAP_VERSION);
	return OK;
}
/******************************************************************/
static const command_rec mvhl_cmds[] = {
	AP_INIT_TAKE1("VhostLdapUrl", 			conf_mvhl_url, 	NULL, 				RSRC_CONF,"RFC 2255 URL of the form ldap://host[:port]/basedn[?attrib[?scope[?filter]]]."),
	AP_INIT_TAKE1("VhostLdapEnabled",		conf_mvhl,		MVHL_ENABLED,		RSRC_CONF,"Set to off or unset to disable vhost_ldap module completely"),
	AP_INIT_TAKE1("VhostAliasesEnabled",	conf_mvhl,		MVHL_ALIASENABLED,	RSRC_CONF,"Set to off or unset to disable ldap-based dir aliases"),
	AP_INIT_TAKE1("VhostLocAuthEnabled",	conf_mvhl,		MVHL_LAUTHENABLED,	RSRC_CONF,"Set to off or unset to disable per-location authentication"),
	AP_INIT_TAKE1("VhostDirAuthEnabled",	conf_mvhl,		MVHL_DAUTHENABLED,	RSRC_CONF,"Set to off or unset to disable per-location authentication"),
	AP_INIT_TAKE1("VhostLdapBindDn",		conf_mvhl,		MVHL_BINDDN,		RSRC_CONF,"DN to use to bind to LDAP server"),
	AP_INIT_TAKE1("VhostLdapBindPw",		conf_mvhl,		MVHL_BINDPW,		RSRC_CONF,"Password to use to bind to LDAP server"),
	AP_INIT_TAKE1("VhostLdapWlcBaseDn",		conf_mvhl,		MVHL_WLCBASEDN,		RSRC_CONF,"Base DN to do all access control config searches."),
	AP_INIT_TAKE1("VhostLdapWucBaseDn",		conf_mvhl,		MVHL_WUCBASEDN,		RSRC_CONF,"Base DN to do all user config searches"),
	AP_INIT_TAKE1("VhostLdapAliasesBaseDn",	conf_mvhl,		MVHL_ALIASBASEDN,	RSRC_CONF,"Base DN to do all aliases config searches"),
	AP_INIT_TAKE1("VhostLdapFallback",  	conf_mvhl, 		MVHL_FALLBACK, 		RSRC_CONF,"Fallback vhost server name to use - to display not-found info"),
	AP_INIT_TAKE1("VhostLdapDeref",			conf_mvhl,		MVHL_DEREF,			RSRC_CONF,"values: never, searching, finding, always"),  
	{NULL}
};
/******************************************************************/
static void mvhl_register_hooks(apr_pool_t * p)
{
	ap_hook_post_config(mvhl_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(mvhl_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_get_suexec_identity(mvhl_suexec_doer, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_check_user_id(mvhl_authenticate_basic_user, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(mvhl_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
}
/******************************************************************/
module AP_MODULE_DECLARE_DATA vhost_ldap_module = {
	STANDARD20_MODULE_STUFF,				
	NULL,				// create per-directory config structure
	NULL,				// merge per-directory config structures, default is to override
	mvhl_create_sconfig,// called when module configuration data needs to be created/allocated.
	mvhl_merge_sconfig,	// merge per-server config structures
	mvhl_cmds,			// Here we pass in the list of new configuration directives.
	mvhl_register_hooks,// register me in apache core
};
