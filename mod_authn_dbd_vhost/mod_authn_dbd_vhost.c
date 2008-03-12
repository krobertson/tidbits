/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_lib.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include "apr_strings.h"
#include "mod_auth.h"
#include "apr_md5.h"
#include "apu_version.h"

module AP_MODULE_DECLARE_DATA authn_dbd_vhost_module;

typedef struct {
    const char *user_vhost;
} authn_dbd_conf;
typedef struct {
    const char *label;
    const char *query;
} authn_dbd_rec;

/* optional function - look it up once in post_config */
static ap_dbd_t *(*authn_dbd_acquire_fn)(request_rec*) = NULL;
static void (*authn_dbd_prepare_fn)(server_rec*, const char*, const char*) = NULL;

static void *authn_dbd_cr_conf(apr_pool_t *pool, char *dummy)
{
    authn_dbd_conf *ret = apr_pcalloc(pool, sizeof(authn_dbd_conf));
    return ret;
}
static void *authn_dbd_merge_conf(apr_pool_t *pool, void *BASE, void *ADD)
{
    authn_dbd_conf *add = ADD;
    authn_dbd_conf *base = BASE;
    authn_dbd_conf *ret = apr_palloc(pool, sizeof(authn_dbd_conf));
    ret->user_vhost = (add->user_vhost == NULL) ? base->user_vhost : add->user_vhost;
    return ret;
}
static const char *authn_dbd_prepare(cmd_parms *cmd, void *cfg, const char *query)
{
    static unsigned int label_num = 0;
    char *label;

    if (authn_dbd_prepare_fn == NULL) {
        authn_dbd_prepare_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        if (authn_dbd_prepare_fn == NULL) {
            return "You must load mod_dbd to enable AuthDBD functions";
        }
        authn_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    }
    label = apr_psprintf(cmd->pool, "authn_dbd_%d", ++label_num);

    authn_dbd_prepare_fn(cmd->server, query, label);

    /* save the label here for our own use */
    return ap_set_string_slot(cmd, cfg, label);
}
static const command_rec authn_dbd_cmds[] =
{
    AP_INIT_TAKE1("AuthDBDUserVhostQuery", authn_dbd_prepare,
                  (void *)APR_OFFSETOF(authn_dbd_conf, user_vhost), ACCESS_CONF,
                  "Query used to fetch password for user+vhost"),
    {NULL}
};
static authn_status authn_dbd_vhost_password(request_rec *r, const char *user,
                                       const char *password)
{
    apr_status_t rv;
    const char *dbd_password = NULL;
    apr_dbd_prepared_t *statement;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;

    authn_dbd_conf *conf = ap_get_module_config(r->per_dir_config,
                                                &authn_dbd_vhost_module);
    ap_dbd_t *dbd = authn_dbd_acquire_fn(r);
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error looking up %s in database", user);
        return AUTH_GENERAL_ERROR;
    }

    if (conf->user_vhost == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No AuthDBDUserVhostQuery has been specified.");
        return AUTH_GENERAL_ERROR;
    }

    statement = apr_hash_get(dbd->prepared, conf->user_vhost, APR_HASH_KEY_STRING);
    if (statement == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "A prepared statement could not be found for AuthDBDUserVhostQuery, key '%s'.", conf->user_vhost);
        return AUTH_GENERAL_ERROR;
    }
    if (apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle, &res, statement,
                              0, user, r->hostname, NULL) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Error looking up %s in database", user);
        return AUTH_GENERAL_ERROR;
    }
    for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
         rv != -1;
         rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
        if (rv != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "Error looking up %s in database", user);
            return AUTH_GENERAL_ERROR;
        }
        if (dbd_password == NULL) {
            dbd_password = apr_dbd_get_entry(dbd->driver, row, 0);

#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 3)
            /* add the rest of the columns to the environment */
            int i = 1;
            const char *name;
            for (name = apr_dbd_get_name(dbd->driver, res, i);
                 name != NULL;
                 name = apr_dbd_get_name(dbd->driver, res, i)) {

                char *str = apr_pstrcat(r->pool, AUTHN_PREFIX,
                                        name,
                                        NULL);
                int j = sizeof(AUTHN_PREFIX)-1; /* string length of "AUTHENTICATE_", excluding the trailing NIL */
                while (str[j]) {
                    if (!apr_isalnum(str[j])) {
                        str[j] = '_';
                    }
                    else {
                        str[j] = apr_toupper(str[j]);
                    }
                    j++;
                }
                apr_table_set(r->subprocess_env, str,
                              apr_dbd_get_entry(dbd->driver, row, i));
                i++;
            }
#endif
        }
        /* we can't break out here or row won't get cleaned up */
    }

    if (!dbd_password) {
        return AUTH_USER_NOT_FOUND;
    }

    rv = apr_password_validate(password, dbd_password);

    if (rv != APR_SUCCESS) {
        return AUTH_DENIED;
    }

    return AUTH_GRANTED;
}
static void authn_dbd_hooks(apr_pool_t *p)
{
    static const authn_provider authn_dbd_provider = {
        &authn_dbd_vhost_password
    };

    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "dbd", "0", &authn_dbd_provider);
}
module AP_MODULE_DECLARE_DATA authn_dbd_vhost_module =
{
    STANDARD20_MODULE_STUFF,
    authn_dbd_cr_conf,
    authn_dbd_merge_conf,
    NULL,
    NULL,
    authn_dbd_cmds,
    authn_dbd_hooks
};
