/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-hsts-enforcer-db.c: persistent HTTP Strict Transport Security feature
 *
 * Using soup-cookie-jar-db as template
 * Copyright (C) 2016, 2017, 2018 Igalia S.L.
 * Copyright (C) 2017, 2018 Metrological Group B.V.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include <sqlite3.h>

#include "soup-hsts-enforcer-db.h"
#include "soup.h"

/**
 * SoupHSTSEnforcerDB:
 *
 * Persistent HTTP Strict Transport Security enforcer.
 *
 * [class@HSTSEnforcerDB] is a [class@HSTSEnforcer] that uses a SQLite
 * database as a backend for persistency.
 **/

enum {
	PROP_0,

	PROP_FILENAME,

	LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

struct _SoupHSTSEnforcerDB {
	SoupHSTSEnforcer parent;
};

typedef struct {
	char *filename;
	sqlite3 *db;
} SoupHSTSEnforcerDBPrivate;

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupHSTSEnforcerDB, soup_hsts_enforcer_db, SOUP_TYPE_HSTS_ENFORCER,
			       G_ADD_PRIVATE(SoupHSTSEnforcerDB))

static void load (SoupHSTSEnforcer *hsts_enforcer);

static void
soup_hsts_enforcer_db_init (SoupHSTSEnforcerDB *db)
{
}

static void
soup_hsts_enforcer_db_finalize (GObject *object)
{
        SoupHSTSEnforcerDBPrivate *priv = soup_hsts_enforcer_db_get_instance_private ((SoupHSTSEnforcerDB*)object);

	g_free (priv->filename);
	sqlite3_close (priv->db);

	G_OBJECT_CLASS (soup_hsts_enforcer_db_parent_class)->finalize (object);
}

static void
soup_hsts_enforcer_db_set_property (GObject *object, guint prop_id,
				    const GValue *value, GParamSpec *pspec)
{
        SoupHSTSEnforcerDBPrivate *priv = soup_hsts_enforcer_db_get_instance_private ((SoupHSTSEnforcerDB*)object);

	switch (prop_id) {
	case PROP_FILENAME:
		priv->filename = g_value_dup_string (value);
		load (SOUP_HSTS_ENFORCER (object));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_hsts_enforcer_db_get_property (GObject *object, guint prop_id,
				    GValue *value, GParamSpec *pspec)
{
        SoupHSTSEnforcerDBPrivate *priv = soup_hsts_enforcer_db_get_instance_private ((SoupHSTSEnforcerDB*)object);

	switch (prop_id) {
	case PROP_FILENAME:
		g_value_set_string (value, priv->filename);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * soup_hsts_enforcer_db_new:
 * @filename: the filename of the database to read/write from.
 *
 * Creates a [class@HSTSEnforcerDB].
 *
 * @filename will be read in during the initialization of a
 * [class@HSTSEnforcerDB], in order to create an initial set of HSTS
 * policies. If the file doesn't exist, a new database will be created
 * and initialized. Changes to the policies during the lifetime of a
 * [class@HSTSEnforcerDB] will be written to @filename when
 * [signal@HSTSEnforcer::changed] is emitted.
 *
 * Returns: the new #SoupHSTSEnforcer
 **/
SoupHSTSEnforcer *
soup_hsts_enforcer_db_new (const char *filename)
{
	g_return_val_if_fail (filename != NULL, NULL);

	return g_object_new (SOUP_TYPE_HSTS_ENFORCER_DB,
			     "filename", filename,
			     NULL);
}

#define QUERY_ALL "SELECT id, host, max_age, expiry, include_subdomains FROM soup_hsts_policies;"
#define CREATE_TABLE "CREATE TABLE soup_hsts_policies (id INTEGER PRIMARY KEY, host TEXT UNIQUE, max_age INTEGER, expiry INTEGER, include_subdomains INTEGER)"
#define QUERY_INSERT "INSERT OR REPLACE INTO soup_hsts_policies VALUES((SELECT id FROM soup_hsts_policies WHERE host=%Q), %Q, %lu, %lu, %u);"
#define QUERY_DELETE "DELETE FROM soup_hsts_policies WHERE host=%Q;"

enum {
	COL_ID,
	COL_HOST,
	COL_MAX_AGE,
	COL_EXPIRY,
	COL_SUBDOMAINS,
	N_COL,
};

static int
query_all_callback (void *data, int argc, char **argv, char **colname)
{
	SoupHSTSPolicy *policy = NULL;
	SoupHSTSEnforcer *hsts_enforcer = SOUP_HSTS_ENFORCER (data);

	char *host;
	gulong expire_time;
	unsigned long max_age;
	time_t now;
	GDateTime *expires;
	gboolean include_subdomains = FALSE;

	now = time (NULL);

	host = argv[COL_HOST];
	expire_time = strtoul (argv[COL_EXPIRY], NULL, 10);

	if (now >= expire_time)
		return 0;

	expires = g_date_time_new_from_unix_utc (expire_time);
	max_age = strtoul (argv[COL_MAX_AGE], NULL, 10);
	include_subdomains = (g_strcmp0 (argv[COL_SUBDOMAINS], "1") == 0);

	policy = soup_hsts_policy_new_full (host, max_age, expires, include_subdomains);

	if (policy) {
		soup_hsts_enforcer_set_policy (hsts_enforcer, policy);
		soup_hsts_policy_free (policy);
	}

        g_date_time_unref (expires);

	return 0;
}

static void
try_create_table (sqlite3 *db)
{
	char *error = NULL;

	if (sqlite3_exec (db, CREATE_TABLE, NULL, NULL, &error)) {
		g_warning ("Failed to execute query: %s", error);
		sqlite3_free (error);
	}
}

typedef int (*ExecQueryCallback) (void *, int, char**, char**);

static void
exec_query_with_try_create_table (sqlite3 *db,
				  const char *sql,
				  ExecQueryCallback callback,
				  void *argument)
{
	char *error = NULL;
	gboolean try_create = TRUE;

try_exec:
	if (sqlite3_exec (db, sql, callback, argument, &error)) {
		if (try_create) {
			try_create = FALSE;
			try_create_table (db);
			sqlite3_free (error);
			error = NULL;
			goto try_exec;
		} else {
			g_warning ("Failed to execute query: %s", error);
			sqlite3_free (error);
		}
	}
}

/* Follows sqlite3 convention; returns TRUE on error */
static gboolean
open_db (SoupHSTSEnforcer *hsts_enforcer)
{
	SoupHSTSEnforcerDBPrivate *priv = soup_hsts_enforcer_db_get_instance_private ((SoupHSTSEnforcerDB*)hsts_enforcer);

	char *error = NULL;

	if (sqlite3_open (priv->filename, &priv->db)) {
		sqlite3_close (priv->db);
		priv->db = NULL;
		g_warning ("Can't open %s", priv->filename);
		return TRUE;
	}

	if (sqlite3_exec (priv->db, "PRAGMA synchronous = OFF; PRAGMA secure_delete = 1;", NULL, NULL, &error)) {
		g_warning ("Failed to execute query: %s", error);
		sqlite3_free (error);
	}

	return FALSE;
}

static void
load (SoupHSTSEnforcer *hsts_enforcer)
{
	SoupHSTSEnforcerDBPrivate *priv = soup_hsts_enforcer_db_get_instance_private ((SoupHSTSEnforcerDB*)hsts_enforcer);

	if (priv->db == NULL) {
		if (open_db (hsts_enforcer))
			return;
	}

	exec_query_with_try_create_table (priv->db, QUERY_ALL, query_all_callback, hsts_enforcer);
}

static void
soup_hsts_enforcer_db_changed (SoupHSTSEnforcer *hsts_enforcer,
			       SoupHSTSPolicy   *old_policy,
			       SoupHSTSPolicy   *new_policy)
{
	SoupHSTSEnforcerDBPrivate *priv = soup_hsts_enforcer_db_get_instance_private ((SoupHSTSEnforcerDB*)hsts_enforcer);
	char *query;

	/* Session policies do not need to be stored in the database. */
	if ((old_policy && soup_hsts_policy_is_session_policy (old_policy)) ||
	    (new_policy && soup_hsts_policy_is_session_policy (new_policy)))
		return;

	if (priv->db == NULL) {
		if (open_db (hsts_enforcer))
			return;
	}

	if (old_policy && !new_policy) {
		query = sqlite3_mprintf (QUERY_DELETE,
					 soup_hsts_policy_get_domain (old_policy));
		g_assert (query);
		exec_query_with_try_create_table (priv->db, query, NULL, NULL);
		sqlite3_free (query);
	}

	/* Insert the new policy or update the existing one. */
	if (new_policy && soup_hsts_policy_get_expires (new_policy)) {
		gulong expires;

		expires = (gulong)g_date_time_to_unix (soup_hsts_policy_get_expires (new_policy));
		query = sqlite3_mprintf (QUERY_INSERT,
					 soup_hsts_policy_get_domain (new_policy),
					 soup_hsts_policy_get_domain (new_policy),
					 soup_hsts_policy_get_max_age (new_policy),
					 expires,
					 soup_hsts_policy_includes_subdomains (new_policy));
		g_assert (query);
		exec_query_with_try_create_table (priv->db, query, NULL, NULL);
		sqlite3_free (query);
	}
}

static gboolean
soup_hsts_enforcer_db_is_persistent (SoupHSTSEnforcer *hsts_enforcer)
{
	return TRUE;
}

static gboolean
soup_hsts_enforcer_db_has_valid_policy (SoupHSTSEnforcer *hsts_enforcer,
					const char *domain)
{
	/* TODO: In the future we should not load the full contents of
	   this database into the enforcer, and instead query the
	   database on request here. Loading the entire database for a
	   potentially large amount of domains is probably not the
	   best approach.
	*/

	return SOUP_HSTS_ENFORCER_CLASS (soup_hsts_enforcer_db_parent_class)->has_valid_policy (hsts_enforcer, domain);
}

static void
soup_hsts_enforcer_db_class_init (SoupHSTSEnforcerDBClass *db_class)
{
	SoupHSTSEnforcerClass *hsts_enforcer_class =
		SOUP_HSTS_ENFORCER_CLASS (db_class);
	GObjectClass *object_class = G_OBJECT_CLASS (db_class);

	hsts_enforcer_class->is_persistent = soup_hsts_enforcer_db_is_persistent;
	hsts_enforcer_class->has_valid_policy = soup_hsts_enforcer_db_has_valid_policy;
	hsts_enforcer_class->changed       = soup_hsts_enforcer_db_changed;

	object_class->finalize     = soup_hsts_enforcer_db_finalize;
	object_class->set_property = soup_hsts_enforcer_db_set_property;
	object_class->get_property = soup_hsts_enforcer_db_get_property;

	/**
	 * SoupHSTSEnforcerDB:filename:
	 *
	 * The filename of the SQLite database where HSTS policies are stored.
	 **/
        properties[PROP_FILENAME] =
		g_param_spec_string ("filename",
				     "Filename",
				     "HSTS policy storage filename",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}
