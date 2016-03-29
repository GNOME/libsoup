/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-hsts-enforcer-db.c: database-based HSTS policy storage
 *
 * Using soup-cookie-jar-db as template
 * Copyright (C) 2016 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include <sqlite3.h>

#include "soup-hsts-enforcer-db.h"
#include "soup-hsts-enforcer-private.h"
#include "soup.h"

/**
 * SECTION:soup-hsts-enforcer-db
 * @short_description: Database-based HSTS Enforcer
 *
 * #SoupHstsEnforcerDB is a #SoupHstsEnforcer that reads HSTS policies from
 * and writes them to a sqlite database.
 **/

enum {
	PROP_0,

	PROP_FILENAME,

	LAST_PROP
};

typedef struct {
	char *filename;
	sqlite3 *db;
} SoupHstsEnforcerDBPrivate;

#define SOUP_HSTS_ENFORCER_DB_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HSTS_ENFORCER_DB, SoupHstsEnforcerDBPrivate))

G_DEFINE_TYPE (SoupHstsEnforcerDB, soup_hsts_enforcer_db, SOUP_TYPE_HSTS_ENFORCER)

static void load (SoupHstsEnforcer *hsts_enforcer);

static void
soup_hsts_enforcer_db_init (SoupHstsEnforcerDB *db)
{
}

static void
soup_hsts_enforcer_db_finalize (GObject *object)
{
	SoupHstsEnforcerDBPrivate *priv =
		SOUP_HSTS_ENFORCER_DB_GET_PRIVATE (object);

	g_free (priv->filename);
	g_clear_pointer (&priv->db, sqlite3_close);

	G_OBJECT_CLASS (soup_hsts_enforcer_db_parent_class)->finalize (object);
}

static void
soup_hsts_enforcer_db_set_property (GObject *object, guint prop_id,
				    const GValue *value, GParamSpec *pspec)
{
	SoupHstsEnforcerDBPrivate *priv =
		SOUP_HSTS_ENFORCER_DB_GET_PRIVATE (object);

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
	SoupHstsEnforcerDBPrivate *priv =
		SOUP_HSTS_ENFORCER_DB_GET_PRIVATE (object);

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
 * @filename: the filename to read to/write from, or %NULL
 *
 * Creates a #SoupHstsEnforcerDB.
 *
 * @filename will be read in at startup to create an initial set of HSTS
 * policies. Changes to the policies will be written to @filename when the
 * 'changed' signal is emitted from the HSTS enforcer.
 *
 * Return value: the new #SoupHstsEnforcer
 *
 * Since: 2.54
 **/
SoupHstsEnforcer *
soup_hsts_enforcer_db_new (const char *filename)
{
	g_return_val_if_fail (filename != NULL, NULL);

	return g_object_new (SOUP_TYPE_HSTS_ENFORCER_DB,
			     SOUP_HSTS_ENFORCER_DB_FILENAME, filename,
			     NULL);
}

#define QUERY_ALL "SELECT id, host, expiry, includeSubDomains FROM soup_hsts_policies;"
#define CREATE_TABLE "CREATE TABLE soup_hsts_policies (id INTEGER PRIMARY KEY, host TEXT UNIQUE, expiry INTEGER, includeSubDomains INTEGER)"
#define QUERY_INSERT "INSERT OR REPLACE INTO soup_hsts_policies VALUES((SELECT id FROM soup_hsts_policies WHERE host=%Q), %Q, %d, %d);"
#define QUERY_DELETE "DELETE FROM soup_hsts_policies WHERE host=%Q;"

enum {
	COL_ID,
	COL_HOST,
	COL_EXPIRY,
	COL_SUB_DOMAINS,
	N_COL,
};

static int
callback (void *data, int argc, char **argv, char **colname)
{
	SoupHstsPolicy *policy = NULL;
	SoupHstsEnforcer *hsts_enforcer = SOUP_HSTS_ENFORCER (data);

	char *host;
	gulong expire_time;
	time_t now;
	SoupDate *expires;
	gboolean include_sub_domains = FALSE;

	now = time (NULL);

	host = argv[COL_HOST];
	expire_time = strtoul (argv[COL_EXPIRY], NULL, 10);

	if (now >= expire_time)
		return 0;

	expires = soup_date_new_from_time_t (expire_time);
	include_sub_domains = (g_strcmp0 (argv[COL_SUB_DOMAINS], "1") == 0);

	policy = soup_hsts_policy_new (host, expires, include_sub_domains);

	if (policy)
		soup_hsts_enforcer_set_policy (hsts_enforcer, policy);
	else
		soup_date_free (expires);

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

static void
exec_query_with_try_create_table (sqlite3 *db,
				  const char *sql,
				  int (*callback)(void*,int,char**,char**),
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
open_db (SoupHstsEnforcer *hsts_enforcer)
{
	SoupHstsEnforcerDBPrivate *priv =
		SOUP_HSTS_ENFORCER_DB_GET_PRIVATE (hsts_enforcer);

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
load (SoupHstsEnforcer *hsts_enforcer)
{
	SoupHstsEnforcerDBPrivate *priv =
		SOUP_HSTS_ENFORCER_DB_GET_PRIVATE (hsts_enforcer);

	if (priv->db == NULL) {
		if (open_db (hsts_enforcer))
			return;
	}

	exec_query_with_try_create_table (priv->db, QUERY_ALL, callback, hsts_enforcer);
}

static void
soup_hsts_enforcer_db_changed (SoupHstsEnforcer *hsts_enforcer,
			       SoupHstsPolicy   *old_policy,
			       SoupHstsPolicy   *new_policy)
{
	SoupHstsEnforcerDBPrivate *priv =
		SOUP_HSTS_ENFORCER_DB_GET_PRIVATE (hsts_enforcer);
	char *query;

	if (priv->db == NULL) {
		if (open_db (hsts_enforcer))
			return;
	}

	if (old_policy && !new_policy) {
		query = sqlite3_mprintf (QUERY_DELETE,
					 old_policy->domain);
		exec_query_with_try_create_table (priv->db, query, NULL, NULL);
		sqlite3_free (query);
	}

	/* Insert the new policy or update the existing one. */
	if (new_policy && new_policy->expires) {
		gulong expires;

		expires = (gulong)soup_date_to_time_t (new_policy->expires);
		query = sqlite3_mprintf (QUERY_INSERT,
					 new_policy->domain,
					 new_policy->domain,
					 expires,
					 new_policy->include_sub_domains);
		exec_query_with_try_create_table (priv->db, query, NULL, NULL);
		sqlite3_free (query);
	}
}

static gboolean
soup_hsts_enforcer_db_is_persistent (SoupHstsEnforcer *hsts_enforcer)
{
	return TRUE;
}

static void
soup_hsts_enforcer_db_class_init (SoupHstsEnforcerDBClass *db_class)
{
	SoupHstsEnforcerClass *hsts_enforcer_class =
		SOUP_HSTS_ENFORCER_CLASS (db_class);
	GObjectClass *object_class = G_OBJECT_CLASS (db_class);

	g_type_class_add_private (db_class, sizeof (SoupHstsEnforcerDBPrivate));

	hsts_enforcer_class->is_persistent = soup_hsts_enforcer_db_is_persistent;
	hsts_enforcer_class->changed       = soup_hsts_enforcer_db_changed;

	object_class->finalize     = soup_hsts_enforcer_db_finalize;
	object_class->set_property = soup_hsts_enforcer_db_set_property;
	object_class->get_property = soup_hsts_enforcer_db_get_property;

	/**
	 * SOUP_HSTS_ENFORCER_DB_FILENAME:
	 *
	 * Alias for the #SoupHstsEnforcerDB:filename property. (The
	 * HSTS policy storage filename.)
	 **/
	g_object_class_install_property (
		object_class, PROP_FILENAME,
		g_param_spec_string (SOUP_HSTS_ENFORCER_DB_FILENAME,
				     "Filename",
				     "HSTS policy storage filename",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
