/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-cookie-jar-db.c: database-based cookie storage
 *
 * Using danw's soup-cookie-jar-text as template
 * Copyright (C) 2008 Diego Escalante Urrelo
 * Copyright (C) 2009 Collabora Ltd.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include <sqlite3.h>

#include "soup-cookie-jar-db.h"
#include "soup.h"

/**
 * SoupCookieJarDB:
 *
 * Database-based Cookie Jar.
 *
 * [class@CookieJarDB] is a [class@CookieJar] that reads cookies from and writes
 * them to a sqlite database in the new Mozilla format.
 *
 * (This is identical to `SoupCookieJarSqlite` in
 * libsoup-gnome; it has just been moved into libsoup proper, and
 * renamed to avoid conflicting.)
 *
 * Since 3.8 this class implements [iface@Gio.Initable] to track failures
 * opening the database. See [ctor@SoupCookieJarDB.new_with_error].
 **/

enum {
	PROP_0,

	PROP_FILENAME,
	PROP_MAX_SIZE,

	LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

struct _SoupCookieJarDB {
	SoupCookieJar parent;
};


typedef struct {
	char *filename;
	sqlite3 *db;
	guint64 db_default_page_size;
	guint64 db_default_max_page_count;
	guint64 max_size;
	gboolean is_initializing;
	GError *init_error;
} SoupCookieJarDBPrivate;

static void soup_cookie_jar_db_initable_iface_init (GInitableIface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupCookieJarDB, soup_cookie_jar_db, SOUP_TYPE_COOKIE_JAR,
			       G_ADD_PRIVATE (SoupCookieJarDB)
			       G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, soup_cookie_jar_db_initable_iface_init))

static gboolean open_db (SoupCookieJar *jar, GError **error);
static gboolean db_set_max_size (SoupCookieJarDB *jar, guint64 max_size, GError **error);
static void soup_cookie_jar_db_constructed (GObject *object);

static void
soup_cookie_jar_db_init (SoupCookieJarDB *db)
{
}

static void
soup_cookie_jar_db_finalize (GObject *object)
{
	SoupCookieJarDBPrivate *priv =
		soup_cookie_jar_db_get_instance_private (SOUP_COOKIE_JAR_DB (object));

	g_free (priv->filename);
	g_clear_pointer (&priv->db, sqlite3_close);
	g_clear_error (&priv->init_error);

	G_OBJECT_CLASS (soup_cookie_jar_db_parent_class)->finalize (object);
}

static void
soup_cookie_jar_db_set_property (GObject *object, guint prop_id,
				 const GValue *value, GParamSpec *pspec)
{
	SoupCookieJarDBPrivate *priv =
		soup_cookie_jar_db_get_instance_private (SOUP_COOKIE_JAR_DB (object));

	switch (prop_id) {
	case PROP_FILENAME:
		priv->filename = g_value_dup_string (value);
		break;
	case PROP_MAX_SIZE:
		/* construct-only value, actually used in constructed() */
		priv->max_size = g_value_get_uint64 (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_cookie_jar_db_get_property (GObject *object, guint prop_id,
				 GValue *value, GParamSpec *pspec)
{
	SoupCookieJarDBPrivate *priv =
		soup_cookie_jar_db_get_instance_private (SOUP_COOKIE_JAR_DB (object));

	switch (prop_id) {
	case PROP_FILENAME:
		g_value_set_string (value, priv->filename);
		break;
	case PROP_MAX_SIZE:
		g_value_set_uint64 (value, priv->max_size);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static int
read_default_max_page_count_callback (void *data, int argc, char **argv, char **colname)
{
	SoupCookieJarDBPrivate *priv = (SoupCookieJarDBPrivate*)data;

	if (argc != 1 || argv[0] == NULL) {
		g_warning ("cookie-jar-db: Max page count value is missing");
		return -1;
	}

	priv->db_default_max_page_count = g_ascii_strtoull (argv[0], NULL, 10);
	return 0;
}

static gboolean
soup_cookie_jar_db_get_default_max_page_count (SoupCookieJarDB *jar, GError **error)
{
	SoupCookieJarDBPrivate *priv = soup_cookie_jar_db_get_instance_private (jar);

	char *errmsg = NULL;
	int ret = sqlite3_exec (priv->db, "PRAGMA max_page_count;", read_default_max_page_count_callback, priv, &errmsg);
	if (ret) {
		g_set_error (error, SOUP_COOKIE_JAR_ERROR, SOUP_COOKIE_JAR_ERROR_DB,
			     "Failed to execute 'PRAGMA max_page_count': %s", errmsg);
		sqlite3_free (errmsg);
		return FALSE;
	}
	return TRUE;
}

static int
read_default_page_size_callback (void *data, int argc, char **argv, char **colname)
{
	SoupCookieJarDBPrivate *priv = (SoupCookieJarDBPrivate*)data;

	if (argc != 1 || argv[0] == NULL) {
		g_warning ("cookie-jar-db: Page size value is missing");
		return -1;
	}

	priv->db_default_page_size = g_ascii_strtoull (argv[0], NULL, 10);
	return 0;
}

static gboolean
soup_cookie_jar_db_get_default_page_size (SoupCookieJarDB *jar, GError **error)
{
	SoupCookieJarDBPrivate *priv = soup_cookie_jar_db_get_instance_private (jar);

	char *errmsg = NULL;
	int ret = sqlite3_exec (priv->db, "PRAGMA page_size;", read_default_page_size_callback, priv, &errmsg);
	if (ret) {
		g_set_error (error, SOUP_COOKIE_JAR_ERROR, SOUP_COOKIE_JAR_ERROR_DB,
			     "Failed to execute 'PRAGMA page_size': %s", errmsg);
		sqlite3_free (errmsg);
		return FALSE;
	}
	return TRUE;
}

/**
 * soup_cookie_jar_db_get_max_size:
 * @jar: A #SoupCookieJarDB
 *
 * Get the maximum size for the database file storage
 *
 * This method returns the currently configured max database file size. A return value of zero
 * indicates that no limit is configured.
 *
 * Returns: Database max file size
 *
 * Since: 3.8
 **/
guint64
soup_cookie_jar_db_get_max_size (SoupCookieJarDB *jar)
{
	SoupCookieJarDBPrivate *priv;

	g_return_val_if_fail (SOUP_IS_COOKIE_JAR_DB (jar), 0);

	priv = soup_cookie_jar_db_get_instance_private (SOUP_COOKIE_JAR_DB (jar));
	return priv->max_size;
}

/**
 * soup_cookie_jar_db_set_max_size:
 * @jar: A #SoupCookieJarDB
 * @max_size: Max database file size, in bytes
 * @error A #GError
 *
 * Set the maximum size for the database file storage
 *
 * If @max_size is 0, it means "no limit", in which case the database file size will be limited only
 * by the database capabilities / intrinsic limits.
 *
 * If @max_size has a higher limit than supported by the database, the max_size will be internally
 * set to the limit supported by the database.
 *
 * The @max_size will be internally truncated to a multiple of the database page size. If the page
 * size is, for example, 4K, setting a max size of 10K will effectively limit the database size to
 * 8K to ensure it does not grow beyond the specified limit.
 *
 * Attempting to set a limit that is less than the already used database file storage will NOT
 * truncate the database, but won't allow the database to grow further in size (although writes
 * might be still accepted within the already allocated space).
 *
 * This value does not persist in the database. Each construction of this class must set
 * the property again or it will use the default value.
 *
 * Returns: %TRUE is configuration was successful, otherwise %FALSE and @error will be set.
 *
 * Since: 3.8
 **/
gboolean
soup_cookie_jar_db_set_max_size (SoupCookieJarDB *jar, guint64 max_size, GError **error)
{
	g_return_val_if_fail (SOUP_IS_COOKIE_JAR_DB (jar), FALSE);

	SoupCookieJarDBPrivate *priv = soup_cookie_jar_db_get_instance_private (SOUP_COOKIE_JAR_DB (jar));

	return (priv->max_size == max_size) ? TRUE : db_set_max_size (SOUP_COOKIE_JAR_DB (jar), max_size, error);
}

static gboolean
db_set_max_size (SoupCookieJarDB *jar, guint64 max_size, GError **error)
{
	SoupCookieJarDBPrivate *priv =
		soup_cookie_jar_db_get_instance_private (jar);

	if (0 == priv->db_default_page_size) {
		g_set_error_literal (error,
				     SOUP_COOKIE_JAR_ERROR,
				     SOUP_COOKIE_JAR_ERROR_DB,
				     "Database page size is not available");
		return FALSE;
	}

	if (0 == priv->db_default_max_page_count) {
		g_set_error_literal (error,
				     SOUP_COOKIE_JAR_ERROR,
				     SOUP_COOKIE_JAR_ERROR_DB,
				     "Database max page count is not available");
		return FALSE;
	}

	// Integer truncation ensures we don't use more space than desired in case the max
	// database size is not a multiple of the database page size
	guint64 max_page_count = (max_size != 0) ? max_size / priv->db_default_page_size : priv->db_default_max_page_count;

	if (max_page_count > priv->db_default_max_page_count)
		max_page_count = priv->db_default_max_page_count;

	max_size = max_page_count * priv->db_default_page_size;

	char *error_msg = NULL;
	char *query = sqlite3_mprintf ("PRAGMA max_page_count = %u;", max_page_count);
	int ret = sqlite3_exec (priv->db, query, NULL, NULL, &error_msg);

	sqlite3_free (query);

	if (ret) {
		g_set_error (error,
		             SOUP_COOKIE_JAR_ERROR,
		             SOUP_COOKIE_JAR_ERROR_DB,
		             "PRAGMA failed: %s", error_msg);
		sqlite3_free (error_msg);
		return FALSE;
	}
	priv->max_size = max_size;
	g_object_notify_by_pspec (G_OBJECT (jar), properties[PROP_MAX_SIZE]);

	return TRUE;
}

/**
 * soup_cookie_jar_db_new:
 * @filename: the filename to read to/write from, or %NULL
 * @read_only: %TRUE if @filename is read-only
 *
 * Creates a [class@CookieJarDB].
 *
 * @filename will be read in at startup to create an initial set of cookies. If
 * @read_only is %FALSE, then the non-session cookies will be written to
 * @filename when the [signal@CookieJar::changed] signal is emitted from the
 * jar. (If @read_only is %TRUE, then the cookie jar will only be used for this
 * session, and changes made to it will be lost when the jar is destroyed.)
 *
 * Returns: the new #SoupCookieJar
 **/
SoupCookieJar *
soup_cookie_jar_db_new (const char *filename, gboolean read_only)
{
	g_return_val_if_fail (filename != NULL, NULL);

	GError *error = NULL;
	SoupCookieJarDB *jar = g_object_new (SOUP_TYPE_COOKIE_JAR_DB,
					     "filename", filename,
					     "read-only", read_only,
					     NULL);
	if (!g_initable_init (G_INITABLE (jar), NULL, &error)) {
		g_warning ("Failed to open cookie jar database: %s", error->message);
		g_clear_error (&error);
	}
	return SOUP_COOKIE_JAR (jar);
}

/**
 * soup_cookie_jar_db_new_with_error:
 * @filename: the filename to read to/write from
 * @read_only: %TRUE if @filename is read-only
 * @error: return location for a #GError, or %NULL
 *
 * Creates a [class@CookieJarDB], returning %NULL and setting @error if the
 * database file cannot be opened.
 *
 * Returns: (transfer full): the new #SoupCookieJar, or %NULL on error
 *
 * Since: 3.8
 **/
SoupCookieJar *
soup_cookie_jar_db_new_with_error (const char *filename, gboolean read_only, GError **error)
{
	g_return_val_if_fail (filename != NULL, NULL);

	return g_initable_new (SOUP_TYPE_COOKIE_JAR_DB, NULL, error,
			       "filename", filename,
			       "read-only", read_only,
			       NULL);
}

#define QUERY_ALL "SELECT id, name, value, host, path, expiry, lastAccessed, isSecure, isHttpOnly, sameSite FROM moz_cookies;"
#define CREATE_TABLE "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER)"
#define QUERY_INSERT "INSERT INTO moz_cookies VALUES(NULL, %Q, %Q, %Q, %Q, %d, NULL, %d, %d, %d);"
#define QUERY_DELETE "DELETE FROM moz_cookies WHERE name=%Q AND host=%Q;"

enum {
	COL_ID,
	COL_NAME,
	COL_VALUE,
	COL_HOST,
	COL_PATH,
	COL_EXPIRY,
	COL_LAST_ACCESS,
	COL_SECURE,
	COL_HTTP_ONLY,
	COL_SAME_SITE_POLICY,
	N_COL,
};

static int
callback (void *data, int argc, char **argv, char **colname)
{
	SoupCookie *cookie = NULL;
	SoupCookieJar *jar = SOUP_COOKIE_JAR (data);

	char *name, *value, *host, *path;
	gulong expire_time;
	time_t now;
	int max_age;
	gboolean http_only = FALSE, secure = FALSE;
	SoupSameSitePolicy same_site_policy;

	now = time (NULL);

	name = argv[COL_NAME];
	value = argv[COL_VALUE];
	host = argv[COL_HOST];
	path = argv[COL_PATH];
	expire_time = strtoul (argv[COL_EXPIRY], NULL, 10);

	if (now >= expire_time)
		return 0;
	max_age = (expire_time - now <= G_MAXINT ? expire_time - now : G_MAXINT);

	http_only = (g_strcmp0 (argv[COL_HTTP_ONLY], "1") == 0);
	secure = (g_strcmp0 (argv[COL_SECURE], "1") == 0);

	// COL_SAME_SITE_POLICY is a new column and may be NULL in an old DB, treat as None
	if (argv[COL_SAME_SITE_POLICY] == NULL)
	    same_site_policy = SOUP_SAME_SITE_POLICY_NONE;
	else
	    same_site_policy = g_ascii_strtoll (argv[COL_SAME_SITE_POLICY], NULL, 0);

	cookie = soup_cookie_new (name, value, host, path, max_age);

	if (secure)
		soup_cookie_set_secure (cookie, TRUE);
	if (http_only)
		soup_cookie_set_http_only (cookie, TRUE);
	if (same_site_policy)
		soup_cookie_set_same_site_policy (cookie, same_site_policy);

	soup_cookie_jar_add_cookie (jar, cookie);

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
	int ret;

try_exec:
	ret = sqlite3_exec (db, sql, callback, argument, &error);
	if (ret) {
		/* Missing table will fail with SQLITE_ERROR, ignore others. */
		if (try_create && ret == SQLITE_ERROR) {
			try_create = FALSE;
			try_create_table (db);
			g_clear_pointer (&error, sqlite3_free);
			goto try_exec;
		} else {
			g_warning ("Failed to execute query: %s", error);
			sqlite3_free (error);
		}
	}
}

/* Returns FALSE and sets error on failure */
static gboolean
open_db (SoupCookieJar *jar, GError **error)
{
	SoupCookieJarDBPrivate *priv =
		soup_cookie_jar_db_get_instance_private (SOUP_COOKIE_JAR_DB (jar));

	char *errmsg = NULL;

	if (sqlite3_open (priv->filename, &priv->db)) {
		g_set_error (error, SOUP_COOKIE_JAR_ERROR, SOUP_COOKIE_JAR_ERROR_DB,
			     "Failed to open %s: %s", priv->filename,
			     sqlite3_errmsg (priv->db));
		g_clear_pointer (&priv->db, sqlite3_close);
		return FALSE;
	}

	if (sqlite3_exec (priv->db, "PRAGMA synchronous = OFF; PRAGMA secure_delete = 1;", NULL, NULL, &errmsg)) {
		g_set_error (error, SOUP_COOKIE_JAR_ERROR, SOUP_COOKIE_JAR_ERROR_DB,
			     "Failed to execute PRAGMA: %s", errmsg);
		sqlite3_free (errmsg);
		g_clear_pointer (&priv->db, sqlite3_close);
		return FALSE;
	}

	/* Migrate old DB to include same-site info. We simply always run this as it
	   will safely handle a column with the same name existing */
	sqlite3_exec (priv->db, "ALTER TABLE moz_cookies ADD COLUMN sameSite INTEGER DEFAULT 0", NULL, NULL, NULL);

	return TRUE;
}

static void
soup_cookie_jar_db_constructed (GObject *object)
{
	G_OBJECT_CLASS (soup_cookie_jar_db_parent_class)->constructed (object);

	SoupCookieJarDB *jar = SOUP_COOKIE_JAR_DB (object);
	SoupCookieJarDBPrivate *priv = soup_cookie_jar_db_get_instance_private (jar);

	if (!open_db (SOUP_COOKIE_JAR (object), &priv->init_error))
		return;

	priv->is_initializing = TRUE;
	exec_query_with_try_create_table (priv->db, QUERY_ALL, callback, jar);
	priv->is_initializing = FALSE;

	if (!soup_cookie_jar_db_get_default_page_size (jar, &priv->init_error))
		return;

	if (!soup_cookie_jar_db_get_default_max_page_count (jar, &priv->init_error))
		return;

	if (priv->max_size > 0)
		db_set_max_size (jar, priv->max_size, &priv->init_error);
}

static gboolean
soup_cookie_jar_db_initable_init (GInitable     *initable,
				  GCancellable  *cancellable,
				  GError       **error)
{
	SoupCookieJarDBPrivate *priv = soup_cookie_jar_db_get_instance_private (SOUP_COOKIE_JAR_DB (initable));

	/* This is an unusual pattern but it was done to retain full API compatibility with
	 * the version before GInitable while still exposing previously hidden errors. */
	if (priv->init_error) {
		g_propagate_error (error, g_error_copy (priv->init_error));
		return FALSE;
	}
	return TRUE;
}

static void
soup_cookie_jar_db_initable_iface_init (GInitableIface *iface)
{
	iface->init = soup_cookie_jar_db_initable_init;
}

static void
soup_cookie_jar_db_changed (SoupCookieJar *jar,
			    SoupCookie    *old_cookie,
			    SoupCookie    *new_cookie)
{
	SoupCookieJarDBPrivate *priv =
		soup_cookie_jar_db_get_instance_private (SOUP_COOKIE_JAR_DB (jar));
	char *query;

	if (priv->is_initializing || priv->db == NULL)
		return;

	if (old_cookie) {
		query = sqlite3_mprintf (QUERY_DELETE,
					 soup_cookie_get_name (old_cookie),
					 soup_cookie_get_domain (old_cookie));
		exec_query_with_try_create_table (priv->db, query, NULL, NULL);
		sqlite3_free (query);
	}

	if (new_cookie && soup_cookie_get_expires (new_cookie)) {
		gulong expires;
		
		expires = (gulong)g_date_time_to_unix (soup_cookie_get_expires (new_cookie));
		query = sqlite3_mprintf (QUERY_INSERT, 
					 soup_cookie_get_name (new_cookie),
					 soup_cookie_get_value (new_cookie),
					 soup_cookie_get_domain (new_cookie),
					 soup_cookie_get_path (new_cookie),
					 expires,
					 soup_cookie_get_secure (new_cookie),
					 soup_cookie_get_http_only (new_cookie),
					 soup_cookie_get_same_site_policy (new_cookie));
		exec_query_with_try_create_table (priv->db, query, NULL, NULL);
		sqlite3_free (query);
	}
}

static gboolean
soup_cookie_jar_db_is_persistent (SoupCookieJar *jar)
{
	return TRUE;
}

static void
soup_cookie_jar_db_class_init (SoupCookieJarDBClass *db_class)
{
	SoupCookieJarClass *cookie_jar_class =
		SOUP_COOKIE_JAR_CLASS (db_class);
	GObjectClass *object_class = G_OBJECT_CLASS (db_class);

	cookie_jar_class->is_persistent = soup_cookie_jar_db_is_persistent;
	cookie_jar_class->changed       = soup_cookie_jar_db_changed;

	object_class->constructed  = soup_cookie_jar_db_constructed;
	object_class->finalize     = soup_cookie_jar_db_finalize;
	object_class->set_property = soup_cookie_jar_db_set_property;
	object_class->get_property = soup_cookie_jar_db_get_property;

	/**
	 * SoupCookieJarDB:filename:
	 *
	 * Cookie-storage filename.
	 */
        properties[PROP_FILENAME] =
		g_param_spec_string ("filename",
				     "Filename",
				     "Cookie-storage filename",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

	/**
	 * SoupCookieJarDB:max-size:
	 *
	 * Cookie-storage maximum database size.
	 *
	 * Since: 3.8
	 */
	properties[PROP_MAX_SIZE] =
		g_param_spec_uint64 ("max-size",
		                     "Database maximum size",
		                     NULL,
		                     0,
		                     G_MAXUINT64,
		                     0,
		                     G_PARAM_READWRITE | G_PARAM_EXPLICIT_NOTIFY | G_PARAM_STATIC_STRINGS | G_PARAM_CONSTRUCT_ONLY);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}
