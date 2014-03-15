/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

#include <glib/gprintf.h>

#include <locale.h>
#include <signal.h>

#ifdef HAVE_APACHE
static gboolean apache_running;
#endif

static SoupLogger *logger;
static SoupBuffer *index_buffer;

int debug_level;
gboolean expect_warning, tls_available;
static int http_debug_level;

static gboolean
increment_debug_level (const char *option_name, const char *value,
		       gpointer data, GError **error)
{
	debug_level++;
	return TRUE;
}

static gboolean
increment_http_debug_level (const char *option_name, const char *value,
			    gpointer data, GError **error)
{
	http_debug_level++;
	return TRUE;
}

static GOptionEntry debug_entry[] = {
	{ "debug", 'd', G_OPTION_FLAG_NO_ARG,
	  G_OPTION_ARG_CALLBACK, increment_debug_level,
	  "Enable (or increase) test-specific debugging", NULL },
	{ "http-debug", 'H', G_OPTION_FLAG_NO_ARG,
	  G_OPTION_ARG_CALLBACK, increment_http_debug_level,
	  "Enable (or increase) HTTP-level debugging", NULL },
	{ NULL }
};

static void
quit (int sig)
{
#ifdef HAVE_APACHE
	if (apache_running)
		apache_cleanup ();
#endif

	exit (1);
}

void
test_init (int argc, char **argv, GOptionEntry *entries)
{
	GOptionContext *opts;
	char *name;
	GError *error = NULL;
	GTlsBackend *tls_backend;

	setlocale (LC_ALL, "");
	g_setenv ("GSETTINGS_BACKEND", "memory", TRUE);
	g_setenv ("GIO_USE_PROXY_RESOLVER", "dummy", TRUE);

	name = strrchr (argv[0], '/');
	if (!name++)
		name = argv[0];
	if (!strncmp (name, "lt-", 3))
		name += 3;
	g_set_prgname (name);

	g_test_init (&argc, &argv, NULL);
	g_test_set_nonfatal_assertions ();
	g_test_bug_base ("https://bugzilla.gnome.org/");

	opts = g_option_context_new (NULL);
	g_option_context_add_main_entries (opts, debug_entry, NULL);
	if (entries)
		g_option_context_add_main_entries (opts, entries, NULL);

	if (!g_option_context_parse (opts, &argc, &argv, &error)) {
		g_printerr ("Could not parse arguments: %s\n",
			    error->message);
		g_printerr ("%s",
			    g_option_context_get_help (opts, TRUE, NULL));
		exit (1);
	}
	g_option_context_free (opts);

	/* Exit cleanly on ^C in case we're valgrinding. */
	signal (SIGINT, quit);

	tls_backend = g_tls_backend_get_default ();
	tls_available = g_tls_backend_supports_tls (tls_backend);
}

void
test_cleanup (void)
{
#ifdef HAVE_APACHE
	if (apache_running)
		apache_cleanup ();
#endif

	if (logger)
		g_object_unref (logger);
	if (index_buffer)
		soup_buffer_free (index_buffer);

	g_main_context_unref (g_main_context_default ());

	debug_printf (1, "\n");
}

void
debug_printf (int level, const char *format, ...)
{
	va_list args;

	if (debug_level < level)
		return;

	va_start (args, format);
	g_vprintf (format, args);
	va_end (args);
}

#ifdef HAVE_APACHE

static gboolean
apache_cmd (const char *cmd)
{
	GPtrArray *argv;
	char *server_root, *cwd, *pid_file;
#ifdef HAVE_APACHE_2_4
	char *default_runtime_dir;
#endif
	int status;
	gboolean ok;

	server_root = g_test_build_filename (G_TEST_BUILT, "", NULL);

	cwd = g_get_current_dir ();
#ifdef HAVE_APACHE_2_4
	default_runtime_dir = g_strdup_printf ("DefaultRuntimeDir %s", cwd);
#endif
	pid_file = g_strdup_printf ("PidFile %s/httpd.pid", cwd);

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, APACHE_HTTPD);
	g_ptr_array_add (argv, "-d");
	g_ptr_array_add (argv, server_root);
	g_ptr_array_add (argv, "-f");
	g_ptr_array_add (argv, "httpd.conf");

#ifdef HAVE_APACHE_2_4
	g_ptr_array_add (argv, "-c");
	g_ptr_array_add (argv, default_runtime_dir);
#endif
	g_ptr_array_add (argv, "-c");
	g_ptr_array_add (argv, pid_file);

	g_ptr_array_add (argv, "-k");
	g_ptr_array_add (argv, (char *)cmd);
	g_ptr_array_add (argv, NULL);

	ok = g_spawn_sync (cwd, (char **)argv->pdata, NULL, 0, NULL, NULL,
			   NULL, NULL, &status, NULL);
	if (ok)
		ok = (status == 0);

	g_free (server_root);
	g_free (cwd);
	g_free (pid_file);
#ifdef HAVE_APACHE_2_4
	g_free (default_runtime_dir);
#endif
	g_ptr_array_free (argv, TRUE);

	return ok;
}

void
apache_init (void)
{
	if (g_getenv ("SOUP_TESTS_IN_MAKE_CHECK"))
		return;

	if (!apache_cmd ("start")) {
		g_printerr ("Could not start apache\n");
		exit (1);
	}
	apache_running = TRUE;
}

void
apache_cleanup (void)
{
	pid_t pid;
	char *contents;

	if (g_file_get_contents ("httpd.pid", &contents, NULL, NULL)) {
		pid = strtoul (contents, NULL, 10);
		g_free (contents);
	} else
		pid = 0;

	if (!apache_cmd ("graceful-stop"))
		return;
	apache_running = FALSE;

	if (pid) {
		while (kill (pid, 0) == 0)
			g_usleep (100);
	}
}

#endif /* HAVE_APACHE */

SoupSession *
soup_test_session_new (GType type, ...)
{
	va_list args;
	const char *propname;
	SoupSession *session;
	char *cafile;

	va_start (args, type);
	propname = va_arg (args, const char *);
	session = (SoupSession *)g_object_new_valist (type, propname, args);
	va_end (args);

	cafile = g_test_build_filename (G_TEST_DIST, "test-cert.pem", NULL);
	g_object_set (G_OBJECT (session),
		      SOUP_SESSION_SSL_CA_FILE, cafile,
		      NULL);
	g_free (cafile);

	if (http_debug_level && !logger) {
		SoupLoggerLogLevel level = MIN ((SoupLoggerLogLevel)http_debug_level, SOUP_LOGGER_LOG_BODY);

		logger = soup_logger_new (level, -1);
	}

	if (logger)
		soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));

	return session;
}

void
soup_test_session_abort_unref (SoupSession *session)
{
	soup_session_abort (session);

	g_assert_cmpint (G_OBJECT (session)->ref_count, ==, 1);
	g_object_unref (session);
}

static gpointer run_server_thread (gpointer user_data);

static SoupServer *
test_server_new (gboolean in_own_thread, gboolean ssl)
{
	SoupServer *server;
	GMainContext *async_context;
	char *ssl_cert_file, *ssl_key_file;
	SoupAddress *addr;

	async_context = in_own_thread ? g_main_context_new () : NULL;

	if (ssl) {
		ssl_cert_file = g_test_build_filename (G_TEST_DIST, "test-cert.pem", NULL);
		ssl_key_file = g_test_build_filename (G_TEST_DIST, "test-key.pem", NULL);
	} else
		ssl_cert_file = ssl_key_file = NULL;

	addr = soup_address_new ("127.0.0.1", SOUP_ADDRESS_ANY_PORT);
	soup_address_resolve_sync (addr, NULL);

	server = soup_server_new (SOUP_SERVER_INTERFACE, addr,
				  SOUP_SERVER_ASYNC_CONTEXT, async_context,
				  SOUP_SERVER_SSL_CERT_FILE, ssl_cert_file,
				  SOUP_SERVER_SSL_KEY_FILE, ssl_key_file,
				  NULL);
	g_object_unref (addr);
	if (async_context)
		g_main_context_unref (async_context);
	g_free (ssl_cert_file);
	g_free (ssl_key_file);

	if (!server) {
		g_printerr ("Unable to create server\n");
		exit (1);
	}

	if (in_own_thread) {
		GThread *thread;

		thread = g_thread_new ("server_thread", run_server_thread, server);
		g_object_set_data (G_OBJECT (server), "thread", thread);
	} else
		soup_server_run_async (server);

	return server;
}

SoupServer *
soup_test_server_new (gboolean in_own_thread)
{
	return test_server_new (in_own_thread, FALSE);
}

SoupServer *
soup_test_server_new_ssl (gboolean in_own_thread)
{
	return test_server_new (in_own_thread, TRUE);
}

static gpointer
run_server_thread (gpointer user_data)
{
	SoupServer *server = user_data;

	soup_server_run (server);
	return NULL;
}

static gboolean
idle_quit_server (gpointer server)
{
	soup_server_quit (server);
	return FALSE;
}

void
soup_test_server_quit_unref (SoupServer *server)
{
	GThread *thread;

	thread = g_object_get_data (G_OBJECT (server), "thread");
	if (thread) {
		soup_add_completion (soup_server_get_async_context (server),
				     idle_quit_server, server);
		g_thread_join (thread);
	} else
		soup_server_quit (server);

	g_assert_cmpint (G_OBJECT (server)->ref_count, ==, 1);
	g_object_unref (server);
}

typedef struct {
	GMainLoop *loop;
	GAsyncResult *result;
} AsyncAsSyncData;

static void
async_as_sync_callback (GObject      *object,
			GAsyncResult *result,
			gpointer      user_data)
{
	AsyncAsSyncData *data = user_data;
	GMainContext *context;

	data->result = g_object_ref (result);
	context = g_main_loop_get_context (data->loop);
	while (g_main_context_pending (context))
		g_main_context_iteration (context, FALSE);
	g_main_loop_quit (data->loop);
}

typedef struct {
	SoupRequest  *req;
	GCancellable *cancellable;
	SoupTestRequestFlags flags;
} CancelData;

static CancelData *
create_cancel_data (SoupRequest          *req,
		    GCancellable         *cancellable,
		    SoupTestRequestFlags  flags)
{
	CancelData *cancel_data;

	if (!flags)
		return NULL;

	cancel_data = g_slice_new0 (CancelData);
	cancel_data->flags = flags;
	if (flags & SOUP_TEST_REQUEST_CANCEL_MESSAGE && SOUP_IS_REQUEST_HTTP (req))
		cancel_data->req = g_object_ref (req);
	else if (flags & SOUP_TEST_REQUEST_CANCEL_CANCELLABLE)
		cancel_data->cancellable = g_object_ref (cancellable);
	return cancel_data;
}

static void inline
cancel_message_or_cancellable (CancelData *cancel_data)
{
	if (cancel_data->flags & SOUP_TEST_REQUEST_CANCEL_MESSAGE) {
		SoupRequest *req = cancel_data->req;
		SoupMessage *msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
		soup_session_cancel_message (soup_request_get_session (req), msg,
					     SOUP_STATUS_CANCELLED);
		g_object_unref (msg);
		g_object_unref (req);
	} else if (cancel_data->flags & SOUP_TEST_REQUEST_CANCEL_CANCELLABLE) {
		g_cancellable_cancel (cancel_data->cancellable);
		g_object_unref (cancel_data->cancellable);
	}
	g_slice_free (CancelData, cancel_data);
}

static gboolean
cancel_request_timeout (gpointer data)
{
	cancel_message_or_cancellable ((CancelData *) data);
	return FALSE;
}

static gpointer
cancel_request_thread (gpointer data)
{
	g_usleep (100000); /* .1s */
	cancel_message_or_cancellable ((CancelData *) data);
	return NULL;
}

GInputStream *
soup_test_request_send (SoupRequest   *req,
			GCancellable  *cancellable,
			guint          flags,
			GError       **error)
{
	AsyncAsSyncData data;
	GInputStream *stream;
	CancelData *cancel_data = create_cancel_data (req, cancellable, flags);

	if (SOUP_IS_SESSION_SYNC (soup_request_get_session (req))) {
		GThread *thread;

		if (cancel_data)
			thread = g_thread_new ("cancel_request_thread", cancel_request_thread,
					       cancel_data);
		stream = soup_request_send (req, cancellable, error);
		if (cancel_data)
			g_thread_unref (thread);
		return stream;
	}

	data.loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);
	if (cancel_data &&
	    (flags & SOUP_TEST_REQUEST_CANCEL_SOON || flags & SOUP_TEST_REQUEST_CANCEL_IMMEDIATE)) {
		guint interval = flags & SOUP_TEST_REQUEST_CANCEL_SOON ? 100 : 0;
		g_timeout_add_full (G_PRIORITY_HIGH, interval, cancel_request_timeout, cancel_data, NULL);
	}
	if (cancel_data && (flags & SOUP_TEST_REQUEST_CANCEL_PREEMPTIVE))
		g_cancellable_cancel (cancellable);
	soup_request_send_async (req, cancellable, async_as_sync_callback, &data);
	g_main_loop_run (data.loop);

	stream = soup_request_send_finish (req, data.result, error);

	if (cancel_data && (flags &  SOUP_TEST_REQUEST_CANCEL_AFTER_SEND_FINISH)) {
		GMainContext *context;

		cancel_message_or_cancellable (cancel_data);

		context = g_main_loop_get_context (data.loop);
		while (g_main_context_pending (context))
			g_main_context_iteration (context, FALSE);
	}

	g_main_loop_unref (data.loop);
	g_object_unref (data.result);

	return stream;
}

gboolean
soup_test_request_read_all (SoupRequest   *req,
			    GInputStream  *stream,
			    GCancellable  *cancellable,
			    GError       **error)
{
	char buf[8192];
	AsyncAsSyncData data;
	gsize nread;

	if (!SOUP_IS_SESSION_SYNC (soup_request_get_session (req)))
		data.loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);

	do {
		if (SOUP_IS_SESSION_SYNC (soup_request_get_session (req))) {
			nread = g_input_stream_read (stream, buf, sizeof (buf),
						     cancellable, error);
		} else {
			g_input_stream_read_async (stream, buf, sizeof (buf),
						   G_PRIORITY_DEFAULT, cancellable,
						   async_as_sync_callback, &data);
			g_main_loop_run (data.loop);
			nread = g_input_stream_read_finish (stream, data.result, error);
			g_object_unref (data.result);
		}
	} while (nread > 0);

	if (!SOUP_IS_SESSION_SYNC (soup_request_get_session (req)))
		g_main_loop_unref (data.loop);

	return nread == 0;
}

gboolean
soup_test_request_close_stream (SoupRequest   *req,
				GInputStream  *stream,
				GCancellable  *cancellable,
				GError       **error)
{
	AsyncAsSyncData data;
	gboolean ok;

	if (SOUP_IS_SESSION_SYNC (soup_request_get_session (req)))
		return g_input_stream_close (stream, cancellable, error);

	data.loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);

	g_input_stream_close_async (stream, G_PRIORITY_DEFAULT, cancellable,
				    async_as_sync_callback, &data);
	g_main_loop_run (data.loop);

	ok = g_input_stream_close_finish (stream, data.result, error);

	g_main_loop_unref (data.loop);
	g_object_unref (data.result);

	return ok;
}

void
soup_test_register_resources (void)
{
	static gboolean registered = FALSE;
	GResource *resource;
	char *path;
	GError *error = NULL;

	if (registered)
		return;

	path = g_test_build_filename (G_TEST_BUILT, "soup-tests.gresource", NULL);
	resource = g_resource_load (path, &error);
	if (!resource) {
		g_printerr ("Could not load resource soup-tests.gresource: %s\n",
			    error->message);
		exit (1);
	}
	g_free (path);

	g_resources_register (resource);
	g_resource_unref (resource);

	registered = TRUE;
}

SoupBuffer *
soup_test_load_resource (const char  *name,
			 GError     **error)
{
	GBytes *bytes;
	char *path;

	soup_test_register_resources ();

	path = g_build_path ("/", "/org/gnome/libsoup/tests/resources", name, NULL);
	bytes = g_resources_lookup_data (path, G_RESOURCE_LOOKUP_FLAGS_NONE, error);
	g_free (path);

	if (!bytes)
		return NULL;

	return soup_buffer_new_with_owner (g_bytes_get_data (bytes, NULL),
					   g_bytes_get_size (bytes),
					   bytes,
					   (GDestroyNotify) g_bytes_unref);
}

SoupBuffer *
soup_test_get_index (void)
{
	if (!index_buffer) {
		char *path, *contents;
		gsize length;
		GError *error = NULL;

		path = g_test_build_filename (G_TEST_DIST, "index.txt", NULL);
		if (!g_file_get_contents (path, &contents, &length, &error)) {
			g_printerr ("Could not read index.txt: %s\n",
				    error->message);
			exit (1);
		}
		g_free (path);

		index_buffer = soup_buffer_new (SOUP_MEMORY_TAKE, contents, length);
	}

	return index_buffer;
}

#ifndef G_HAVE_ISO_VARARGS
void
soup_test_assert (gboolean expr, const char *fmt, ...)
{
	char *message;
	va_list args;

	if (G_UNLIKELY (!expr)) {
		va_start (args, fmt);
		message = g_strdup_vprintf (fmt, args);
		va_end (args);

		g_assertion_message (G_LOG_DOMAIN,
				     "???", 0, "???"
				     message);
		g_free (message);
	}
}
#endif
