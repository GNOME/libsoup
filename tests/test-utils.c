/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "test-utils.h"
#include "soup-misc.h"
#include "soup-session-private.h"
#include "soup-server-private.h"

#include <glib/gprintf.h>
#ifdef G_OS_UNIX
#include <gio/gunixsocketaddress.h>
#endif

#include <locale.h>
#include <signal.h>

#ifdef HAVE_APACHE
static gboolean apache_running;
static char *server_root = NULL;
#endif

static SoupLogger *logger;
static GBytes *index_buffer;

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
	g_setenv ("GIO_USE_VFS", "local", TRUE);

	name = strrchr (argv[0], '/');
	if (!name++)
		name = argv[0];
	if (!strncmp (name, "lt-", 3))
		name += 3;
	g_set_prgname (name);

	g_test_init (&argc, &argv, NULL);
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
		g_bytes_unref (index_buffer);

	g_main_context_unref (g_main_context_default ());

	debug_printf (1, "\n");
}

void
debug_printf (int level, const char *format, ...)
{
	va_list args;
        static char last_char = '\n';

	if (debug_level < level)
		return;

        /* Very hacky solution to outputing in the TAP format,
         * every line starts with # */
        if (last_char == '\n')
                g_printf ("# ");
        last_char = format[strlen (format) - 1];

	va_start (args, format);
	g_vprintf (format, args);
	va_end (args);

	fflush (stdout);
}

gboolean
have_curl(void) {
	char *found;

	found = g_find_program_in_path ("curl");
	if (found) {
		g_free (found);
		return TRUE;
	} else {
		return FALSE;
	}
}

#ifdef HAVE_APACHE

static gboolean
apache_cmd (const char *cmd)
{
	GPtrArray *argv;
	char *cwd, *pid_file;
#ifdef HAVE_APACHE_2_4
	char *default_runtime_dir;
#endif
	int status;
	gboolean ok;
	GString *str;
	guint i;

	if (server_root == NULL) {
		g_test_message ("Server root not initialized");
		return FALSE;
	}

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

	str = g_string_new ("Apache command:");

	for (i = 0; i < argv->len - 1; i++) {
		char *escaped = g_shell_quote (argv->pdata[i]);
		g_string_append_c (str, ' ');
		g_string_append (str, escaped);
		g_free (escaped);
	}

	g_test_message ("%s", str->str);
	g_string_free (str, TRUE);

	ok = g_spawn_sync (cwd, (char **)argv->pdata, NULL, 0, NULL, NULL,
			   NULL, NULL, &status, NULL);
	if (ok)
		ok = (status == 0);

	g_free (cwd);
	g_free (pid_file);
#ifdef HAVE_APACHE_2_4
	g_free (default_runtime_dir);
#endif
	g_ptr_array_free (argv, TRUE);

	g_test_message (ok ? "-> success" : "-> failed");
	return ok;
}

void
apache_init (void)
{
	/* Set this environment variable if you are already running a
	 * suitably-configured Apache server */
	if (g_getenv ("SOUP_TESTS_ALREADY_RUNNING_APACHE"))
		return;

	server_root = soup_test_build_filename_abs (G_TEST_BUILT, "", NULL);

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

	g_clear_pointer (&server_root, g_free);
}

#endif /* HAVE_APACHE */

SoupSession *
soup_test_session_new (const char *propname, ...)
{
	va_list args;
	SoupSession *session;
	GTlsDatabase *tlsdb;
	char *cafile;
	GError *error = NULL;

	va_start (args, propname);
	session = (SoupSession *)g_object_new_valist (SOUP_TYPE_SESSION, propname, args);
	va_end (args);

	if (tls_available) {
		char *abs_cafile;

		cafile = g_test_build_filename (G_TEST_DIST, "test-cert.pem", NULL);
		abs_cafile = g_canonicalize_filename (cafile, NULL);
		g_free (cafile);
		tlsdb = g_tls_file_database_new (abs_cafile, &error);
		g_free (abs_cafile);
		if (error) {
			if (g_strcmp0 (g_getenv ("GIO_USE_TLS"), "dummy") == 0)
				g_clear_error (&error);
			else
				g_assert_no_error (error);
		}

		soup_session_set_tls_database (session, tlsdb);
		g_clear_object (&tlsdb);
	}

	if (http_debug_level && !logger) {
		SoupLoggerLogLevel level = MIN ((SoupLoggerLogLevel)http_debug_level, SOUP_LOGGER_LOG_BODY);

		logger = soup_logger_new (level);
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

typedef struct {
	SoupMessage *msg;
	GBytes *body;
	GError *error;
	gboolean done;
        gboolean message_finished;
} SendAsyncData;

static void
send_and_read_async_ready_cb (SoupSession   *session,
			      GAsyncResult  *result,
			      SendAsyncData *data)
{
	data->done = TRUE;
	g_assert_true (soup_session_get_async_result_message (session, result) == data->msg);
	data->body = soup_session_send_and_read_finish (session, result, &data->error);
        if (g_error_matches (data->error, SOUP_SESSION_ERROR, SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE))
                data->message_finished = TRUE;
}

static void
on_message_finished (SoupMessage   *msg,
                     SendAsyncData *data)
{
        data->message_finished = TRUE;
}

GBytes *
soup_test_session_async_send (SoupSession  *session,
			      SoupMessage  *msg,
			      GCancellable *cancellable,
			      GError      **error)
{
	GMainContext *async_context = g_main_context_ref_thread_default ();
	gulong signal_id;
	SendAsyncData data = { msg, NULL, NULL, FALSE, FALSE };

	signal_id = g_signal_connect (msg, "finished",
                                      G_CALLBACK (on_message_finished), &data);

	soup_session_send_and_read_async (session, msg, G_PRIORITY_DEFAULT, cancellable,
					  (GAsyncReadyCallback)send_and_read_async_ready_cb, &data);

	while (!data.done || !data.message_finished)
		g_main_context_iteration (async_context, TRUE);

	g_signal_handler_disconnect (msg, signal_id);

	if (data.error)
		g_propagate_error (error, data.error);

        g_main_context_unref (async_context);
	return data.body;
}

guint
soup_test_session_send_message (SoupSession *session,
				SoupMessage *msg)
{
	GInputStream *stream;

	stream = soup_session_send (session, msg, NULL, NULL);
	if (stream)
		g_object_unref (stream);

	return soup_message_get_status (msg);
}

const char *
soup_test_server_get_unix_path (SoupServer *server)
{
	return g_object_get_data (G_OBJECT (server), "unix-socket-path");
}

static void
server_listen (SoupServer *server)
{
	GError *error = NULL;
        SoupServerListenOptions options = 0;
	GSocket *socket;

        if (g_getenv ("SOUP_TEST_NO_IPV6"))
                options = SOUP_SERVER_LISTEN_IPV4_ONLY;

	socket = g_object_get_data (G_OBJECT (server), "listen-socket");
	if (socket != NULL)
		soup_server_listen_socket (server, socket, 0, &error);
	else
		soup_server_listen_local (server, 0, options, &error);
	if (error) {
		g_printerr ("Unable to create server: %s\n", error->message);
		exit (1);
	}
}

static GMutex server_start_mutex;
static GCond server_start_cond;

static gpointer
run_server_thread (gpointer user_data)
{
	SoupServer *server = user_data;
	SoupTestServerOptions options =
		GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (server), "options"));
	GMainContext *context;
	GMainLoop *loop;

	context = g_main_context_new ();
	g_main_context_push_thread_default (context);
	loop = g_main_loop_new (context, FALSE);
	g_object_set_data (G_OBJECT (server), "GMainLoop", loop);

	if (!(options & SOUP_TEST_SERVER_NO_DEFAULT_LISTENER))
		server_listen (server);

	g_mutex_lock (&server_start_mutex);
	g_cond_signal (&server_start_cond);
	g_mutex_unlock (&server_start_mutex);

	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	soup_server_disconnect (server);

	g_main_context_pop_thread_default (context);
	g_main_context_unref (context);

	return NULL;
}

void
soup_test_server_run_in_thread (SoupServer *server)
{
	GThread *thread;

	g_mutex_lock (&server_start_mutex);

	thread = g_thread_new ("server_thread", run_server_thread, server);
	g_cond_wait (&server_start_cond, &server_start_mutex);
	g_mutex_unlock (&server_start_mutex);

	g_object_set_data (G_OBJECT (server), "thread", thread);
}

SoupServer *
soup_test_server_new (SoupTestServerOptions options)
{
	SoupServer *server;
	GTlsCertificate *cert = NULL;
	GError *error = NULL;

	if (tls_available) {
		char *ssl_cert_file, *ssl_key_file;

		ssl_cert_file = g_test_build_filename (G_TEST_DIST, "test-cert.pem", NULL);
		ssl_key_file = g_test_build_filename (G_TEST_DIST, "test-key.pem", NULL);
		cert = g_tls_certificate_new_from_files (ssl_cert_file,
							 ssl_key_file,
							 &error);
		g_free (ssl_cert_file);
		g_free (ssl_key_file);
		if (error) {
			g_printerr ("Unable to create server: %s\n", error->message);
			exit (1);
		}
	}

	server = soup_server_new ("tls-certificate", cert,
				  NULL);
	g_clear_object (&cert);

        soup_server_set_http2_enabled (server, options & SOUP_TEST_SERVER_HTTP2);

	g_object_set_data (G_OBJECT (server), "options", GUINT_TO_POINTER (options));

	if (options & SOUP_TEST_SERVER_UNIX_SOCKET) {
#ifdef G_OS_UNIX
		char *socket_dir, *socket_path;
		GSocket *listen_socket;
		GSocketAddress *listen_address;

		socket_dir = g_dir_make_tmp ("unix-socket-test-XXXXXX", NULL);
		socket_path = g_build_filename (socket_dir, "socket", NULL);
		g_object_set_data_full (G_OBJECT (server), "unix-socket-path", socket_path, g_free);
		g_free (socket_dir);

		listen_socket = g_socket_new (G_SOCKET_FAMILY_UNIX,
					      G_SOCKET_TYPE_STREAM,
					      G_SOCKET_PROTOCOL_DEFAULT,
					      &error);
		if (listen_socket == NULL) {
			g_printerr ("Unable to create unix socket: %s\n", error->message);
			exit (1);
		}

		listen_address = g_unix_socket_address_new (socket_path);
		if (!g_socket_bind (listen_socket, listen_address, TRUE, &error)) {
			g_printerr ("Unable to bind unix socket to %s: %s\n", socket_path, error->message);
			exit (1);
		}
		g_object_unref (listen_address);
		if (!g_socket_listen (listen_socket, &error)) {
			g_printerr ("Unable to listen on unix socket: %s\n", error->message);
			exit (1);
		}

		g_object_set_data_full (G_OBJECT (server), "listen-socket", listen_socket, g_object_unref);
#else
		g_printerr ("Unix socket support not available\n");
		exit (1);
#endif
	}

	if (options & SOUP_TEST_SERVER_IN_THREAD)
		soup_test_server_run_in_thread (server);
	else if (!(options & SOUP_TEST_SERVER_NO_DEFAULT_LISTENER))
		server_listen (server);

	return server;
}

static GUri *
find_server_uri (SoupServer *server, const char *scheme, const char *host)
{
	GSList *uris, *u;
	GUri *uri, *ret_uri = NULL;

	uris = soup_server_get_uris (server);
	for (u = uris; u; u = u->next) {
		uri = u->data;

		if (scheme && strcmp (g_uri_get_scheme (uri), scheme) != 0)
			continue;
		if (host && strcmp (g_uri_get_host (uri), host) != 0)
			continue;

		ret_uri = g_uri_ref (uri);
		break;
	}
	g_slist_free_full (uris, (GDestroyNotify)g_uri_unref);

	return ret_uri;
}

static GUri *
add_listener (SoupServer *server, const char *scheme, const char *host)
{
	SoupServerListenOptions options = 0;
	GError *error = NULL;

	if (!g_strcmp0 (scheme, "https"))
		options |= SOUP_SERVER_LISTEN_HTTPS;

	if (!g_strcmp0 (host, "127.0.0.1") || g_getenv ("SOUP_TEST_NO_IPV6"))
		options |= SOUP_SERVER_LISTEN_IPV4_ONLY;
	else if (!g_strcmp0 (host, "::1"))
		options |= SOUP_SERVER_LISTEN_IPV6_ONLY;

	soup_server_listen_local (server, 0, options, &error);
	g_assert_no_error (error);

	return find_server_uri (server, scheme, host);
}

typedef struct {
	GMutex mutex;
	GCond cond;

	SoupServer *server;
	const char *scheme;
	const char *host;

	GUri *uri;
} AddListenerData;

static gboolean
add_listener_in_thread (gpointer user_data)
{
	AddListenerData *data = user_data;
	GUri *uri;

	uri = add_listener (data->server, data->scheme, data->host);
	g_mutex_lock (&data->mutex);
	data->uri = uri;
	g_cond_signal (&data->cond);
	g_mutex_unlock (&data->mutex);

	return FALSE;
}

GUri *
soup_test_server_get_uri (SoupServer    *server,
			  const char    *scheme,
			  const char    *host)
{
	GUri *uri;
	GMainLoop *loop;

	uri = find_server_uri (server, scheme, host);
	if (uri)
		return uri;

	/* Need to add a new listener */
	loop = g_object_get_data (G_OBJECT (server), "GMainLoop");
	if (loop) {
		GMainContext *context = g_main_loop_get_context (loop);
		AddListenerData data;

		g_mutex_init (&data.mutex);
		g_cond_init (&data.cond);
		data.server = server;
		data.scheme = scheme;
		data.host = host;
		data.uri = NULL;

		soup_add_completion (context, add_listener_in_thread, &data);

		g_mutex_lock (&data.mutex);
		while (!data.uri)
			g_cond_wait (&data.cond, &data.mutex);

		g_mutex_unlock (&data.mutex);
		g_mutex_clear (&data.mutex);
		g_cond_clear (&data.cond);
		uri = data.uri;
	} else
		uri = add_listener (server, scheme, host);

	return uri;
}

static gboolean
done_waiting (gpointer user_data)
{
	gboolean *done = user_data;

	*done = TRUE;
	return FALSE;
}

static void
disconnect_and_wait (SoupServer *server,
		     GMainContext *context)
{
	GSource *source;
	gboolean done = FALSE;

	source = g_idle_source_new ();
	g_source_set_priority (source, G_PRIORITY_LOW);
	g_source_set_callback (source, done_waiting, &done, NULL);
	g_source_attach (source, context);
	g_source_unref (source);

	soup_server_disconnect (server);
	while (!done)
		g_main_context_iteration (context, TRUE);
}

static gboolean
idle_quit_server (gpointer user_data)
{
	SoupServer *server = user_data;
	GMainLoop *loop = g_object_get_data (G_OBJECT (server), "GMainLoop");

	disconnect_and_wait (server, g_main_loop_get_context (loop));
	g_main_loop_quit (loop);
	return FALSE;
}

void
soup_test_server_quit_unref (SoupServer *server)
{
	GThread *thread;

	thread = g_object_get_data (G_OBJECT (server), "thread");
	if (thread) {
		GMainLoop *loop;
		GMainContext *context;

		loop = g_object_get_data (G_OBJECT (server), "GMainLoop");
		context = g_main_loop_get_context (loop);
		g_main_context_ref (context);
		soup_add_completion (context, idle_quit_server, server);
		g_main_context_unref (context);
		g_thread_join (thread);
	} else
		disconnect_and_wait (server, NULL);

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

	data->result = g_object_ref (result);
	g_main_loop_quit (data->loop);
}

static gboolean
cancel_request_timeout (GCancellable *cancellable)
{
	g_cancellable_cancel (cancellable);
	return FALSE;
}

GInputStream *
soup_test_request_send (SoupSession   *session,
			SoupMessage   *msg,
			GCancellable  *cancellable,
			guint          flags,
			GError       **error)
{
	AsyncAsSyncData data;
	GInputStream *stream;

	data.loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);
	if (flags & SOUP_TEST_REQUEST_CANCEL_SOON || flags & SOUP_TEST_REQUEST_CANCEL_IMMEDIATE) {
		guint interval = flags & SOUP_TEST_REQUEST_CANCEL_SOON ? 100 : 0;
		g_timeout_add_full (G_PRIORITY_HIGH, interval,
				    (GSourceFunc)cancel_request_timeout,
				    g_object_ref (cancellable), g_object_unref);
	}
	if (flags & SOUP_TEST_REQUEST_CANCEL_PREEMPTIVE)
		g_cancellable_cancel (cancellable);

	soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, cancellable,
				 async_as_sync_callback, &data);
	g_main_loop_run (data.loop);

	g_assert_true (soup_session_get_async_result_message (session, data.result) == msg);

	stream = soup_session_send_finish (session, data.result, error);

	if (flags & SOUP_TEST_REQUEST_CANCEL_AFTER_SEND_FINISH) {
                if (flags & SOUP_TEST_REQUEST_CANCEL_BY_SESSION)
                        soup_session_cancel_message (session, msg);
                else
                        g_cancellable_cancel (cancellable);
	}

	g_main_loop_unref (data.loop);
	g_object_unref (data.result);

	return stream;
}

gboolean
soup_test_request_read_all (GInputStream  *stream,
			    GCancellable  *cancellable,
			    GError       **error)
{
	char buf[8192];
	AsyncAsSyncData data;
	gsize nread;

        data.loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);

	do {
                g_input_stream_read_async (stream, buf, sizeof (buf),
					   G_PRIORITY_DEFAULT, cancellable,
					   async_as_sync_callback, &data);
                g_main_loop_run (data.loop);
                nread = g_input_stream_read_finish (stream, data.result, error);
                g_object_unref (data.result);
	} while (nread > 0);

	g_main_loop_unref (data.loop);

	return nread == 0;
}

gboolean
soup_test_request_close_stream (GInputStream  *stream,
				GCancellable  *cancellable,
				GError       **error)
{
	AsyncAsSyncData data;
	gboolean ok;

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

GBytes *
soup_test_load_resource (const char  *name,
			 GError     **error)
{
	GBytes *bytes;
	char *path;

	soup_test_register_resources ();

	path = g_build_path ("/", "/org/gnome/libsoup/tests/resources", name, NULL);
	bytes = g_resources_lookup_data (path, G_RESOURCE_LOOKUP_FLAGS_NONE, error);
	g_free (path);

        return bytes;
}

GBytes *
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

		index_buffer = g_bytes_new_take (contents, length);
	}

	return index_buffer;
}

char *
soup_test_build_filename_abs (GTestFileType  file_type,
                              const gchar   *first_path,
                              ...)
{
        const gchar *pathv[16];
        gsize num_path_segments;
        char *path;
        char *path_abs;
        va_list ap;

        va_start (ap, first_path);

        pathv[0] = g_test_get_dir (file_type);
        pathv[1] = first_path;

        for (num_path_segments = 2; num_path_segments < G_N_ELEMENTS (pathv); num_path_segments++) {
                pathv[num_path_segments] = va_arg (ap, const char *);
                if (pathv[num_path_segments] == NULL)
                        break;
        }

        va_end (ap);

        g_assert_cmpint (num_path_segments, <, G_N_ELEMENTS (pathv));

        path = g_build_filenamev ((gchar **) pathv);
        if (g_path_is_absolute (path))
                return path;

        path_abs = g_canonicalize_filename (path, NULL);
        g_free (path);

        return path_abs;
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
