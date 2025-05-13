/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007, 2008 Red Hat, Inc.
 */

#include "test-utils.h"

static struct {
	const char *title, *name;
	const char *result;
} tests[] = {
	/* Both fields must be filled in */
	{ NULL, "Name", "" },
	{ "Mr.", NULL, "" },

	/* Filled-in but empty is OK */
	{ "", "", "Hello,  " },
	{ "", "Name", "Hello,  Name" },
	{ "Mr.", "", "Hello, MR. " },

	/* Simple */
	{ "Mr.", "Name", "Hello, MR. Name" },

	/* Encoding of spaces */
	{ "Mr.", "Full Name", "Hello, MR. Full Name" },
	{ "Mr. and Mrs.", "Full Name", "Hello, MR. AND MRS. Full Name" },

	/* Encoding of "+" */
	{ "Mr.+Mrs.", "Full Name", "Hello, MR.+MRS. Full Name" },

	/* Encoding of non-ASCII. */
	{ "Se\xC3\xB1or", "Nombre", "Hello, SE\xC3\xB1OR Nombre" },

	/* Encoding of '%' */
	{ "Mr.", "Foo %2f Bar", "Hello, MR. Foo %2f Bar" },
};

static void
do_hello_test_curl (int n, gboolean extra, const char *uri)
{
	GPtrArray *args;
	char *title_arg = NULL, *name_arg = NULL;
	char *str_stdout = NULL;
	GError *error = NULL;

	debug_printf (1, "%2d. '%s' '%s'%s: \n", n * 2 + (extra ? 2 : 1),
		      tests[n].title ? tests[n].title : "(null)",
		      tests[n].name  ? tests[n].name  : "(null)",
		      extra ? " + extra" : "");

	args = g_ptr_array_new ();
	g_ptr_array_add (args, "curl");
	g_ptr_array_add (args, "--noproxy");
	g_ptr_array_add (args, "*");
	g_ptr_array_add (args, "-G");
	if (tests[n].title) {
		title_arg = soup_form_encode ("title", tests[n].title, NULL);
		g_ptr_array_add (args, "-d");
		g_ptr_array_add (args, title_arg);
	}
	if (tests[n].name) {
		name_arg = soup_form_encode ("n@me", tests[n].name, NULL);
		g_ptr_array_add (args, "-d");
		g_ptr_array_add (args, name_arg);
	}
	if (extra) {
		g_ptr_array_add (args, "-d");
		g_ptr_array_add (args, "extra=something");
	}
	g_ptr_array_add (args, (char *)uri);
	g_ptr_array_add (args, NULL);

	if (g_spawn_sync (NULL, (char **)args->pdata, NULL,
			  G_SPAWN_SEARCH_PATH | G_SPAWN_STDERR_TO_DEV_NULL,
			  NULL, NULL,
			  &str_stdout, NULL, NULL, &error)) {
		g_assert_cmpstr (str_stdout, ==, tests[n].result);
		g_free (str_stdout);
	} else {
		g_assert_no_error (error);
		g_error_free (error);
	}
	g_ptr_array_free (args, TRUE);
	g_free (title_arg);
	g_free (name_arg);
}

static void
do_hello_tests_curl (gconstpointer uri)
{
	int n;

	if (!have_curl()) {
		g_test_skip ("curl is not available");
		return;
	}

	for (n = 0; n < G_N_ELEMENTS (tests); n++) {
		do_hello_test_curl (n, FALSE, uri);
		do_hello_test_curl (n, TRUE, uri);
	}
}

static void
do_hello_test_libsoup (int n, gboolean extra, const char *uri)
{
	SoupSession *session;
	SoupMessage *msg;
	GData *data;
	GBytes *body;
        char *encoded;

	debug_printf (1, "%2d. '%s' '%s'%s: \n", n * 2 + (extra ? 2 : 1),
		      tests[n].title ? tests[n].title : "(null)",
		      tests[n].name  ? tests[n].name  : "(null)",
		      extra ? " + extra" : "");

	g_datalist_init (&data);
	if (tests[n].title)
		g_datalist_set_data (&data, "title", (gpointer)tests[n].title);
	if (tests[n].name)
		g_datalist_set_data (&data, "n@me", (gpointer)tests[n].name);
	if (extra)
		g_datalist_set_data (&data, "extra", (gpointer)"something");

	session = soup_test_session_new (NULL);

        encoded = soup_form_encode_datalist (&data);
	msg = soup_message_new_from_encoded_form ("GET",
						  uri,
						  encoded);
	g_datalist_clear (&data);

	body = soup_session_send_and_read (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_cmpmem (tests[n].result, strlen (tests[n].result), g_bytes_get_data (body, NULL), g_bytes_get_size (body));

	g_bytes_unref (body);
	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
do_hello_tests_libsoup (gconstpointer uri)
{
	int n;

	for (n = 0; n < G_N_ELEMENTS (tests); n++) {
		do_hello_test_libsoup (n, FALSE, uri);
		do_hello_test_libsoup (n, TRUE, uri);
	}
}

#define MD5_TEST_FILE (g_test_get_filename (G_TEST_DIST, "index.txt", NULL))
#define MD5_TEST_FILE_BASENAME "index.txt"
#define MD5_TEST_FILE_MIME_TYPE "text/plain"

static char *
get_md5_data (char **contents, gsize *length)
{
	char *my_contents, *md5;
	gsize my_length;
	GError *error = NULL;

	if (!g_file_get_contents (MD5_TEST_FILE, &my_contents, &my_length, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return NULL;
	}

	md5 = g_compute_checksum_for_string (G_CHECKSUM_MD5, my_contents, my_length);

	if (contents)
		*contents = my_contents;
	else
		g_free (my_contents);
	if (length)
		*length = my_length;

	return md5;
}

static void
do_md5_test_curl (gconstpointer data)
{
	const char *uri = data;
	char *md5;
	GPtrArray *args;
	char *file_arg, *str_stdout;
	GError *error = NULL;

	if (!have_curl()) {
		g_test_skip ("curl is not available");
		return;
	}

	md5 = get_md5_data (NULL, NULL);
	if (!md5)
		return;

	args = g_ptr_array_new ();
	g_ptr_array_add (args, "curl");
	g_ptr_array_add (args, "--noproxy");
	g_ptr_array_add (args, "*");
	g_ptr_array_add (args, "-L");
	g_ptr_array_add (args, "-F");
	file_arg = g_strdup_printf ("file=@%s", MD5_TEST_FILE);
	g_ptr_array_add (args, file_arg);
	g_ptr_array_add (args, "-F");
	g_ptr_array_add (args, "fmt=txt");
	g_ptr_array_add (args, (char *)uri);
	g_ptr_array_add (args, NULL);

	if (g_spawn_sync (NULL, (char **)args->pdata, NULL,
			  G_SPAWN_SEARCH_PATH | G_SPAWN_STDERR_TO_DEV_NULL,
			  NULL, NULL,
			  &str_stdout, NULL, NULL, NULL)) {
		g_assert_cmpstr (str_stdout, ==, md5);
		g_free (str_stdout);
	} else {
		g_assert_no_error (error);
		g_error_free (error);
	}
	g_ptr_array_free (args, TRUE);
	g_free (file_arg);

	g_free (md5);
}

static void
do_md5_test_libsoup (gconstpointer data)
{
	const char *uri = data;
	char *contents, *md5;
	gsize length;
	SoupMultipart *multipart;
	GBytes *buffer;
	SoupMessage *msg;
	SoupSession *session;
	GBytes *body;

	g_test_bug ("601640");

	md5 = get_md5_data (&contents, &length);
	if (!md5)
		return;

	multipart = soup_multipart_new (SOUP_FORM_MIME_TYPE_MULTIPART);
	buffer = g_bytes_new (contents, length);
	soup_multipart_append_form_file (multipart, "file",
					 MD5_TEST_FILE_BASENAME,
					 MD5_TEST_FILE_MIME_TYPE,
					 buffer);
	g_bytes_unref (buffer);
	soup_multipart_append_form_string (multipart, "fmt", "text");

	msg = soup_message_new_from_multipart (uri, multipart);
	soup_multipart_free (multipart);

	session = soup_test_session_new (NULL);
	body = soup_session_send_and_read (session, msg, NULL, NULL);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_cmpmem (md5, strlen (md5), g_bytes_get_data (body, NULL), g_bytes_get_size (body));

	g_bytes_unref (body);
	g_object_unref (msg);
	soup_test_session_abort_unref (session);

	g_free (contents);
	g_free (md5);
}

static void
do_form_decode_test (void)
{
	GHashTable *table;
	const gchar *value;
	gchar *tmp;

	if (!have_curl()) {
		g_test_skip ("curl is not available");
		return;
	}

	/*  Test that the code handles multiple values with the same key.  */
	table = soup_form_decode ("foo=first&foo=second&foo=third");

	/*  Allocate some memory. We do this to test for a bug in
	 *  soup_form_decode() that resulted in values from the hash
	 *  table pointing to memory that is already released.
	 */
	tmp = g_strdup ("other");

	value = g_hash_table_lookup (table, "foo");
	g_assert_cmpstr (value, ==, "third");

	g_free (tmp);
	g_hash_table_destroy (table);
}

static void
hello_callback (SoupServer        *server,
		SoupServerMessage *msg,
		const char        *path,
		GHashTable        *query,
		gpointer           data)
{
	char *title, *name, *fmt;
	const char *content_type;
	GString *buf;
	const char *method;
	char *buf_str;
	gsize buf_len;

	method = soup_server_message_get_method (msg);
	if (method != SOUP_METHOD_GET && method != SOUP_METHOD_HEAD) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	if (query) {
		title = g_hash_table_lookup (query, "title");
		name = g_hash_table_lookup (query, "n@me");
		fmt = g_hash_table_lookup (query, "fmt");
	} else
		title = name = fmt = NULL;

	buf = g_string_new (NULL);
	if (!query || (fmt && !strcmp (fmt, "html"))) {
		content_type = "text/html";
		g_string_append (buf, "<html><head><title>forms-test: hello</title></head><body>\r\n");
		if (title && name) {
			/* mumble mumble html-escape... */
			g_string_append_printf (buf, "<p>Hello, <b><em>%s</em> %s</b></p>\r\n",
						title, name);
		}
		g_string_append (buf, "<form action='/hello' method='get'>"
				 "<p>Title: <input name='title'></p>"
				 "<p>Name: <input name='n@me'></p>"
				 "<p><input type=hidden name='fmt' value='html'></p>"
				 "<p><input type=submit></p>"
				 "</form>\r\n");
		g_string_append (buf, "</body></html>\r\n");
	} else {
		content_type = "text/plain";
		if (title && name) {
			char *uptitle = g_ascii_strup (title, -1);
			g_string_append_printf (buf, "Hello, %s %s",
						uptitle, name);
			g_free (uptitle);
		}
	}

	buf_len = buf->len;
	buf_str = g_string_free (g_steal_pointer (&buf), FALSE);
	soup_server_message_set_response (msg, content_type,
					  SOUP_MEMORY_TAKE,
					  g_steal_pointer (&buf_str), buf_len);
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
}

static void
md5_get_callback (SoupServer        *server,
		  SoupServerMessage *msg,
		  const char        *path,
		  GHashTable        *query,
		  gpointer           data)
{
	const char *file = NULL, *md5sum = NULL, *fmt;
	const char *content_type;
	GString *buf;
	char *buf_str;
	gsize buf_len;

	if (query) {
		file = g_hash_table_lookup (query, "file");
		md5sum = g_hash_table_lookup (query, "md5sum");
		fmt = g_hash_table_lookup (query, "fmt");
	} else
		fmt = "html";

	buf = g_string_new (NULL);
	if (!strcmp (fmt, "html")) {
		content_type = "text/html";
		g_string_append (buf, "<html><head><title>forms-test: md5</title></head><body>\r\n");
		if (file && md5sum) {
			/* mumble mumble html-escape... */
			g_string_append_printf (buf, "<p>File: %s<br>MD5: <b>%s</b></p>\r\n",
						file, md5sum);
		}
		g_string_append (buf, "<form action='/md5' method='post' enctype='multipart/form-data'>"
				 "<p>File: <input type='file' name='file'></p>"
				 "<p><input type=hidden name='fmt' value='html'></p>"
				 "<p><input type=submit></p>"
				 "</form>\r\n");
		g_string_append (buf, "</body></html>\r\n");
	} else {
		content_type = "text/plain";
		if (md5sum)
			g_string_append_printf (buf, "%s", md5sum);
	}

	buf_len = buf->len;
	buf_str = g_string_free (g_steal_pointer (&buf), FALSE);
	soup_server_message_set_response (msg, content_type,
					  SOUP_MEMORY_TAKE,
					  g_steal_pointer (&buf_str), buf_len);
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
}

static void
md5_post_callback (SoupServer        *server,
		   SoupServerMessage *msg,
		   const char        *path,
		   GHashTable        *query,
		   gpointer           data)
{
	const char *content_type;
	GHashTable *params;
	const char *fmt;
	char *filename, *md5sum, *redirect_uri;
	GBytes *file;
	GUri *uri;
	char *encoded_form;
	SoupMultipart *multipart;
	GBytes *body;
	SoupMessageHeaders *request_headers;

	request_headers = soup_server_message_get_request_headers (msg);
	content_type = soup_message_headers_get_content_type (request_headers, NULL);
	if (!content_type || strcmp (content_type, "multipart/form-data") != 0) {
		soup_server_message_set_status (msg, SOUP_STATUS_BAD_REQUEST, NULL);
		return;
	}

	body = soup_message_body_flatten (soup_server_message_get_request_body (msg));
	multipart = soup_multipart_new_from_message (request_headers, body);
	g_bytes_unref (body);
	params = multipart ? soup_form_decode_multipart (multipart, "file", &filename, NULL, &file) : NULL;
	if (!params) {
		soup_server_message_set_status (msg, SOUP_STATUS_BAD_REQUEST, NULL);
		return;
	}
	fmt = g_hash_table_lookup (params, "fmt");

	md5sum = g_compute_checksum_for_bytes (G_CHECKSUM_MD5, file);
	g_bytes_unref (file);

	encoded_form = soup_form_encode ("file", filename ? filename : "",
					 "md5sum", md5sum,
					 "fmt", fmt ? fmt : "html",
					 NULL);
	uri = soup_uri_copy (soup_server_message_get_uri (msg),
			     SOUP_URI_QUERY, encoded_form,
			     SOUP_URI_NONE);
	g_free (encoded_form);
	redirect_uri = g_uri_to_string (uri);

	soup_server_message_set_redirect (msg, SOUP_STATUS_SEE_OTHER, redirect_uri);

	g_free (redirect_uri);
	g_uri_unref (uri);
	g_free (md5sum);
	g_free (filename);
	g_hash_table_destroy (params);
}

static void
md5_callback (SoupServer        *server,
	      SoupServerMessage *msg,
	      const char        *path,
	      GHashTable        *query,
	      gpointer           data)
{
	const char *method;

	method = soup_server_message_get_method (msg);

	if (method == SOUP_METHOD_GET || method == SOUP_METHOD_HEAD)
		md5_get_callback (server, msg, path, query, data);
	else if (method == SOUP_METHOD_POST)
		md5_post_callback (server, msg, path, query, data);
	else
		soup_server_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED, NULL);
}

static void
do_form_decode_multipart_test (void)
{
	SoupMultipart *multipart = soup_multipart_new ("multipart/form-data");
	const char *file_control_name = "uploaded_file";
	char *content_type = NULL;
	char *filename = NULL;
	GBytes *file = NULL;
	GHashTable *result;
	int part;

	for (part = 0; part < 2; part++) {
		SoupMessageHeaders *headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
		GHashTable *params = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
		GBytes *body = g_bytes_new (NULL, 0);

		g_hash_table_insert (params, g_strdup ("name"), g_strdup (file_control_name));
		g_hash_table_insert (params, g_strdup ("filename"), g_strdup (file_control_name));
		soup_message_headers_set_content_disposition (headers, "form-data", params);
		soup_message_headers_set_content_type (headers, "text/x-form", NULL);
		soup_multipart_append_part (multipart, headers, body);

		soup_message_headers_unref (headers);
		g_hash_table_destroy (params);
		g_bytes_unref (body);
	}

	/* this would leak memory of the output variables, due to two parts having the same 'file_control_name' */
	result = soup_form_decode_multipart (multipart, file_control_name, &filename, &content_type, &file);
	g_assert_nonnull (result);
	g_assert_cmpstr (content_type, ==, "text/x-form");
	g_assert_cmpstr (filename, ==, file_control_name);
	g_assert_nonnull (file);

	g_hash_table_destroy (result);
	g_free (content_type);
	g_free (filename);
	g_bytes_unref (file);
}

static gboolean run_tests = TRUE;

static GOptionEntry no_test_entry[] = {
        { "no-tests", 'n', G_OPTION_FLAG_REVERSE,
          G_OPTION_ARG_NONE, &run_tests,
          "Don't run tests, just run the test server", NULL },
        { NULL }
};

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server;
	GUri *base_uri, *uri;
	int ret = 0;

	test_init (argc, argv, no_test_entry);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, "/hello",
				 hello_callback, NULL, NULL);
	soup_server_add_handler (server, "/md5",
				 md5_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	loop = g_main_loop_new (NULL, TRUE);

	if (run_tests) {
		uri = g_uri_parse_relative (base_uri, "/hello", SOUP_HTTP_URI_FLAGS, NULL);
		g_test_add_data_func_full ("/forms/hello/curl", g_uri_to_string (uri), do_hello_tests_curl, g_free);
		g_test_add_data_func_full ("/forms/hello/libsoup", g_uri_to_string (uri), do_hello_tests_libsoup, g_free);
		g_uri_unref (uri);

		uri = g_uri_parse_relative (base_uri, "/md5", SOUP_HTTP_URI_FLAGS, NULL);
		g_test_add_data_func_full ("/forms/md5/curl", g_uri_to_string (uri), do_md5_test_curl, g_free);
		g_test_add_data_func_full ("/forms/md5/libsoup", g_uri_to_string (uri), do_md5_test_libsoup, g_free);
		g_uri_unref (uri);

		g_test_add_func ("/forms/decode", do_form_decode_test);
		g_test_add_func ("/forms/decodemultipart", do_form_decode_multipart_test);

		ret = g_test_run ();
	} else {
		g_print ("Listening on port %d\n", g_uri_get_port (base_uri));
		g_main_loop_run (loop);
	}

	g_main_loop_unref (loop);

	soup_test_server_quit_unref (server);
	g_uri_unref (base_uri);

	if (run_tests)
		test_cleanup ();
	return ret;
}
