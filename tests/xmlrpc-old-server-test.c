/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include "test-utils.h"

static char *uri;

#ifdef G_GNUC_BEGIN_IGNORE_DEPRECATIONS
G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#endif

static void
type_error (SoupMessage *msg, GType expected, GValueArray *params, int bad_value)
{
	soup_xmlrpc_set_fault (msg,
			       SOUP_XMLRPC_FAULT_SERVER_ERROR_INVALID_METHOD_PARAMETERS,
			       "Bad parameter #%d: expected %s, got %s",
			       bad_value + 1, g_type_name (expected),
			       g_type_name (G_VALUE_TYPE (&params->values[bad_value])));
}

static void
args_error (SoupMessage *msg, GValueArray *params, int expected)
{
	soup_xmlrpc_set_fault (msg,
			       SOUP_XMLRPC_FAULT_SERVER_ERROR_INVALID_METHOD_PARAMETERS,
			       "Wrong number of parameters: expected %d, got %d",
			       expected, params->n_values);
}

static void
do_sum (SoupMessage *msg, GValueArray *params)
{
	int i;
	double sum = 0.0, val;
	GValueArray *nums;

	if (params->n_values != 1) {
		args_error (msg, params, 1);
		return;
	}
	if (!soup_value_array_get_nth (params, 0, G_TYPE_VALUE_ARRAY, &nums)) {
		type_error (msg, G_TYPE_VALUE_ARRAY, params, 0);
		return;
	}

	for (i = 0; i < nums->n_values; i++) {
		if (!soup_value_array_get_nth (nums, i, G_TYPE_DOUBLE, &val)) {
			type_error (msg, G_TYPE_DOUBLE, nums, i);
			return;
		}
		sum += val;
	}

	soup_xmlrpc_set_response (msg, G_TYPE_DOUBLE, sum);

}

static void
do_countBools (SoupMessage *msg, GValueArray *params)
{
	int i, trues = 0, falses = 0;
	GValueArray *bools;
	GHashTable *ret = soup_value_hash_new ();
	gboolean val;

	if (params->n_values != 1) {
		args_error (msg, params, 1);
		return;
	}
	if (!soup_value_array_get_nth (params, 0, G_TYPE_VALUE_ARRAY, &bools)) {
		type_error (msg, G_TYPE_VALUE_ARRAY, params, 0);
		return;
	}

	for (i = 0; i < bools->n_values; i++) {
		if (!soup_value_array_get_nth (bools, i, G_TYPE_BOOLEAN, &val)) {
			type_error (msg, G_TYPE_BOOLEAN, params, i);
			return;
		}
		if (val)
			trues++;
		else
			falses++;
	}

	soup_value_hash_insert (ret, "true", G_TYPE_INT, trues);
	soup_value_hash_insert (ret, "false", G_TYPE_INT, falses);
	soup_xmlrpc_set_response (msg, G_TYPE_HASH_TABLE, ret);
	g_hash_table_destroy (ret);

}

static void
do_md5sum (SoupMessage *msg, GValueArray *params)
{
	GChecksum *checksum;
	GByteArray *data, *digest;
	gsize digest_len = 16;

	if (params->n_values != 1) {
		args_error (msg, params, 1);
		return;
	}

	if (!soup_value_array_get_nth (params, 0, SOUP_TYPE_BYTE_ARRAY, &data)) {
		type_error (msg, SOUP_TYPE_BYTE_ARRAY, params, 0);
		return;
	}
	checksum = g_checksum_new (G_CHECKSUM_MD5);
	g_checksum_update (checksum, data->data, data->len);
	digest = g_byte_array_new ();
	g_byte_array_set_size (digest, digest_len);
	g_checksum_get_digest (checksum, digest->data, &digest_len);
	g_checksum_free (checksum);

	soup_xmlrpc_set_response (msg, SOUP_TYPE_BYTE_ARRAY, digest);
	g_byte_array_free (digest, TRUE);
}


static void
do_dateChange (SoupMessage *msg, GValueArray *params)
{
	GHashTable *arg;
	SoupDate *date;
	int val;

	if (params->n_values != 2) {
		args_error (msg, params, 2);
		return;
	}

	if (!soup_value_array_get_nth (params, 0, SOUP_TYPE_DATE, &date)) {
		type_error (msg, SOUP_TYPE_DATE, params, 0);
		return;
	}
	if (!soup_value_array_get_nth (params, 1, G_TYPE_HASH_TABLE, &arg)) {
		type_error (msg, G_TYPE_HASH_TABLE, params, 1);
		return;
	}

	if (soup_value_hash_lookup (arg, "tm_year", G_TYPE_INT, &val))
		date->year = val + 1900;
	if (soup_value_hash_lookup (arg, "tm_mon", G_TYPE_INT, &val))
		date->month = val + 1;
	if (soup_value_hash_lookup (arg, "tm_mday", G_TYPE_INT, &val))
		date->day = val;
	if (soup_value_hash_lookup (arg, "tm_hour", G_TYPE_INT, &val))
		date->hour = val;
	if (soup_value_hash_lookup (arg, "tm_min", G_TYPE_INT, &val))
		date->minute = val;
	if (soup_value_hash_lookup (arg, "tm_sec", G_TYPE_INT, &val))
		date->second = val;

	soup_xmlrpc_set_response (msg, SOUP_TYPE_DATE, date);
}

static void
do_echo (SoupMessage *msg, GValueArray *params)
{
	int i;
	const char *val;
	GValueArray *in, *out;

	if (!soup_value_array_get_nth (params, 0, G_TYPE_VALUE_ARRAY, &in)) {
		type_error (msg, G_TYPE_VALUE_ARRAY, params, 0);
		return;
	}

	out = g_value_array_new (in->n_values);
	for (i = 0; i < in->n_values; i++) {
		if (!soup_value_array_get_nth (in, i, G_TYPE_STRING, &val)) {
			type_error (msg, G_TYPE_STRING, in, i);
			return;
		}
		soup_value_array_append (out, G_TYPE_STRING, val);
	}

	soup_xmlrpc_set_response (msg, G_TYPE_VALUE_ARRAY, out);
	g_value_array_free (out);
}

static void
do_ping (SoupMessage *msg, GValueArray *params)
{
	if (params->n_values) {
		args_error (msg, params, 0);
		return;
	}

	soup_xmlrpc_set_response (msg, G_TYPE_STRING, "pong");
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	char *method_name;
	GValueArray *params;

	if (msg->method != SOUP_METHOD_POST) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);

	if (!soup_xmlrpc_parse_method_call (msg->request_body->data,
					    msg->request_body->length,
					    &method_name, &params)) {
		soup_xmlrpc_set_fault (msg, SOUP_XMLRPC_FAULT_PARSE_ERROR_NOT_WELL_FORMED,
				       "Could not parse method call");
		return;
	}

	if (!strcmp (method_name, "sum"))
		do_sum (msg, params);
	else if (!strcmp (method_name, "countBools"))
		do_countBools (msg, params);
	else if (!strcmp (method_name, "md5sum"))
		do_md5sum (msg, params);
	else if (!strcmp (method_name, "dateChange"))
		do_dateChange (msg, params);
	else if (!strcmp (method_name, "echo"))
		do_echo (msg, params);
	else if (!strcmp (method_name, "ping"))
		do_ping (msg, params);
	else {
		soup_xmlrpc_set_fault (msg, SOUP_XMLRPC_FAULT_SERVER_ERROR_REQUESTED_METHOD_NOT_FOUND,
				       "Unknown method %s", method_name);
	}

	g_free (method_name);
	g_value_array_free (params);
}

static gboolean
run_xmlrpc_test (char **argv,
		 char **stdout_out,
		 char **stderr_out,
		 GError **error)
{
	gboolean ok;
	int status;

	argv[0] = g_test_build_filename (G_TEST_BUILT, "xmlrpc-old-test", NULL);
	ok = g_spawn_sync (NULL, argv, NULL, 0, NULL, NULL,
			   stdout_out, stderr_out, &status,
			   error);
	g_free (argv[0]);

	if (!ok)
		return FALSE;

	return g_spawn_check_exit_status (status, error);
}

static void
do_one_xmlrpc_test (gconstpointer data)
{
	const char *path = data;
	char *argv[12];
	char *stdout_out, *stderr_out;
	GError *error = NULL;
	int arg;

	argv[0] = NULL;
	argv[1] = "-S";
	argv[2] = "-U";
	argv[3] = uri;
	argv[4] = "-q";
	argv[5] = "-p";
	argv[6] = (char *) path;

	for (arg = 0; arg < debug_level && arg < 3; arg++)
		argv[arg + 7] = "-d";
	argv[arg + 7] = NULL;

	run_xmlrpc_test (argv, &stdout_out, &stderr_out, &error);
	if (stdout_out) {
		g_print ("%s", stdout_out);
		g_free (stdout_out);
	}
	if (stderr_out) {
		g_printerr ("%s", stderr_out);
		g_free (stderr_out);
	}

	if (   g_error_matches (error, G_SPAWN_EXIT_ERROR, 1)
	    || g_error_matches (error, G_SPAWN_EXIT_ERROR, 77))
		g_test_fail ();
	else
		g_assert_no_error (error);
	g_clear_error (&error);
}

gboolean run_tests = TRUE;

static GOptionEntry no_test_entry[] = {
        { "no-tests", 'n', G_OPTION_FLAG_REVERSE,
          G_OPTION_ARG_NONE, &run_tests,
          "Don't run tests, just run the test server", NULL },
        { NULL }
};

int
main (int argc, char **argv)
{
	SoupServer *server;
	SoupURI *server_uri;
	int ret;

	test_init (argc, argv, no_test_entry);

	server = soup_test_server_new (run_tests ? SOUP_TEST_SERVER_IN_THREAD : SOUP_TEST_SERVER_DEFAULT);
	soup_server_add_handler (server, "/xmlrpc-server.php",
				 server_callback, NULL, NULL);
	server_uri = soup_test_server_get_uri (server, "http", NULL);
	soup_uri_set_path (server_uri, "/xmlrpc-server.php");
	uri = soup_uri_to_string (server_uri, FALSE);

	if (run_tests) {
		char *out, **tests, *path;
		char *list_argv[4];
		GError *error = NULL;
		int i;

		list_argv[0] = NULL;
		list_argv[1] = "-S";
		list_argv[2] = "-l";
		list_argv[3] = NULL;

		if (!run_xmlrpc_test (list_argv, &out, NULL, &error)) {
			g_printerr ("'xmlrpc-old-test -l' failed: %s\n", error->message);
			g_error_free (error);
			return 1;
		}

		tests = g_strsplit (out, "\n", -1);
		g_free (out);

		for (i = 0; tests[i] && *tests[i]; i++) {
			/* GLib >= 2.62 defaults to TAP output for tests, and
			 * this adds TAP diagnostics "#..." and the test count
			 * "1..N", even in the output of "some-test -l".
			 * Ignore those. */
			if (tests[i][0] == '#' || g_str_has_prefix (tests[i], "1.."))
				continue;

			g_assert_true (g_str_has_prefix (tests[i], "/xmlrpc-old/"));
			path = g_strdup_printf ("/xmlrpc-old-server/%s", tests[i] + strlen ("/xmlrpc-old/"));
			g_test_add_data_func (path, tests[i], do_one_xmlrpc_test);
			g_free (path);
		}

		ret = g_test_run ();

		g_strfreev (tests);
	} else {
		GMainLoop *loop;

		g_print ("Listening on port %d\n", server_uri->port);

		loop = g_main_loop_new (NULL, TRUE);
		g_main_loop_run (loop);
		g_main_loop_unref (loop);

		ret = 0;
	}

	soup_test_server_quit_unref (server);
	soup_uri_free (server_uri);
	g_free (uri);
	if (run_tests)
		test_cleanup ();
	return ret;
}
