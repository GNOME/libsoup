/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2008 Red Hat, Inc.
 * Copyright 2015, Collabora ltd.
 */

#include "test-utils.h"

static char *uri;

static GVariant *
parse_params (SoupMessage *msg, SoupXMLRPCParams *params, const char *signature)
{
	GVariant *args;
	GError *error = NULL;

	args = soup_xmlrpc_params_parse (params, signature, &error);
	if (!args) {
		soup_xmlrpc_message_set_fault (msg,
					       SOUP_XMLRPC_FAULT_SERVER_ERROR_INVALID_METHOD_PARAMETERS,
					       "Wrong method signature: expected %s: %s",
					       signature, error->message);
	}

	return args;
}

static void
do_sum (SoupMessage *msg, SoupXMLRPCParams *params)
{
	GVariant *args;
	GVariant *child;
	GVariantIter iter;
	double sum = 0.0, val;

	if (!(args = parse_params (msg, params, "(ad)")))
		return;

	child = g_variant_get_child_value (args, 0);

	g_variant_iter_init (&iter, child);
	while (g_variant_iter_loop (&iter, "d", &val))
		sum += val;

	soup_xmlrpc_message_set_response (msg, g_variant_new_double (sum), NULL);

	g_variant_unref (args);
	g_variant_unref (child);
}

static void
do_countBools (SoupMessage *msg, SoupXMLRPCParams *params)
{
	GVariant *args;
	GVariant *child;
	GVariantIter iter;
	gboolean val;
	int trues = 0, falses = 0;
	GVariantDict dict;

	if (!(args = parse_params (msg, params, "(ab)")))
		return;

	child = g_variant_get_child_value (args, 0);

	g_variant_iter_init (&iter, child);
	while (g_variant_iter_loop (&iter, "b", &val)) {
		if (val)
			trues++;
		else
			falses++;
	}

	g_variant_dict_init (&dict, NULL);
	g_variant_dict_insert (&dict, "true", "i", trues);
	g_variant_dict_insert (&dict, "false", "i", falses);

	soup_xmlrpc_message_set_response (msg, g_variant_dict_end (&dict), NULL);

	g_variant_unref (args);
	g_variant_unref (child);
}

static void
do_md5sum (SoupMessage *msg, SoupXMLRPCParams *params)
{
	GVariant *args;
	GVariant *child;
	GChecksum *checksum;
	GByteArray *digest;
	gsize digest_len = 16;

	if (!(args = parse_params (msg, params, "(ay)")))
		return;

	child = g_variant_get_child_value (args, 0);

	checksum = g_checksum_new (G_CHECKSUM_MD5);
	g_checksum_update (checksum,
			   g_variant_get_data (child),
			   g_variant_get_size (child));
	digest = g_byte_array_new ();
	g_byte_array_set_size (digest, digest_len);
	g_checksum_get_digest (checksum, digest->data, &digest_len);
	g_checksum_free (checksum);

	soup_xmlrpc_message_set_response (msg,
					  g_variant_new_from_data (G_VARIANT_TYPE_BYTESTRING,
								   digest->data, digest_len,
								   TRUE, NULL, NULL),
					  NULL);
	g_byte_array_free (digest, TRUE);
	g_variant_unref (child);
	g_variant_unref (args);
}


static void
do_dateChange (SoupMessage *msg, SoupXMLRPCParams *params)
{
	GVariant *args;
	GVariant *timestamp;
	SoupDate *date;
	GVariant *arg;
	int val;
	GError *error = NULL;

	if (!(args = parse_params (msg, params, "(va{si})")))
		return;

	g_variant_get (args, "(v@a{si})", &timestamp, &arg);

	date = soup_xmlrpc_variant_get_datetime (timestamp, &error);
	if (!date) {
		soup_xmlrpc_message_set_fault (msg,
					       SOUP_XMLRPC_FAULT_SERVER_ERROR_INVALID_METHOD_PARAMETERS,
					       "%s", error->message);
		g_clear_error (&error);
		goto fail;
	}

	if (g_variant_lookup (arg, "tm_year", "i", &val))
		date->year = val + 1900;
	if (g_variant_lookup (arg, "tm_mon", "i", &val))
		date->month = val + 1;
	if (g_variant_lookup (arg, "tm_mday", "i", &val))
		date->day = val;
	if (g_variant_lookup (arg, "tm_hour", "i", &val))
		date->hour = val;
	if (g_variant_lookup (arg, "tm_min", "i", &val))
		date->minute = val;
	if (g_variant_lookup (arg, "tm_sec", "i", &val))
		date->second = val;

	soup_xmlrpc_message_set_response (msg,
					  soup_xmlrpc_variant_new_datetime (date),
					  NULL);

	soup_date_free (date);

fail:
	g_variant_unref (args);
	g_variant_unref (arg);
	g_variant_unref (timestamp);
}

static void
do_echo (SoupMessage *msg, SoupXMLRPCParams *params)
{
	GVariant *args;
	GVariant *child;

	if (!(args = parse_params (msg, params, "(as)")))
		return;

	child = g_variant_get_child_value (args, 0);
	soup_xmlrpc_message_set_response (msg, child, NULL);
	g_variant_unref (args);
	g_variant_unref (child);
}

static void
do_ping (SoupMessage *msg, SoupXMLRPCParams *params)
{
	GVariant *args;

	if (!(args = parse_params (msg, params, "()")))
		return;

	soup_xmlrpc_message_set_response (msg, g_variant_new_string ("pong"), NULL);
	g_variant_unref (args);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	char *method_name;
	SoupXMLRPCParams *params;
	GError *error = NULL;

	if (msg->method != SOUP_METHOD_POST) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);

	method_name = soup_xmlrpc_parse_request (msg->request_body->data,
						 msg->request_body->length,
						 &params, &error);
	if (!method_name) {
		soup_xmlrpc_message_set_fault (msg, SOUP_XMLRPC_FAULT_PARSE_ERROR_NOT_WELL_FORMED,
				       "Could not parse method call: %s", error->message);
		g_clear_error (&error);
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
		soup_xmlrpc_message_set_fault (msg, SOUP_XMLRPC_FAULT_SERVER_ERROR_REQUESTED_METHOD_NOT_FOUND,
				       "Unknown method %s", method_name);
	}

	g_free (method_name);
	soup_xmlrpc_params_free (params);
}

static gboolean
run_xmlrpc_test (char **argv,
		 char **stdout_out,
		 char **stderr_out,
		 GError **error)
{
	gboolean ok;
	int status;

	argv[0] = g_test_build_filename (G_TEST_BUILT, "xmlrpc-test", NULL);
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
			g_printerr ("'xmlrpc-test -l' failed: %s\n", error->message);
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

			g_assert_true (g_str_has_prefix (tests[i], "/xmlrpc/"));
			path = g_strdup_printf ("/xmlrpc-server/%s", tests[i] + strlen ("/xmlrpc/"));
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
