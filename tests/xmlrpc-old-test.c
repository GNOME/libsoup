/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include "test-utils.h"

#ifdef G_GNUC_BEGIN_IGNORE_DEPRECATIONS
G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#endif

static SoupSession *session;
static const char *default_uri = "http://127.0.0.1:47524/xmlrpc-server.php";
static const char *uri = NULL;
static gboolean server_test = FALSE;

#ifdef HAVE_PHP_XMLRPC
#define SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER
#else
#define SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER				\
	G_STMT_START {							\
		if (!server_test) {					\
			g_test_skip ("php-xmlrpc is not available");	\
			return;						\
		}							\
	} G_STMT_END
#endif

static gboolean
send_xmlrpc (const char *body, GValue *retval)
{
	SoupMessage *msg;
	GError *err = NULL;

	msg = soup_message_new ("POST", uri);
	soup_message_set_request (msg, "text/xml", SOUP_MEMORY_COPY,
				  body, strlen (body));
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	if (!soup_xmlrpc_parse_method_response (msg->response_body->data,
						msg->response_body->length,
						retval, &err)) {
		if (err) {
			soup_test_assert (FALSE, "FAULT: %d %s\n", err->code, err->message);
			g_error_free (err);
		} else
			soup_test_assert (FALSE, "ERROR: could not parse response\n");
		g_object_unref (msg);
		return FALSE;
	}
	g_object_unref (msg);

	return TRUE;
}

static gboolean
do_xmlrpc (const char *method, GValue *retval, ...)
{
	va_list args;
	GValueArray *params;
	char *body;
	gboolean ret;

	va_start (args, retval);
	params = soup_value_array_from_args (args);
	va_end (args);

	body = soup_xmlrpc_build_method_call (method, params->values,
					      params->n_values);
	g_value_array_free (params);
	if (!body)
		return FALSE;

	ret = send_xmlrpc (body, retval);
	g_free (body);

	return ret;
}

static gboolean
check_xmlrpc (GValue *value, GType type, ...)
{
	va_list args;

	if (!G_VALUE_HOLDS (value, type)) {
		g_assert_true (G_VALUE_HOLDS (value, type));
		return FALSE;
	}

	va_start (args, type);
	SOUP_VALUE_GETV (value, type, args);
	va_end (args);
	return TRUE;
}

static void
test_sum (void)
{
	GValueArray *dbls;
	int i;
	double val, sum, result;
	GValue retval;
	gboolean ok;

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "sum (array of double -> double): ");

	dbls = g_value_array_new (10);
	for (i = sum = 0; i < 10; i++) {
		val = g_random_int_range (0, 400) / 4.0;
		debug_printf (2, "%s%.2f", i == 0 ? "[" : ", ", val);
		soup_value_array_append (dbls, G_TYPE_DOUBLE, val);
		sum += val;
	}
	debug_printf (2, "] -> ");

	ok = (do_xmlrpc ("sum", &retval,
			G_TYPE_VALUE_ARRAY, dbls,
			G_TYPE_INVALID) &&
	      check_xmlrpc (&retval, G_TYPE_DOUBLE, &result));
	g_value_array_free (dbls);

	if (!ok)
		return;

	debug_printf (2, "%.2f\n", result);
	g_assert_cmpfloat (result, ==, sum);
}

static void
test_countBools (void)
{
	GValueArray *bools;
	int i, trues, falses;
	GValue retval;
	int ret_trues, ret_falses;
	gboolean val, ok;
	GHashTable *result;

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "countBools (array of boolean -> struct of ints): ");

	bools = g_value_array_new (10);
	for (i = trues = falses = 0; i < 10; i++) {
		val = g_random_boolean ();
		debug_printf (2, "%s%c", i == 0 ? "[" : ", ", val ? 'T' : 'F');
		soup_value_array_append (bools, G_TYPE_BOOLEAN, val);
		if (val)
			trues++;
		else
			falses++;
	}
	debug_printf (2, "] -> ");

	ok = (do_xmlrpc ("countBools", &retval,
			 G_TYPE_VALUE_ARRAY, bools,
			 G_TYPE_INVALID) &&
	      check_xmlrpc (&retval, G_TYPE_HASH_TABLE, &result));
	g_value_array_free (bools);
	if (!ok)
		return;

	g_assert_true (soup_value_hash_lookup (result, "true", G_TYPE_INT, &ret_trues));
	g_assert_true (soup_value_hash_lookup (result, "false", G_TYPE_INT, &ret_falses));

	g_hash_table_destroy (result);

	debug_printf (2, "{ true: %d, false: %d }\n", ret_trues, ret_falses);
	g_assert_cmpint (trues, ==, ret_trues);
	g_assert_cmpint (falses, ==, ret_falses);
}

static void
test_md5sum (void)
{
	GByteArray *data, *result;
	int i;
	GChecksum *checksum;
	guchar digest[16];
	gsize digest_len = sizeof (digest);
	GValue retval;
	gboolean ok;

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "md5sum (base64 -> base64)\n");

	data = g_byte_array_new ();
	g_byte_array_set_size (data, 256);
	for (i = 0; i < data->len; i++)
		data->data[i] = (char)(g_random_int_range (0, 256));

	checksum = g_checksum_new (G_CHECKSUM_MD5);
	g_checksum_update (checksum, data->data, data->len);
	g_checksum_get_digest (checksum, digest, &digest_len);
	g_checksum_free (checksum);

	ok = (do_xmlrpc ("md5sum", &retval,
			 SOUP_TYPE_BYTE_ARRAY, data,
			 G_TYPE_INVALID) &&
	      check_xmlrpc (&retval, SOUP_TYPE_BYTE_ARRAY, &result));
	g_byte_array_free (data, TRUE);
	if (!ok)
		return;

	soup_assert_cmpmem (result->data, result->len,
			    digest, digest_len);
	g_byte_array_free (result, TRUE);
}

static void
test_dateChange (void)
{
	GHashTable *structval;
	SoupDate *date, *result;
	char *timestamp;
	GValue retval;
	gboolean ok;

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "dateChange (date, struct of ints -> time)\n");

	date = soup_date_new (1970 + (g_random_int_range (0, 50)),
			      1 + g_random_int_range (0, 12),
			      1 + g_random_int_range (0, 28),
			      g_random_int_range (0, 24),
			      g_random_int_range (0, 60),
			      g_random_int_range (0, 60));
	if (debug_level >= 2) {
		timestamp = soup_date_to_string (date, SOUP_DATE_ISO8601_XMLRPC);
		debug_printf (2, "date: %s, {", timestamp);
		g_free (timestamp);
	}

	structval = soup_value_hash_new ();

#define MAYBE (g_random_int_range (0, 3) != 0)

	if (MAYBE) {
		date->year = 1970 + (g_random_int_range (0, 50));
		debug_printf (2, "tm_year: %d, ", date->year - 1900);
		soup_value_hash_insert (structval, "tm_year",
					G_TYPE_INT, date->year - 1900);
	}
	if (MAYBE) {
		date->month = 1 + g_random_int_range (0, 12);
		debug_printf (2, "tm_mon: %d, ", date->month - 1);
		soup_value_hash_insert (structval, "tm_mon",
					G_TYPE_INT, date->month - 1);
	}
	if (MAYBE) {
		date->day = 1 + g_random_int_range (0, 28);
		debug_printf (2, "tm_mday: %d, ", date->day);
		soup_value_hash_insert (structval, "tm_mday",
					G_TYPE_INT, date->day);
	}
	if (MAYBE) {
		date->hour = g_random_int_range (0, 24);
		debug_printf (2, "tm_hour: %d, ", date->hour);
		soup_value_hash_insert (structval, "tm_hour",
					G_TYPE_INT, date->hour);
	}
	if (MAYBE) {
		date->minute = g_random_int_range (0, 60);
		debug_printf (2, "tm_min: %d, ", date->minute);
		soup_value_hash_insert (structval, "tm_min",
					G_TYPE_INT, date->minute);
	}
	if (MAYBE) {
		date->second = g_random_int_range (0, 60);
		debug_printf (2, "tm_sec: %d, ", date->second);
		soup_value_hash_insert (structval, "tm_sec",
					G_TYPE_INT, date->second);
	}

	debug_printf (2, "} -> ");

	ok = (do_xmlrpc ("dateChange", &retval,
			 SOUP_TYPE_DATE, date,
			 G_TYPE_HASH_TABLE, structval,
			 G_TYPE_INVALID) &&
	      check_xmlrpc (&retval, SOUP_TYPE_DATE, &result));
	g_hash_table_destroy (structval);
	if (!ok) {
		soup_date_free (date);
		return;
	}

	if (debug_level >= 2) {
		timestamp = soup_date_to_string (result, SOUP_DATE_ISO8601_XMLRPC);
		debug_printf (2, "%s\n", timestamp);
		g_free (timestamp);
	}

	g_assert_cmpint (date->year,   ==, result->year);
	g_assert_cmpint (date->month,  ==, result->month);
	g_assert_cmpint (date->day,    ==, result->day);
	g_assert_cmpint (date->hour,   ==, result->hour);
	g_assert_cmpint (date->minute, ==, result->minute);
	g_assert_cmpint (date->second, ==, result->second);

	soup_date_free (date);
	soup_date_free (result);
}

static const char *const echo_strings[] = {
	"This is a test",
	"& so is this",
	"and so is <this>",
	"&amp; so is &lt;this&gt;"
};
#define N_ECHO_STRINGS G_N_ELEMENTS (echo_strings)

static void
test_echo (void)
{
	GValueArray *originals, *echoes;
	GValue retval;
	int i;

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "echo (array of string -> array of string):\n");

	originals = g_value_array_new (N_ECHO_STRINGS);
	for (i = 0; i < N_ECHO_STRINGS; i++) {
		soup_value_array_append (originals, G_TYPE_STRING, echo_strings[i]);
		debug_printf (2, "%s\"%s\"", i == 0 ? "[" : ", ", echo_strings[i]);
	}
	debug_printf (2, "] -> ");

	if (!(do_xmlrpc ("echo", &retval,
			 G_TYPE_VALUE_ARRAY, originals,
			 G_TYPE_INVALID) &&
	      check_xmlrpc (&retval, G_TYPE_VALUE_ARRAY, &echoes))) {
		g_value_array_free (originals);
		return;
	}
	g_value_array_free (originals);

	if (debug_level >= 2) {
		for (i = 0; i < echoes->n_values; i++) {
			debug_printf (2, "%s\"%s\"", i == 0 ? "[" : ", ",
				      g_value_get_string (&echoes->values[i]));
		}
		debug_printf (2, "]\n");
	}

	g_assert_cmpint (echoes->n_values, ==, N_ECHO_STRINGS);

	for (i = 0; i < echoes->n_values; i++)
		g_assert_cmpstr (echo_strings[i], ==, g_value_get_string (&echoes->values[i]));

	g_value_array_free (echoes);
}

static void
test_ping (gconstpointer include_params)
{
	GValueArray *params;
	GValue retval;
	char *request;
	char *out;
	gboolean ret;

	g_test_bug ("671661");

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "ping (void (%s) -> string)\n",
		      include_params ? "empty <params>" : "no <params>");

	params = soup_value_array_new ();
	request = soup_xmlrpc_build_method_call ("ping", params->values,
						 params->n_values);
	g_value_array_free (params);
	if (!request)
		return;

	if (!include_params) {
		char *params, *end;

		params = strstr (request, "<params/>");
		if (!params) {
			soup_test_assert (FALSE, "ERROR: XML did not contain <params/>!");
			return;
		}
		end = params + strlen ("<params/>");
		memmove (params, end, strlen (end) + 1);
	}

	ret = send_xmlrpc (request, &retval);
	g_free (request);

	if (!ret || !check_xmlrpc (&retval, G_TYPE_STRING, &out))
		return;

	g_assert_cmpstr (out, ==, "pong");

	g_free (out);
}

static void
do_bad_xmlrpc (const char *body)
{
	SoupMessage *msg;
	GError *err = NULL;
	GValue retval;

	msg = soup_message_new ("POST", uri);
	soup_message_set_request (msg, "text/xml", SOUP_MEMORY_COPY,
				  body, strlen (body));
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	if (!soup_xmlrpc_parse_method_response (msg->response_body->data,
						msg->response_body->length,
						&retval, &err)) {
		if (err) {
			debug_printf (1, "FAULT: %d %s (OK!)\n",
				      err->code, err->message);
			g_error_free (err);
			g_object_unref (msg);
			return;
		} else
			soup_test_assert (FALSE, "ERROR: could not parse response\n");
	} else
		soup_test_assert (FALSE, "Unexpectedly got successful response!\n");

	g_object_unref (msg);
}

static void
test_fault_malformed (void)
{
	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	do_bad_xmlrpc ("<methodCall/>");
}

static void
test_fault_method (void)
{
	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	do_bad_xmlrpc ("<methodCall><methodName>no_such_method</methodName><params><param><value><int>1</int></value></param></params></methodCall>");
}

static void
test_fault_args (void)
{
	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	do_bad_xmlrpc ("<methodCall><methodName>sum</methodName><params><param><value><int>1</int></value></param></params></methodCall>");
}

static GOptionEntry xmlrpc_entries[] = {
        { "uri", 'U', 0, G_OPTION_ARG_STRING, &uri,
          "Alternate URI for server", NULL },
        { "server-test", 'S', 0, G_OPTION_ARG_NONE, &server_test,
          "If this is being run from xmlrpc-old-server-test", NULL },
        { NULL }
};

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, xmlrpc_entries);

	if (!uri && !server_test) {
		apache_init ();
		uri = default_uri;
	}

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	g_test_add_func ("/xmlrpc-old/sum", test_sum);
	g_test_add_func ("/xmlrpc-old/countBools", test_countBools);
	g_test_add_func ("/xmlrpc-old/md5sum", test_md5sum);
	g_test_add_func ("/xmlrpc-old/dateChange", test_dateChange);
	g_test_add_func ("/xmlrpc-old/echo", test_echo);
	g_test_add_data_func ("/xmlrpc-old/ping/empty-params", GINT_TO_POINTER (TRUE), test_ping);
	g_test_add_data_func ("/xmlrpc-old/ping/no-params", GINT_TO_POINTER (FALSE), test_ping);
	g_test_add_func ("/xmlrpc-old/fault/malformed", test_fault_malformed);
	g_test_add_func ("/xmlrpc-old/fault/method", test_fault_method);
	g_test_add_func ("/xmlrpc-old/fault/args", test_fault_args);

	ret = g_test_run ();

	soup_test_session_abort_unref (session);

	test_cleanup ();
	return ret;
}
