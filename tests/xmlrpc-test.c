/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2001-2003, Ximian, Inc.
 * Copyright 2015, Collabora ltd.
 */

#include "test-utils.h"

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
send_xmlrpc (const char *body, const char *signature, GVariant **retval)
{
	SoupMessage *msg;
	GError *err = NULL;

	msg = soup_message_new ("POST", uri);
	soup_message_set_request (msg, "text/xml", SOUP_MEMORY_COPY,
				  body, strlen (body));
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	*retval = soup_xmlrpc_parse_response (msg->response_body->data,
					      msg->response_body->length,
					      signature, &err);
	if (!*retval) {
		if (err->domain == SOUP_XMLRPC_FAULT)
			soup_test_assert (FALSE, "FAULT: %d %s\n", err->code, err->message);
		else
			soup_test_assert (FALSE, "ERROR: %s\n", err->message);
		g_error_free (err);
		g_object_unref (msg);
		return FALSE;
	}

	return TRUE;
}

static gboolean
do_xmlrpc (const char *method, GVariant *args, const char *signature, GVariant **retval)
{
	gboolean ret;
	char *body;
	GError *error = NULL;

	body = soup_xmlrpc_build_request (method, args, &error);
	g_assert_no_error (error);
	if (!body)
		return FALSE;

	ret = send_xmlrpc (body, signature, retval);
	g_free (body);

	return ret;
}

static void
test_sum (void)
{
	GVariantBuilder builder;
	int i;
	double val, sum, result;
	GVariant *retval;
	gboolean ok;

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "sum (array of double -> double): ");

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ad"));
	for (i = sum = 0; i < 10; i++) {
		val = g_random_int_range (0, 400) / 4.0;
		debug_printf (2, "%s%.2f", i == 0 ? "[" : ", ", val);
		g_variant_builder_add (&builder, "d", val);
		sum += val;
	}
	debug_printf (2, "] -> ");

	ok = do_xmlrpc ("sum",
			g_variant_new ("(@ad)", g_variant_builder_end (&builder)),
			"d", &retval);

	if (!ok)
		return;

	result = g_variant_get_double (retval);
	debug_printf (2, "%.2f\n", result);
	g_assert_cmpfloat (result, ==, sum);

	g_variant_unref (retval);
}

static void
test_countBools (void)
{
	GVariantBuilder builder;
	int i, trues, falses;
	GVariant *retval;
	int ret_trues, ret_falses;
	gboolean val, ok;

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "countBools (array of boolean -> struct of ints): ");

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("ab"));
	for (i = trues = falses = 0; i < 10; i++) {
		val = g_random_boolean ();
		debug_printf (2, "%s%c", i == 0 ? "[" : ", ", val ? 'T' : 'F');
		g_variant_builder_add (&builder, "b", val);
		if (val)
			trues++;
		else
			falses++;
	}
	debug_printf (2, "] -> ");

	ok = do_xmlrpc ("countBools",
			g_variant_new ("(@ab)", g_variant_builder_end (&builder)),
			"a{si}", &retval);
	if (!ok)
		return;

	g_assert_true (g_variant_lookup (retval, "true", "i", &ret_trues));
	g_assert_true (g_variant_lookup (retval, "false", "i", &ret_falses));
	g_assert_cmpint (g_variant_n_children (retval), ==, 2);
	g_variant_unref (retval);

	debug_printf (2, "{ true: %d, false: %d }\n", ret_trues, ret_falses);
	g_assert_cmpint (trues, ==, ret_trues);
	g_assert_cmpint (falses, ==, ret_falses);
}

static void
test_md5sum (void)
{
	GByteArray *data;
	int i;
	GChecksum *checksum;
	guchar digest[16];
	gsize digest_len = sizeof (digest);
	GVariant *retval;
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

	ok = do_xmlrpc ("md5sum",
			g_variant_new ("(@ay)",
				       g_variant_new_from_data (G_VARIANT_TYPE_BYTESTRING,
								data->data, data->len,
								TRUE, NULL, NULL)),
			"ay", &retval);
	g_byte_array_free (data, TRUE);
	if (!ok)
		return;

	soup_assert_cmpmem (g_variant_get_data (retval), g_variant_get_size (retval),
			    digest, digest_len);
	g_variant_unref (retval);
}

static void
test_dateChange (void)
{
	GVariantDict structval;
	SoupDate *date, *result;
	char *timestamp;
	GVariant *retval;
	gboolean ok;
	GError *error = NULL;

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "dateChange (date, struct of ints -> time)\n");

	date = soup_date_new (1970 + (g_random_int_range (0, 50)),
			      1 + g_random_int_range (0, 12),
			      1 + g_random_int_range (0, 28),
			      g_random_int_range (0, 24),
			      g_random_int_range (0, 60),
			      g_random_int_range (0, 60));
	if (debug_level >= 2) {
		char *tmp;

		tmp = soup_date_to_string (date, SOUP_DATE_ISO8601_XMLRPC);
		debug_printf (2, "date: %s, {", tmp);
		g_free (tmp);
	}

	g_variant_dict_init (&structval, NULL);

#define MAYBE (g_random_int_range (0, 3) != 0)

	if (MAYBE) {
		date->year = 1970 + (g_random_int_range (0, 50));
		debug_printf (2, "tm_year: %d, ", date->year - 1900);
		g_variant_dict_insert (&structval, "tm_year",
					"i", date->year - 1900);
	}
	if (MAYBE) {
		date->month = 1 + g_random_int_range (0, 12);
		debug_printf (2, "tm_mon: %d, ", date->month - 1);
		g_variant_dict_insert (&structval, "tm_mon",
					"i", date->month - 1);
	}
	if (MAYBE) {
		date->day = 1 + g_random_int_range (0, 28);
		debug_printf (2, "tm_mday: %d, ", date->day);
		g_variant_dict_insert (&structval, "tm_mday",
					"i", date->day);
	}
	if (MAYBE) {
		date->hour = g_random_int_range (0, 24);
		debug_printf (2, "tm_hour: %d, ", date->hour);
		g_variant_dict_insert (&structval, "tm_hour",
					"i", date->hour);
	}
	if (MAYBE) {
		date->minute = g_random_int_range (0, 60);
		debug_printf (2, "tm_min: %d, ", date->minute);
		g_variant_dict_insert (&structval, "tm_min",
					"i", date->minute);
	}
	if (MAYBE) {
		date->second = g_random_int_range (0, 60);
		debug_printf (2, "tm_sec: %d, ", date->second);
		g_variant_dict_insert (&structval, "tm_sec",
					"i", date->second);
	}

	debug_printf (2, "} -> ");

	ok = do_xmlrpc ("dateChange",
			g_variant_new ("(vv)",
				       soup_xmlrpc_variant_new_datetime (date),
				       g_variant_dict_end (&structval)),
			NULL, &retval);
	if (!ok) {
		soup_date_free (date);
		return;
	}

	result = soup_xmlrpc_variant_get_datetime (retval, &error);
	g_assert_no_error (error);

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
	g_variant_unref (retval);
}

static const char *const echo_strings[] = {
	"This is a test",
	"& so is this",
	"and so is <this>",
	"&amp; so is &lt;this&gt;",
	NULL
};

static void
test_echo (void)
{
	GVariant *originals;
	GVariant *retval;
	char *str;

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "echo (array of string -> array of string):\n");

	originals = g_variant_new ("^as", echo_strings);
	g_variant_ref_sink (originals);
	str = g_variant_print (originals, TRUE);
	debug_printf (2, "%s -> ", str);
	g_free (str);

	if (!do_xmlrpc ("echo",
			g_variant_new ("(@as)", originals),
			"as", &retval)) {
		g_variant_unref (originals);
		return;
	}

	str = g_variant_print (retval, TRUE);
	debug_printf (2, "%s\n", str);
	g_free (str);

	g_assert_true (g_variant_equal (originals, retval));

	g_variant_unref (originals);
	g_variant_unref (retval);
}

static void
test_ping (gconstpointer include_params)
{
	GVariant *retval;
	char *request;
	gboolean ret;
	GError *error = NULL;

	g_test_bug ("671661");

	SOUP_TEST_SKIP_IF_NO_XMLRPC_SERVER;

	debug_printf (2, "ping (void (%s) -> string)\n",
		      include_params ? "empty <params>" : "no <params>");

	request = soup_xmlrpc_build_request ("ping", g_variant_new ("()"), &error);
	g_assert_no_error (error);
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

	ret = send_xmlrpc (request, "s", &retval);
	g_free (request);

	if (!ret)
		return;

	g_assert_cmpstr (g_variant_get_string (retval, NULL), ==, "pong");
	g_variant_unref (retval);
}

static void
do_bad_xmlrpc (const char *body)
{
	SoupMessage *msg;
	GError *err = NULL;

	msg = soup_message_new ("POST", uri);
	soup_message_set_request (msg, "text/xml", SOUP_MEMORY_COPY,
				  body, strlen (body));
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	if (!soup_xmlrpc_parse_response (msg->response_body->data,
					 msg->response_body->length,
					 "()", &err)) {
		if (err->domain == SOUP_XMLRPC_FAULT) {
			debug_printf (1, "FAULT: %d %s (OK!)\n",
				      err->code, err->message);
			g_error_free (err);
			g_object_unref (msg);
			return;
		} else
			soup_test_assert (FALSE, "ERROR: could not parse response: %s\n", err->message);
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

#define BODY_PREFIX \
	"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" \
	"<methodCall><methodName>MyMethod</methodName>"
#define BODY_SUFFIX \
	"</methodCall>\n"

static void
verify_serialization (GVariant    *value,
		      const char *expected_params)
{
	char *debug;
	char *body;
	char *params;
	GError *error = NULL;

	debug = g_variant_print (value, TRUE);

	body = soup_xmlrpc_build_request ("MyMethod", value, &error);
	g_assert_no_error (error);
	g_assert (g_str_has_prefix (body, BODY_PREFIX));
	g_assert (g_str_has_suffix (body, BODY_SUFFIX));

	params = g_strndup (body + strlen (BODY_PREFIX),
	                    strlen (body) - strlen (BODY_PREFIX)
	                                  - strlen (BODY_SUFFIX));

	if (!g_str_equal (params, expected_params))
		g_error ("Failed to serialize '%s':\n"
		         "  expected: %s\n"
		         "  got:      %s\n",
		         debug, expected_params, params);

	g_free (params);
	g_free (body);
	g_free (debug);
}

static void
verify_serialization_fail (GVariant *value)
{
	char *body;
	GError *error = NULL;

	body = soup_xmlrpc_build_request ("MyMethod", value, &error);
	g_assert (body == NULL);
	g_assert (error != NULL);
	g_clear_error (&error);
}

static void
test_serializer (void)
{
	SoupDate *date;

	verify_serialization (g_variant_new_parsed ("()"),
		"<params/>");
	verify_serialization (g_variant_new_parsed ("(1, 2)"),
		"<params>"
		"<param><value><int>1</int></value></param>"
		"<param><value><int>2</int></value></param>"
		"</params>");
	verify_serialization (g_variant_new_parsed ("((1, 2),)"),
		"<params><param><value><array><data>"
		"<value><int>1</int></value>"
		"<value><int>2</int></value>"
		"</data></array></value></param></params>");
	verify_serialization (g_variant_new_parsed ("({'one', 1},)"),
		"<params><param><value><struct>"
		"<member><name>one</name><value><int>1</int></value></member>"
		"</struct></value></param></params>");
	verify_serialization (g_variant_new_parsed ("([{'one', 1},{'two', 2}],)"),
		"<params><param><value><struct>"
		"<member><name>one</name><value><int>1</int></value></member>"
		"<member><name>two</name><value><int>2</int></value></member>"
		"</struct></value></param></params>");
	verify_serialization (g_variant_new ("(^ay)", "bytestring"),
		"<params><param>"
		"<value><base64>Ynl0ZXN0cmluZwA=</base64></value>"
		"</param></params>");
	verify_serialization (g_variant_new ("(y)", 42),
		"<params>"
		"<param><value><int>42</int></value></param>"
		"</params>");
	date = soup_date_new_from_time_t (1434161309);
	verify_serialization (g_variant_new ("(v)", soup_xmlrpc_variant_new_datetime (date)),
		"<params>"
		"<param><value><dateTime.iso8601>20150613T02:08:29</dateTime.iso8601></value></param>"
		"</params>");
	soup_date_free (date);
	verify_serialization (g_variant_new ("(s)", "<>&"),
		"<params>"
		"<param><value><string>&lt;&gt;&amp;</string></value></param>"
		"</params>");
	verify_serialization (g_variant_new ("(u)", 0),
		"<params>"
		"<param><value><i8>0</i8></value></param>"
		"</params>");

	verify_serialization_fail (g_variant_new_parsed ("({1, 2},)"));
	verify_serialization_fail (g_variant_new ("(mi)", NULL));
	verify_serialization_fail (g_variant_new ("(t)", 0));
}

static void
verify_deserialization (GVariant *expected_variant,
			const char *signature,
			const char *params)
{
	char *body;
	char *method_name;
	SoupXMLRPCParams *out_params = NULL;
	GVariant *variant;
	GError *error = NULL;

	body = g_strconcat (BODY_PREFIX, params, BODY_SUFFIX, NULL);
	method_name = soup_xmlrpc_parse_request (body, strlen (body),
						 &out_params,
						 &error);
	g_assert_no_error (error);
	g_assert_cmpstr (method_name, ==, "MyMethod");

	variant = soup_xmlrpc_params_parse (out_params, signature, &error);
	g_assert_no_error (error);

	if (!g_variant_equal (variant, expected_variant)) {
		char *str1, *str2;

		str1 = g_variant_print (expected_variant, TRUE);
		str2 = g_variant_print (variant, TRUE);
		g_error ("Failed to deserialize '%s':\n"
		         "  expected: %s\n"
		         "  got:      %s\n",
		         params, str1, str2);
		g_free (str1);
		g_free (str2);
	}

	soup_xmlrpc_params_free (out_params);
	g_variant_unref (variant);
	g_variant_unref (expected_variant);
	g_free (method_name);
	g_free (body);
}

static void
verify_deserialization_fail (const char *signature,
			     const char *params)
{
	char *body;
	char *method_name;
	SoupXMLRPCParams *out_params = NULL;
	GVariant *variant;
	GError *error = NULL;

	body = g_strconcat (BODY_PREFIX, params, BODY_SUFFIX, NULL);
	method_name = soup_xmlrpc_parse_request (body, strlen (body),
						 &out_params,
						 &error);
	g_assert_no_error (error);
	g_assert_cmpstr (method_name, ==, "MyMethod");

	variant = soup_xmlrpc_params_parse (out_params, signature, &error);
	g_assert_error (error, SOUP_XMLRPC_ERROR, SOUP_XMLRPC_ERROR_ARGUMENTS);
	g_assert (variant == NULL);

	g_free (body);
	g_free (method_name);
	g_clear_error (&error);
	soup_xmlrpc_params_free (out_params);
}

static void
test_deserializer (void)
{
	char *tmp;
	SoupDate *date;

	verify_deserialization (g_variant_new_parsed ("@av []"),
		NULL,
		"<params/>");
	verify_deserialization (g_variant_new_parsed ("()"),
		"()",
		"<params/>");
	verify_deserialization (g_variant_new_parsed ("(@y 1,@n 2)"),
		"(yn)",
		"<params>"
		"<param><value><int>1</int></value></param>"
		"<param><value><int>2</int></value></param>"
		"</params>");
	verify_deserialization (g_variant_new_parsed ("[<[{'one', <1>},{'two', <2>}]>]"),
		NULL,
		"<params><param><value><struct>"
		"<member><name>one</name><value><int>1</int></value></member>"
		"<member><name>two</name><value><int>2</int></value></member>"
		"</struct></value></param></params>");
	verify_deserialization (g_variant_new_parsed ("([{'one', 1},{'two', 2}],)"),
		"(a{si})",
		"<params><param><value><struct>"
		"<member><name>one</name><value><int>1</int></value></member>"
		"<member><name>two</name><value><int>2</int></value></member>"
		"</struct></value></param></params>");
	date = soup_date_new_from_time_t (1434146909);
	verify_deserialization (g_variant_new_parsed ("[%v]", soup_xmlrpc_variant_new_datetime (date)),
		NULL,
		"<params>"
		"<param><value><dateTime.iso8601>20150612T22:08:29</dateTime.iso8601></value></param>"
		"</params>");
	soup_date_free (date);
	verify_deserialization (g_variant_new_parsed ("[<b'bytestring'>]"),
		NULL,
		"<params>"
		"<param><value><base64>Ynl0ZXN0cmluZwA=</base64></value></param>"
		"</params>");
	verify_deserialization (g_variant_new_parsed ("[<1>]"),
		"av",
		"<params><param><value><int>1</int></value></param></params>");
	verify_deserialization (g_variant_new_parsed ("[<%s>]", "<>&"),
		NULL,
		"<params>"
		"<param><value><string>&lt;&gt;&amp;</string></value></param>"
		"</params>");
	verify_deserialization (g_variant_new_parsed ("(@y 255,)"),
		"(y)",
		"<params>"
		"<param><value><int>255</int></value></param>"
		"</params>");

	tmp = g_strdup_printf ("<params>"
		"<param><value><int>%"G_GUINT64_FORMAT"</int></value></param>"
		"</params>", G_MAXUINT64);
	verify_deserialization (g_variant_new ("(t)", G_MAXUINT64),
		"(t)", tmp);
	g_free (tmp);

	verify_deserialization_fail (NULL,
		"<params>"
		"<param><value><boolean>2</boolean></value></param>"
		"</params>");
	verify_deserialization_fail ("(y)",
		"<params>"
		"<param><value><int>256</int></value></param>"
		"</params>");
	verify_deserialization_fail ("(ii)",
		"<params>"
		"<param><value><int>1</int></value></param>"
		"</params>");
	verify_deserialization_fail ("(i)",
		"<params>"
		"<param><value><int>1</int></value></param>"
		"<param><value><int>2</int></value></param>"
		"</params>");
}

static void
test_fault (void)
{
	char *body;
	GVariant *reply;
	GError *error = NULL;

	body = soup_xmlrpc_build_fault (1, "error: %s", "failed");
	reply = soup_xmlrpc_parse_response (body, strlen (body), NULL, &error);
	g_assert_error (error, SOUP_XMLRPC_FAULT, 1);
	g_assert_cmpstr (error->message, ==, "error: failed");
	g_assert (reply == NULL);

	g_free (body);
	g_clear_error (&error);
}

static GOptionEntry xmlrpc_entries[] = {
        { "uri", 'U', 0, G_OPTION_ARG_STRING, &uri,
          "Alternate URI for server", NULL },
        { "server-test", 'S', 0, G_OPTION_ARG_NONE, &server_test,
          "If this is being run from xmlrpc-server-test", NULL },
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

	g_test_add_func ("/xmlrpc/variant/serializer", test_serializer);
	g_test_add_func ("/xmlrpc/variant/deserializer", test_deserializer);
	g_test_add_func ("/xmlrpc/variant/fault", test_fault);
	g_test_add_func ("/xmlrpc/variant/sum", test_sum);
	g_test_add_func ("/xmlrpc/variant/countBools", test_countBools);
	g_test_add_func ("/xmlrpc/variant/md5sum", test_md5sum);
	g_test_add_func ("/xmlrpc/variant/dateChange", test_dateChange);
	g_test_add_func ("/xmlrpc/variant/echo", test_echo);
	g_test_add_data_func ("/xmlrpc/variant/ping/empty-params", GINT_TO_POINTER (TRUE), test_ping);
	g_test_add_data_func ("/xmlrpc/variant/ping/no-params", GINT_TO_POINTER (FALSE), test_ping);
	g_test_add_func ("/xmlrpc/variant/fault/malformed", test_fault_malformed);
	g_test_add_func ("/xmlrpc/variant/fault/method", test_fault_method);
	g_test_add_func ("/xmlrpc/variant/fault/args", test_fault_args);

	ret = g_test_run ();

	soup_test_session_abort_unref (session);

	test_cleanup ();
	return ret;
}
