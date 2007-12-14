/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include <string.h>
#include <unistd.h>

#include <libsoup/soup.h>
#include <libsoup/soup-md5-utils.h>

#include "apache-wrapper.h"

SoupSession *session;
static const char *uri = "http://localhost:47524/xmlrpc-server.php";
int debug;

static void
dprintf (int level, const char *format, ...)
{
	va_list args;

	if (debug < level)
		return;

	va_start (args, format);
	vprintf (format, args);
	va_end (args);
}

static const char *const value_type[] = {
	"BAD",
	"int",
	"boolean",
	"string",
	"double",
	"datetime",
	"base64",
	"struct",
	"array"
};

static gboolean
do_xmlrpc (const char *method, ...)
{
	SoupMessage *msg;
	va_list args;
	GValueArray *params;
	GValue value;
	GError *err = NULL;
	char *body;
	GType type;

	va_start (args, method);
	params = soup_value_array_from_args (args);
	body = soup_xmlrpc_build_method_call (method, params->values,
					      params->n_values);
	g_value_array_free (params);
	if (!body) {
		va_end (args);
		return FALSE;
	}

	msg = soup_message_new ("POST", uri);
	soup_message_set_request (msg, "text/xml",
				  SOUP_BUFFER_SYSTEM_OWNED,
				  body, strlen (body));
	soup_session_send_message (session, msg);

	dprintf (3, "\n%.*s\n%d %s\n%.*s\n",
		 msg->request.length, msg->request.body,
		 msg->status_code, msg->reason_phrase,
		 msg->response.length, msg->response.body);

	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		dprintf (1, "ERROR: %d %s\n", msg->status_code,
			 msg->reason_phrase);
		g_object_unref (msg);
		va_end (args);
		return FALSE;
	}

	if (!soup_xmlrpc_parse_method_response (msg->response.body,
						msg->response.length,
						&value, &err)) {
		if (err) {
			dprintf (1, "FAULT: %d %s\n", err->code, err->message);
			g_error_free (err);
		} else
			dprintf (1, "ERROR: could not parse response\n");
		g_object_unref (msg);
		va_end (args);
		return FALSE;
	}
	g_object_unref (msg);

	type = va_arg (args, GType);
	if (!soup_value_getv (&value, type, args)) {
		dprintf (1, "ERROR: could not parse response\n");
		g_value_unset (&value);
		va_end (args);
		return FALSE;
	}

	va_end (args);
	return TRUE;
}

static gboolean
test_sum (void)
{
	GValueArray *ints;
	int i, val, sum, result;
	gboolean ok;

	dprintf (1, "sum (array of int -> int): ");

	ints = g_value_array_new (10);
	for (i = sum = 0; i < 10; i++) {
		val = rand () % 100;
		dprintf (2, "%s%d", i == 0 ? "[" : ", ", val);
		soup_value_array_append (ints, G_TYPE_INT, val);
		sum += val;
	}
	dprintf (2, "] -> ");

	ok = do_xmlrpc ("sum",
			G_TYPE_VALUE_ARRAY, ints,
			G_TYPE_INVALID,
			G_TYPE_INT, &result);
	g_value_array_free (ints);

	if (!ok)
		return FALSE;

	dprintf (2, "%d: ", result);
	dprintf (1, "%s\n", result == sum ? "OK!" : "WRONG!");
	return result == sum;
}

static gboolean
test_countBools (void)
{
	GValueArray *bools;
	int i, trues, falses;
	int ret_trues, ret_falses;
	gboolean val, ok;
	GHashTable *result;

	dprintf (1, "countBools (array of boolean -> struct of ints): ");

	bools = g_value_array_new (10);
	for (i = trues = falses = 0; i < 10; i++) {
		val = rand () > (RAND_MAX / 2);
		dprintf (2, "%s%c", i == 0 ? "[" : ", ", val ? 'T' : 'F');
		soup_value_array_append (bools, G_TYPE_BOOLEAN, val);
		if (val)
			trues++;
		else
			falses++;
	}
	dprintf (2, "] -> ");

	ok = do_xmlrpc ("countBools",
			G_TYPE_VALUE_ARRAY, bools,
			G_TYPE_INVALID,
			G_TYPE_HASH_TABLE, &result);
	g_value_array_free (bools);
	if (!ok)
		return FALSE;

	if (!soup_value_hash_lookup (result, "true", G_TYPE_INT, &ret_trues)) {
		dprintf (1, "NO 'true' value in response\n");
		return FALSE;
	}
	if (!soup_value_hash_lookup (result, "false", G_TYPE_INT, &ret_falses)) {
		dprintf (1, "NO 'false' value in response\n");
		return FALSE;
	}
	g_hash_table_destroy (result);

	dprintf (2, "{ true: %d, false: %d } ", ret_trues, ret_falses);
	ok = (trues == ret_trues) && (falses == ret_falses);
	dprintf (1, "%s\n", ok ? "OK!" : "WRONG!");
	return ok;
}

static gboolean
test_md5sum (void)
{
	GByteArray *data, *result;
	int i;
	SoupMD5Context md5;
	guchar digest[16];
	gboolean ok;

	dprintf (1, "md5sum (base64 -> base64): ");

	data = g_byte_array_new ();
	g_byte_array_set_size (data, 256);
	for (i = 0; i < data->len; i++)
		data->data[i] = (char)(rand ());

	soup_md5_init (&md5);
	soup_md5_update (&md5, data->data, data->len);
	soup_md5_final (&md5, digest);

	ok = do_xmlrpc ("md5sum",
			SOUP_TYPE_BYTE_ARRAY, data,
			G_TYPE_INVALID,
			SOUP_TYPE_BYTE_ARRAY, &result);
	g_byte_array_free (data, TRUE);
	if (!ok)
		return FALSE;

	if (result->len != 16) {
		dprintf (1, "result has WRONG length (%d)\n", result->len);
		g_byte_array_free (result, TRUE);
		return FALSE;
	}

	ok = (memcmp (digest, result->data, 16) == 0);
	dprintf (1, "%s\n", ok ? "OK!" : "WRONG!");
	g_byte_array_free (result, TRUE);
	return ok;
}

static gboolean
test_dateChange (void)
{
	GHashTable *structval;
	SoupDate *date, *result;
	char *timestamp;
	gboolean ok;

	dprintf (1, "dateChange (struct of time and ints -> time): ");

	structval = soup_value_hash_new ();

	date = soup_date_new (1970 + (rand () % 50),
			      1 + rand () % 12,
			      1 + rand () % 28,
			      rand () % 24,
			      rand () % 60,
			      rand () % 60);
	soup_value_hash_insert (structval, "date", SOUP_TYPE_DATE, date);

	if (debug >= 2) {
		timestamp = soup_date_to_string (date, SOUP_DATE_ISO8601_XMLRPC);
		dprintf (2, "{ date: %s", timestamp);
		g_free (timestamp);
	}

	if (rand () % 3) {
		date->year = 1970 + (rand () % 50);
		dprintf (2, ", tm_year: %d", date->year - 1900);
		soup_value_hash_insert (structval, "tm_year",
					G_TYPE_INT, date->year - 1900);
	}
	if (rand () % 3) {
		date->month = 1 + rand () % 12;
		dprintf (2, ", tm_mon: %d", date->month - 1);
		soup_value_hash_insert (structval, "tm_mon",
					G_TYPE_INT, date->month - 1);
	}
	if (rand () % 3) {
		date->day = 1 + rand () % 28;
		dprintf (2, ", tm_mday: %d", date->day);
		soup_value_hash_insert (structval, "tm_mday",
					G_TYPE_INT, date->day);
	}
	if (rand () % 3) {
		date->hour = rand () % 24;
		dprintf (2, ", tm_hour: %d", date->hour);
		soup_value_hash_insert (structval, "tm_hour",
					G_TYPE_INT, date->hour);
	}
	if (rand () % 3) {
		date->minute = rand () % 60;
		dprintf (2, ", tm_min: %d", date->minute);
		soup_value_hash_insert (structval, "tm_min",
					G_TYPE_INT, date->minute);
	}
	if (rand () % 3) {
		date->second = rand () % 60;
		dprintf (2, ", tm_sec: %d", date->second);
		soup_value_hash_insert (structval, "tm_sec",
					G_TYPE_INT, date->second);
	}

	dprintf (2, " } -> ");

	ok = do_xmlrpc ("dateChange",
			G_TYPE_HASH_TABLE, structval,
			G_TYPE_INVALID,
			SOUP_TYPE_DATE, &result);
	g_hash_table_destroy (structval);
	if (!ok) {
		soup_date_free (date);
		return FALSE;
	}

	if (debug >= 2) {
		timestamp = soup_date_to_string (result, SOUP_DATE_ISO8601_XMLRPC);
		dprintf (2, "%s: ", timestamp);
		g_free (timestamp);
	}

	ok = ((date->year   == result->year) &&
	      (date->month  == result->month) &&
	      (date->day    == result->day) &&
	      (date->hour   == result->hour) &&
	      (date->minute == result->minute) &&
	      (date->second == result->second));
	soup_date_free (date);
	soup_date_free (result);

	dprintf (1, "%s\n", ok ? "OK!" : "WRONG!");
	return ok;
}

static const char *const echo_strings[] = {
	"This is a test",
	"& so is this",
	"and so is <this>",
	"&amp; so is &lt;this&gt;"
};
#define N_ECHO_STRINGS G_N_ELEMENTS (echo_strings)

static gboolean
test_echo (void)
{
	GValueArray *originals, *echoes;
	int i;

	dprintf (1, "echo (array of string -> array of string): ");

	originals = g_value_array_new (N_ECHO_STRINGS);
	for (i = 0; i < N_ECHO_STRINGS; i++) {
		soup_value_array_append (originals, G_TYPE_STRING, echo_strings[i]);
		dprintf (2, "%s\"%s\"", i == 0 ? "[" : ", ", echo_strings[i]);
	}
	dprintf (2, "] -> ");

	if (!do_xmlrpc ("echo",
			G_TYPE_VALUE_ARRAY, originals,
			G_TYPE_INVALID,
			G_TYPE_VALUE_ARRAY, &echoes)) {
		g_value_array_free (originals);
		return FALSE;
	}
	g_value_array_free (originals);

	if (debug >= 2) {
		for (i = 0; i < echoes->n_values; i++) {
			dprintf (2, "%s\"%s\"", i == 0 ? "[" : ", ",
				 g_value_get_string (&echoes->values[i]));
		}
		dprintf (2, "] -> ");
	}

	if (echoes->n_values != N_ECHO_STRINGS) {
		dprintf (1, " WRONG! Wrong number of return strings");
		g_value_array_free (echoes);
		return FALSE;
	}

	for (i = 0; i < echoes->n_values; i++) {
		if (strcmp (echo_strings[i], g_value_get_string (&echoes->values[i])) != 0) {
			dprintf (1, " WRONG! Mismatch at %d\n", i + 1);
			g_value_array_free (echoes);
			return FALSE;
		}
	}

	dprintf (1, "OK!\n");
	g_value_array_free (echoes);
	return TRUE;
}

static void
usage (void)
{
	fprintf (stderr, "Usage: xmlrpc-test [-d] [-d]\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	int opt, errors = 0;

	g_type_init ();
	g_thread_init (NULL);

	while ((opt = getopt (argc, argv, "d")) != -1) {
		switch (opt) {
		case 'd':
			debug++;
			break;

		case '?':
			usage ();
			break;
		}
	}

	srand (time (NULL));

	if (!apache_init ()) {
		fprintf (stderr, "Could not start apache\n");
		return 1;
	}

	session = soup_session_sync_new ();

	if (!test_sum ())
		errors++;
	if (!test_countBools ())
		errors++;
	if (!test_md5sum ())
		errors++;
	if (!test_dateChange ())
		errors++;
	if (!test_echo ())
		errors++;

	soup_session_abort (session);
	g_object_unref (session);

	apache_cleanup ();

	dprintf (1, "\n");
	if (errors) {
		printf ("xmlrpc-test: %d error(s). Run with '-d' for details\n",
			errors);
	} else
		printf ("xmlrpc-test: OK\n");
	return errors;
}
