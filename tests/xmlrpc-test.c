/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include <string.h>
#include <unistd.h>

#include <libsoup/soup.h>
#include <libsoup/soup-date.h>
#include <libsoup/soup-md5-utils.h>
#include <libsoup/soup-xmlrpc-message.h>
#include <libsoup/soup-xmlrpc-response.h>

#include "apache-wrapper.h"

SoupSession *session;
static const char *uri = "http://localhost:47524/xmlrpc-server.php";
int debug;

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

static SoupXmlrpcValue *
do_xmlrpc (SoupXmlrpcMessage *xmsg, SoupXmlrpcValueType type)
{
	SoupMessage *msg = SOUP_MESSAGE (xmsg);
	SoupXmlrpcResponse *response;
	SoupXmlrpcValue *value;
	int status;

	soup_xmlrpc_message_persist (xmsg);
	status = soup_session_send_message (session, msg);

	if (debug > 1) {
		printf ("\n%.*s\n%d %s\n%.*s\n",
			msg->request.length, msg->request.body,
			msg->status_code, msg->reason_phrase,
			msg->response.length, msg->response.body);
	}

	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		printf ("ERROR: %d %s\n", status, msg->reason_phrase);
		return FALSE;
	}

	response = soup_xmlrpc_message_parse_response (xmsg);
	if (!response || soup_xmlrpc_response_is_fault (response)) {
		if (!response)
			printf ("ERROR: no response\n");
		else
			printf ("ERROR: fault\n");
		return FALSE;
	}

	value = soup_xmlrpc_response_get_value (response);
	if (!value) {
		printf ("ERROR: no value?\n");
		return NULL;
	} else if (soup_xmlrpc_value_get_type (value) != type) {
		printf ("ERROR: wrong value type; expected %s, got %s\n",
			value_type[type], value_type[soup_xmlrpc_value_get_type (value)]);
		return NULL;
	}

	return value;
}

static gboolean
test_sum (void)
{
	SoupXmlrpcMessage *msg;
	SoupXmlrpcValue *value;
	int i, val, sum;
	long result;

	printf ("sum (array of int -> int): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "sum");
	soup_xmlrpc_message_start_param (msg);
	soup_xmlrpc_message_start_array (msg);
	for (i = sum = 0; i < 10; i++) {
		val = rand () % 100;
		if (debug)
			printf ("%s%d", i == 0 ? "[" : ", ", val);
		soup_xmlrpc_message_write_int (msg, val);
		sum += val;
	}
	if (debug)
		printf ("] -> ");
	soup_xmlrpc_message_end_array (msg);
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	value = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_INT);
	if (!value)
		return FALSE;

	if (!soup_xmlrpc_value_get_int (value, &result)) {
		printf ("wrong type?\n");
		return FALSE;
	}

	if (debug)
		printf ("%ld: ", result);
	printf ("%s\n", result == sum ? "OK!" : "WRONG!");
	return result == sum;
}

static gboolean
test_countBools (void)
{
	SoupXmlrpcMessage *msg;
	SoupXmlrpcValue *value;
	int i, trues, falses;
	long ret_trues, ret_falses;
	gboolean val, ok;
	GHashTable *result;

	printf ("countBools (array of boolean -> struct of ints): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "countBools");
	soup_xmlrpc_message_start_param (msg);
	soup_xmlrpc_message_start_array (msg);
	for (i = trues = falses = 0; i < 10; i++) {
		val = rand () > (RAND_MAX / 2);
		if (debug)
			printf ("%s%c", i == 0 ? "[" : ", ", val ? 'T' : 'F');
		soup_xmlrpc_message_write_boolean (msg, val);
		if (val)
			trues++;
		else
			falses++;
	}
	if (debug)
		printf ("] -> ");
	soup_xmlrpc_message_end_array (msg);
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	value = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_STRUCT);
	if (!value)
		return FALSE;

	if (!soup_xmlrpc_value_get_struct (value, &result)) {
		printf ("wrong type?\n");
		return FALSE;
	}

	if (!soup_xmlrpc_value_get_int (g_hash_table_lookup (result, "true"), &ret_trues)) {
		printf ("NO 'true' value in response\n");
		return FALSE;
	}
	if (!soup_xmlrpc_value_get_int (g_hash_table_lookup (result, "false"), &ret_falses)) {
		printf ("NO 'false' value in response\n");
		return FALSE;
	}

	if (debug)
		printf ("{ true: %ld, false: %ld } ", ret_trues, ret_falses);
	ok = (trues == ret_trues) && (falses == ret_falses);
	printf ("%s\n", ok ? "OK!" : "WRONG!");
	return ok;
}

static gboolean
test_md5sum (void)
{
	SoupXmlrpcMessage *msg;
	SoupXmlrpcValue *value;
	GByteArray *result;
	char data[512];
	int i;
	SoupMD5Context md5;
	guchar digest[16];
	gboolean ok;

	printf ("md5sum (base64 -> base64): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "md5sum");
	soup_xmlrpc_message_start_param (msg);
	for (i = 0; i < sizeof (data); i++)
		data[i] = (char)(rand () & 0xFF);
	soup_xmlrpc_message_write_base64 (msg, data, sizeof (data));
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	value = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_BASE64);
	if (!value)
		return FALSE;

	if (!soup_xmlrpc_value_get_base64 (value, &result)) {
		printf ("wrong type?\n");
		return FALSE;
	}

	if (result->len != 16) {
		printf ("result has WRONG length (%d)\n", result->len);
		g_byte_array_free (result, TRUE);
		return FALSE;
	}

	soup_md5_init (&md5);
	soup_md5_update (&md5, data, sizeof (data));
	soup_md5_final (&md5, digest);

	ok = (memcmp (digest, result->data, 16) == 0);
	printf ("%s\n", ok ? "OK!" : "WRONG!");
	g_byte_array_free (result, TRUE);
	return ok;
}

static gboolean
test_dateChange (void)
{
	SoupXmlrpcMessage *msg;
	SoupXmlrpcValue *value;
	struct tm tm;
	time_t when, result;
	char timestamp[128];

	printf ("dateChange (struct of time and ints -> time): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "dateChange");
	soup_xmlrpc_message_start_param (msg);
	soup_xmlrpc_message_start_struct (msg);

	soup_xmlrpc_message_start_member (msg, "date");
	memset (&tm, 0, sizeof (tm));
	tm.tm_year = 70 + (rand () % 50);
	tm.tm_mon = rand () % 12;
	tm.tm_mday = 1 + (rand () % 28);
	tm.tm_hour = rand () % 24;
	tm.tm_min = rand () % 60;
	tm.tm_sec = rand () % 60;
	when = soup_mktime_utc (&tm);
	soup_xmlrpc_message_write_datetime (msg, when);
	soup_xmlrpc_message_end_member (msg);

	if (debug) {
		strftime (timestamp, sizeof (timestamp),
			  "%Y-%m-%dT%H:%M:%S", &tm);
		printf ("{ date: %s", timestamp);
	}

	if (rand () % 3) {
		tm.tm_year = 70 + (rand () % 50);
		if (debug)
			printf (", tm_year: %d", tm.tm_year);
		soup_xmlrpc_message_start_member (msg, "tm_year");
		soup_xmlrpc_message_write_int (msg, tm.tm_year);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		tm.tm_mon = rand () % 12;
		if (debug)
			printf (", tm_mon: %d", tm.tm_mon);
		soup_xmlrpc_message_start_member (msg, "tm_mon");
		soup_xmlrpc_message_write_int (msg, tm.tm_mon);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		tm.tm_mday = 1 + (rand () % 28);
		if (debug)
			printf (", tm_mday: %d", tm.tm_mday);
		soup_xmlrpc_message_start_member (msg, "tm_mday");
		soup_xmlrpc_message_write_int (msg, tm.tm_mday);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		tm.tm_hour = rand () % 24;
		if (debug)
			printf (", tm_hour: %d", tm.tm_hour);
		soup_xmlrpc_message_start_member (msg, "tm_hour");
		soup_xmlrpc_message_write_int (msg, tm.tm_hour);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		tm.tm_min = rand () % 60;
		if (debug)
			printf (", tm_min: %d", tm.tm_min);
		soup_xmlrpc_message_start_member (msg, "tm_min");
		soup_xmlrpc_message_write_int (msg, tm.tm_min);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		tm.tm_sec = rand () % 60;
		if (debug)
			printf (", tm_sec: %d", tm.tm_sec);
		soup_xmlrpc_message_start_member (msg, "tm_sec");
		soup_xmlrpc_message_write_int (msg, tm.tm_sec);
		soup_xmlrpc_message_end_member (msg);
	}
	when = soup_mktime_utc (&tm);

	if (debug)
		printf (" } -> ");

	soup_xmlrpc_message_end_struct (msg);
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	value = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_DATETIME);
	if (!value)
		return FALSE;

	if (!soup_xmlrpc_value_get_datetime (value, &result)) {
		printf ("wrong type?\n");
		return FALSE;
	}

	if (debug) {
		memset (&tm, 0, sizeof (tm));
		soup_gmtime (&result, &tm);
		strftime (timestamp, sizeof (timestamp),
			  "%Y-%m-%dT%H:%M:%S", &tm);
		printf ("%s: ", timestamp);
	}

	printf ("%s\n", (when == result) ? "OK!" : "WRONG!");
	return (when == result);
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
	SoupXmlrpcMessage *msg;
	SoupXmlrpcValue *value, *elt;
	SoupXmlrpcValueArrayIterator *iter;
	char *echo;
	int i;

	printf ("echo (array of string -> array of string): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "echo");
	soup_xmlrpc_message_start_param (msg);
	soup_xmlrpc_message_start_array (msg);
	for (i = 0; i < N_ECHO_STRINGS; i++) {
		if (debug)
			printf ("%s\"%s\"", i == 0 ? "[" : ", ", echo_strings[i]);
		soup_xmlrpc_message_write_string (msg, echo_strings[i]);
	}
	if (debug)
		printf ("] -> ");
	soup_xmlrpc_message_end_array (msg);
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	value = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_ARRAY);
	if (!value)
		return FALSE;

	if (!soup_xmlrpc_value_array_get_iterator (value, &iter)) {
		printf ("wrong type?\n");
		return FALSE;
	}
	i = 0;
	while (iter) {
		if (!soup_xmlrpc_value_array_iterator_get_value (iter, &elt)) {
			printf (" WRONG! Can't get result element %d\n", i + 1);
			return FALSE;
		}
		if (!soup_xmlrpc_value_get_string (elt, &echo)) {
			printf (" WRONG! Result element %d is not a string", i + 1);
			return FALSE;
		}
		if (debug)
			printf ("%s\"%s\"", i == 0 ? "[" : ", ", echo);
		if (strcmp (echo_strings[i], echo) != 0) {
			printf (" WRONG! Mismatch at %d\n", i + 1);
			return FALSE;
		}

		iter = soup_xmlrpc_value_array_iterator_next (iter);
		i++;
	}
	if (debug)
		printf ("] ");

	printf ("%s\n", i == N_ECHO_STRINGS ? "OK!" : "WRONG! Too few results");
	return i == N_ECHO_STRINGS;
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

	apache_cleanup ();

	printf ("\n%d errors\n", errors);
	return errors > 0;
}
