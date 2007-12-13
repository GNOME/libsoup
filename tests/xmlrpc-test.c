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

static SoupXmlrpcResponse *
do_xmlrpc (SoupXmlrpcMessage *xmsg, SoupXmlrpcValueType type)
{
	SoupMessage *msg = SOUP_MESSAGE (xmsg);
	SoupXmlrpcResponse *response;
	SoupXmlrpcValue *value;
	int status;

	soup_xmlrpc_message_persist (xmsg);
	status = soup_session_send_message (session, msg);

	dprintf (3, "\n%.*s\n%d %s\n%.*s\n",
		 msg->request.length, msg->request.body,
		 msg->status_code, msg->reason_phrase,
		 msg->response.length, msg->response.body);

	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		dprintf (1, "ERROR: %d %s\n", status, msg->reason_phrase);
		g_object_unref (msg);
		return FALSE;
	}

	response = soup_xmlrpc_message_parse_response (xmsg);
	g_object_unref (msg);
	if (!response || soup_xmlrpc_response_is_fault (response)) {
		if (!response)
			dprintf (1, "ERROR: no response\n");
		else {
			dprintf (1, "ERROR: fault\n");
			g_object_unref (response);
		}
		return FALSE;
	}

	value = soup_xmlrpc_response_get_value (response);
	if (!value) {
		dprintf (1, "ERROR: no value?\n");
		g_object_unref (response);
		return NULL;
	} else if (soup_xmlrpc_value_get_type (value) != type) {
		dprintf (1, "ERROR: wrong value type; expected %s, got %s\n",
			 value_type[type], value_type[soup_xmlrpc_value_get_type (value)]);
		g_object_unref (response);
		return NULL;
	}

	return response;
}

static gboolean
test_sum (void)
{
	SoupXmlrpcMessage *msg;
	SoupXmlrpcResponse *response;
	SoupXmlrpcValue *value;
	int i, val, sum;
	long result;

	dprintf (1, "sum (array of int -> int): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "sum");
	soup_xmlrpc_message_start_param (msg);
	soup_xmlrpc_message_start_array (msg);
	for (i = sum = 0; i < 10; i++) {
		val = rand () % 100;
		dprintf (2, "%s%d", i == 0 ? "[" : ", ", val);
		soup_xmlrpc_message_write_int (msg, val);
		sum += val;
	}
	dprintf (2, "] -> ");
	soup_xmlrpc_message_end_array (msg);
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	response = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_INT);
	if (!response)
		return FALSE;
	value = soup_xmlrpc_response_get_value (response);

	if (!soup_xmlrpc_value_get_int (value, &result)) {
		dprintf (1, "wrong type?\n");
		g_object_unref (response);
		return FALSE;
	}
	g_object_unref (response);

	dprintf (2, "%ld: ", result);
	dprintf (1, "%s\n", result == sum ? "OK!" : "WRONG!");
	return result == sum;
}

static gboolean
test_countBools (void)
{
	SoupXmlrpcMessage *msg;
	SoupXmlrpcResponse *response;
	SoupXmlrpcValue *value;
	int i, trues, falses;
	long ret_trues, ret_falses;
	gboolean val, ok;
	GHashTable *result;

	dprintf (1, "countBools (array of boolean -> struct of ints): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "countBools");
	soup_xmlrpc_message_start_param (msg);
	soup_xmlrpc_message_start_array (msg);
	for (i = trues = falses = 0; i < 10; i++) {
		val = rand () > (RAND_MAX / 2);
		dprintf (2, "%s%c", i == 0 ? "[" : ", ", val ? 'T' : 'F');
		soup_xmlrpc_message_write_boolean (msg, val);
		if (val)
			trues++;
		else
			falses++;
	}
	dprintf (2, "] -> ");
	soup_xmlrpc_message_end_array (msg);
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	response = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_STRUCT);
	if (!response)
		return FALSE;
	value = soup_xmlrpc_response_get_value (response);

	if (!soup_xmlrpc_value_get_struct (value, &result)) {
		dprintf (1, "wrong type?\n");
		g_object_unref (response);
		return FALSE;
	}

	if (!soup_xmlrpc_value_get_int (g_hash_table_lookup (result, "true"), &ret_trues)) {
		dprintf (1, "NO 'true' value in response\n");
		g_hash_table_destroy (result);
		g_object_unref (response);
		return FALSE;
	}
	if (!soup_xmlrpc_value_get_int (g_hash_table_lookup (result, "false"), &ret_falses)) {
		dprintf (1, "NO 'false' value in response\n");
		g_hash_table_destroy (result);
		g_object_unref (response);
		return FALSE;
	}
	g_hash_table_destroy (result);
	g_object_unref (response);

	dprintf (2, "{ true: %ld, false: %ld } ", ret_trues, ret_falses);
	ok = (trues == ret_trues) && (falses == ret_falses);
	dprintf (1, "%s\n", ok ? "OK!" : "WRONG!");
	return ok;
}

static gboolean
test_md5sum (void)
{
	SoupXmlrpcMessage *msg;
	SoupXmlrpcResponse *response;
	SoupXmlrpcValue *value;
	GByteArray *result;
	char data[512];
	int i;
	SoupMD5Context md5;
	guchar digest[16];
	gboolean ok;

	dprintf (1, "md5sum (base64 -> base64): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "md5sum");
	soup_xmlrpc_message_start_param (msg);
	for (i = 0; i < sizeof (data); i++)
		data[i] = (char)(rand () & 0xFF);
	soup_xmlrpc_message_write_base64 (msg, data, sizeof (data));
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	response = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_BASE64);
	if (!response)
		return FALSE;
	value = soup_xmlrpc_response_get_value (response);

	if (!soup_xmlrpc_value_get_base64 (value, &result)) {
		dprintf (1, "wrong type?\n");
		g_object_unref (response);
		return FALSE;
	}
	g_object_unref (response);

	if (result->len != 16) {
		dprintf (1, "result has WRONG length (%d)\n", result->len);
		g_byte_array_free (result, TRUE);
		return FALSE;
	}

	soup_md5_init (&md5);
	soup_md5_update (&md5, data, sizeof (data));
	soup_md5_final (&md5, digest);

	ok = (memcmp (digest, result->data, 16) == 0);
	dprintf (1, "%s\n", ok ? "OK!" : "WRONG!");
	g_byte_array_free (result, TRUE);
	return ok;
}

static gboolean
test_dateChange (void)
{
	SoupXmlrpcMessage *msg;
	SoupXmlrpcResponse *response;
	SoupXmlrpcValue *value;
	SoupDate *date, *result;
	char *timestamp;
	gboolean ok;

	dprintf (1, "dateChange (struct of time and ints -> time): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "dateChange");
	soup_xmlrpc_message_start_param (msg);
	soup_xmlrpc_message_start_struct (msg);

	soup_xmlrpc_message_start_member (msg, "date");

	date = soup_date_new (1970 + (rand () % 50),
			      1 + rand () % 12,
			      1 + rand () % 28,
			      rand () % 24,
			      rand () % 60,
			      rand () % 60);
	soup_xmlrpc_message_write_datetime (msg, date);
	soup_xmlrpc_message_end_member (msg);

	if (debug) {
		timestamp = soup_date_to_string (date, SOUP_DATE_ISO8601_XMLRPC);
		dprintf (2, "{ date: %s", timestamp);
		g_free (timestamp);
	}

	if (rand () % 3) {
		date->year = 1970 + (rand () % 50);
		dprintf (2, ", tm_year: %d", date->year - 1900);
		soup_xmlrpc_message_start_member (msg, "tm_year");
		soup_xmlrpc_message_write_int (msg, date->year - 1900);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		date->month = rand () % 12 + 1;
		dprintf (2, ", tm_mon: %d", date->month - 1);
		soup_xmlrpc_message_start_member (msg, "tm_mon");
		soup_xmlrpc_message_write_int (msg, date->month - 1);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		date->day = 1 + (rand () % 28);
		dprintf (2, ", tm_mday: %d", date->day);
		soup_xmlrpc_message_start_member (msg, "tm_mday");
		soup_xmlrpc_message_write_int (msg, date->day);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		date->hour = rand () % 24;
		dprintf (2, ", tm_hour: %d", date->hour);
		soup_xmlrpc_message_start_member (msg, "tm_hour");
		soup_xmlrpc_message_write_int (msg, date->hour);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		date->minute = rand () % 60;
		dprintf (2, ", tm_min: %d", date->minute);
		soup_xmlrpc_message_start_member (msg, "tm_min");
		soup_xmlrpc_message_write_int (msg, date->minute);
		soup_xmlrpc_message_end_member (msg);
	}
	if (rand () % 3) {
		date->second = rand () % 60;
		dprintf (2, ", tm_sec: %d", date->second);
		soup_xmlrpc_message_start_member (msg, "tm_sec");
		soup_xmlrpc_message_write_int (msg, date->second);
		soup_xmlrpc_message_end_member (msg);
	}

	dprintf (2, " } -> ");

	soup_xmlrpc_message_end_struct (msg);
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	response = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_DATETIME);
	if (!response)
		return FALSE;
	value = soup_xmlrpc_response_get_value (response);

	if (!soup_xmlrpc_value_get_datetime (value, &result)) {
		dprintf (1, "wrong type?\n");
		g_object_unref (response);
		return FALSE;
	}
	g_object_unref (response);

	if (debug) {
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
	SoupXmlrpcMessage *msg;
	SoupXmlrpcResponse *response;
	SoupXmlrpcValue *value, *elt;
	SoupXmlrpcValueArrayIterator *iter;
	char *echo;
	int i;

	dprintf (1, "echo (array of string -> array of string): ");

	msg = soup_xmlrpc_message_new (uri);
	soup_xmlrpc_message_start_call (msg, "echo");
	soup_xmlrpc_message_start_param (msg);
	soup_xmlrpc_message_start_array (msg);
	for (i = 0; i < N_ECHO_STRINGS; i++) {
		dprintf (2, "%s\"%s\"", i == 0 ? "[" : ", ", echo_strings[i]);
		soup_xmlrpc_message_write_string (msg, echo_strings[i]);
	}
	dprintf (2, "] -> ");
	soup_xmlrpc_message_end_array (msg);
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	response = do_xmlrpc (msg, SOUP_XMLRPC_VALUE_TYPE_ARRAY);
	if (!response)
		return FALSE;
	value = soup_xmlrpc_response_get_value (response);

	if (!soup_xmlrpc_value_array_get_iterator (value, &iter)) {
		dprintf (1, "wrong type?\n");
		g_object_unref (response);
		return FALSE;
	}
	i = 0;
	while (iter) {
		if (!soup_xmlrpc_value_array_iterator_get_value (iter, &elt)) {
			dprintf (1, " WRONG! Can't get result element %d\n", i + 1);
			g_object_unref (response);
			return FALSE;
		}
		if (!soup_xmlrpc_value_get_string (elt, &echo)) {
			dprintf (1, " WRONG! Result element %d is not a string", i + 1);
			g_object_unref (response);
			return FALSE;
		}
		dprintf (2, "%s\"%s\"", i == 0 ? "[" : ", ", echo);
		if (strcmp (echo_strings[i], echo) != 0) {
			dprintf (1, " WRONG! Mismatch at %d\n", i + 1);
			g_free (echo);
			g_object_unref (response);
			return FALSE;
		}
		g_free (echo);

		iter = soup_xmlrpc_value_array_iterator_next (iter);
		i++;
	}
	dprintf (2, "] ");
	g_object_unref (response);

	dprintf (1, "%s\n", i == N_ECHO_STRINGS ? "OK!" : "WRONG! Too few results");
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
