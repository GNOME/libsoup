/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message.c: HTTP request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#include <string.h>

#include "soup-auth.h"
#include "soup-marshal.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup-private.h"

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

enum {
	WROTE_INFORMATIONAL,
	WROTE_HEADERS,
	WROTE_CHUNK,
	WROTE_BODY,

	GOT_INFORMATIONAL,
	GOT_HEADERS,
	GOT_CHUNK,
	GOT_BODY,

	FINISHED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void got_headers (SoupMessage *req);
static void got_chunk (SoupMessage *req);
static void got_body (SoupMessage *req);
static void finished (SoupMessage *req);
static void free_chunks (SoupMessage *msg);

static void
init (GObject *object)
{
	SoupMessage *msg = SOUP_MESSAGE (object);

	msg->priv = g_new0 (SoupMessagePrivate, 1);

	msg->status  = SOUP_MESSAGE_STATUS_IDLE;

	msg->request_headers = g_hash_table_new (soup_str_case_hash,
						 soup_str_case_equal);

	msg->response_headers = g_hash_table_new (soup_str_case_hash,
						  soup_str_case_equal);

	msg->priv->http_version = SOUP_HTTP_1_1;
}

static void
finalize (GObject *object)
{
	SoupMessage *msg = SOUP_MESSAGE (object);

	soup_message_io_cancel (msg);

	if (msg->priv->uri)
		soup_uri_free (msg->priv->uri);

	if (msg->request.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (msg->request.body);
	if (msg->response.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (msg->response.body);
	free_chunks (msg);

	soup_message_clear_headers (msg->request_headers);
	g_hash_table_destroy (msg->request_headers);

	soup_message_clear_headers (msg->response_headers);
	g_hash_table_destroy (msg->response_headers);

	g_slist_foreach (msg->priv->content_handlers, (GFunc) g_free, NULL);
	g_slist_free (msg->priv->content_handlers);

	g_free ((char *) msg->reason_phrase);

	g_free (msg->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	SoupMessageClass *message_class = SOUP_MESSAGE_CLASS (object_class);

	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method definition */
	message_class->got_headers  = got_headers;
	message_class->got_chunk    = got_chunk;
	message_class->got_body     = got_body;
	message_class->finished     = finished;

	/* virtual method override */
	object_class->finalize = finalize;

	/* signals */
	signals[WROTE_INFORMATIONAL] =
		g_signal_new ("wrote_informational",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_informational),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
	signals[WROTE_HEADERS] =
		g_signal_new ("wrote_headers",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_headers),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
	signals[WROTE_CHUNK] =
		g_signal_new ("wrote_chunk",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_chunk),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
	signals[WROTE_BODY] =
		g_signal_new ("wrote_body",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_body),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	signals[GOT_INFORMATIONAL] =
		g_signal_new ("got_informational",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_informational),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
	signals[GOT_HEADERS] =
		g_signal_new ("got_headers",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_headers),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
	signals[GOT_CHUNK] =
		g_signal_new ("got_chunk",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_chunk),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
	signals[GOT_BODY] =
		g_signal_new ("got_body",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_body),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	signals[FINISHED] =
		g_signal_new ("finished",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, finished),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
}

SOUP_MAKE_TYPE (soup_message, SoupMessage, class_init, init, PARENT_TYPE)


/**
 * soup_message_new:
 * @method: the HTTP method for the created request
 * @uri_string: the destination endpoint (as a string)
 * 
 * Creates a new empty #SoupMessage, which will connect to @uri
 *
 * Return value: the new #SoupMessage (or %NULL if @uri could not
 * be parsed).
 */
SoupMessage *
soup_message_new (const char *method, const char *uri_string)
{
	SoupMessage *msg;
	SoupUri *uri;

	uri = soup_uri_new (uri_string);
	if (!uri)
		return NULL;

	msg = g_object_new (SOUP_TYPE_MESSAGE, NULL);
	msg->method = method ? method : SOUP_METHOD_GET;
	msg->priv->uri = uri;

	return msg;
}

/**
 * soup_message_new_from_uri:
 * @method: the HTTP method for the created request
 * @uri: the destination endpoint (as a #SoupUri)
 * 
 * Creates a new empty #SoupMessage, which will connect to @uri
 *
 * Return value: the new #SoupMessage
 */
SoupMessage *
soup_message_new_from_uri (const char *method, const SoupUri *uri)
{
	SoupMessage *msg;

	msg = g_object_new (SOUP_TYPE_MESSAGE, NULL);
	msg->method = method ? method : SOUP_METHOD_GET;
	msg->priv->uri = soup_uri_copy (uri);

	return msg;
}

/**
 * soup_message_set_request:
 * @msg: the message
 * @content_type: MIME Content-Type of the body
 * @req_owner: the #SoupOwnership of the passed data buffer.
 * @req_body: a data buffer containing the body of the message request.
 * @req_length: the byte length of @req_body.
 * 
 * Convenience function to set the request body of a #SoupMessage
 */
void
soup_message_set_request (SoupMessage   *msg,
			  const char    *content_type,
			  SoupOwnership  req_owner,
			  char          *req_body,
			  gulong         req_length)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (content_type != NULL);
	g_return_if_fail (req_body != NULL || req_length == 0);

	soup_message_add_header (msg->request_headers,
				 "Content-Type", content_type);
	msg->request.owner = req_owner;
	msg->request.body = req_body;
	msg->request.length = req_length;
}

/**
 * soup_message_set_response:
 * @msg: the message
 * @content_type: MIME Content-Type of the body
 * @req_owner: the #SoupOwnership of the passed data buffer.
 * @req_body: a data buffer containing the body of the message response.
 * @req_length: the byte length of @req_body.
 * 
 * Convenience function to set the response body of a #SoupMessage
 */
void
soup_message_set_response (SoupMessage   *msg,
			   const char    *content_type,
			   SoupOwnership  resp_owner,
			   char          *resp_body,
			   gulong         resp_length)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (content_type != NULL);
	g_return_if_fail (resp_body != NULL || resp_length == 0);

	soup_message_add_header (msg->response_headers,
				 "Content-Type", content_type);
	msg->response.owner = resp_owner;
	msg->response.body = resp_body;
	msg->response.length = resp_length;
}

void
soup_message_wrote_informational (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_INFORMATIONAL], 0);
}

void
soup_message_wrote_headers (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_HEADERS], 0);
}

void
soup_message_wrote_chunk (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_CHUNK], 0);
}

void
soup_message_wrote_body (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_BODY], 0);
}

void
soup_message_got_informational (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_INFORMATIONAL], 0);
}

static void
got_headers (SoupMessage *req)
{
	g_object_ref (req);
	soup_message_run_handlers (req, SOUP_HANDLER_PRE_BODY);
	if (SOUP_MESSAGE_IS_STARTING (req))
		g_signal_stop_emission (req, signals[GOT_HEADERS], 0);
	g_object_unref (req);
}

void
soup_message_got_headers (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_HEADERS], 0);
}

static void
got_chunk (SoupMessage *req)
{
	g_object_ref (req);
	soup_message_run_handlers (req, SOUP_HANDLER_BODY_CHUNK);
	if (SOUP_MESSAGE_IS_STARTING (req))
		g_signal_stop_emission (req, signals[GOT_CHUNK], 0);
	g_object_unref (req);
}

void
soup_message_got_chunk (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_CHUNK], 0);
}

static void
got_body (SoupMessage *req)
{
	g_object_ref (req);
	soup_message_run_handlers (req, SOUP_HANDLER_POST_BODY);
	if (SOUP_MESSAGE_IS_STARTING (req))
		g_signal_stop_emission (req, signals[GOT_BODY], 0);
	g_object_unref (req);
}

void
soup_message_got_body (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_BODY], 0);
}

static void
finished (SoupMessage *req)
{
	soup_message_io_cancel (req);
}

void
soup_message_finished (SoupMessage *msg)
{
	g_signal_emit (msg, signals[FINISHED], 0);
}


/**
 * soup_message_cancel:
 * @msg: a #SoupMessage currently being processed.
 * 
 * Cancel a running message, and issue completion callback with an
 * status code of %SOUP_STATUS_CANCELLED. If not requeued by the
 * completion callback, the @msg will be destroyed.
 */
void
soup_message_cancel (SoupMessage *msg)
{
	soup_message_set_status (msg, SOUP_STATUS_CANCELLED);
	soup_message_finished (msg);
}

static gboolean
free_header_list (gpointer name, gpointer vals, gpointer user_data)
{
	g_free (name);
	g_slist_foreach (vals, (GFunc) g_free, NULL);
	g_slist_free (vals);

	return TRUE;
}

void
soup_message_clear_headers (GHashTable *hash)
{
	g_return_if_fail (hash != NULL);

	g_hash_table_foreach_remove (hash, free_header_list, NULL);
}

void
soup_message_remove_header (GHashTable *hash, const char *name)
{
	gpointer old_key, old_vals;

	g_return_if_fail (hash != NULL);
	g_return_if_fail (name != NULL || name[0] != '\0');

	if (g_hash_table_lookup_extended (hash, name, &old_key, &old_vals)) {
		g_hash_table_remove (hash, name);
		free_header_list (old_key, old_vals, NULL);
	}
}

void
soup_message_add_header (GHashTable *hash, const char *name, const char *value)
{
	GSList *old_value;

	g_return_if_fail (hash != NULL);
	g_return_if_fail (name != NULL || name [0] != '\0');
	g_return_if_fail (value != NULL);

	old_value = g_hash_table_lookup (hash, name);

	if (old_value)
		g_slist_append (old_value, g_strdup (value));
	else {
		g_hash_table_insert (hash, g_strdup (name),
				     g_slist_append (NULL, g_strdup (value)));
	}
}

/**
 * soup_message_get_header:
 * @hash: a header hash table
 * @name: header name.
 * 
 * Lookup the first transport header in @hash with a key equal to
 * @name.
 * 
 * Return value: the header's value or %NULL if not found.
 */
const char *
soup_message_get_header (GHashTable *hash, const char *name)
{
	GSList *vals;

	g_return_val_if_fail (hash != NULL, NULL);
	g_return_val_if_fail (name != NULL || name [0] != '\0', NULL);

	vals = g_hash_table_lookup (hash, name);
	if (vals)
		return vals->data;

	return NULL;
}

/**
 * soup_message_get_header_list:
 * @hash: a header hash table
 * @name: header name.
 * 
 * Lookup the all transport request headers in @hash with a key equal
 * to @name.
 * 
 * Return value: a const pointer to a #GSList of header values or
 * %NULL if not found.
 */
const GSList *
soup_message_get_header_list (GHashTable *hash, const char *name)
{
	g_return_val_if_fail (hash != NULL, NULL);
	g_return_val_if_fail (name != NULL || name [0] != '\0', NULL);

	return g_hash_table_lookup (hash, name);
}

typedef struct {
	GHFunc   func;
	gpointer user_data;
} SoupMessageForeachHeaderData;

static void
foreach_value_in_list (gpointer name, gpointer value, gpointer user_data)
{
	GSList *vals = value;
	SoupMessageForeachHeaderData *data = user_data;

	while (vals) {
		(*data->func) (name, vals->data, data->user_data);
		vals = vals->next;
	}
}

void
soup_message_foreach_header (GHashTable *hash, GHFunc func, gpointer user_data)
{
	SoupMessageForeachHeaderData data;

	g_return_if_fail (hash != NULL);
	g_return_if_fail (func != NULL);

	data.func = func;
	data.user_data = user_data;
	g_hash_table_foreach (hash, foreach_value_in_list, &data);
}

void
soup_message_cleanup_response (SoupMessage *req)
{
	if (req->response.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (req->response.body);

	req->response.owner = 0;
	req->response.body = NULL;
	req->response.length = 0;

	free_chunks (req);

	soup_message_clear_headers (req->response_headers);

	req->status_code = 0;
	if (req->reason_phrase) {
		g_free ((char *) req->reason_phrase);
		req->reason_phrase = NULL;
	}
}

void
soup_message_set_flags (SoupMessage *msg, guint flags)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	msg->priv->msg_flags = flags;
}

guint
soup_message_get_flags (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), 0);

	return msg->priv->msg_flags;
}

void
soup_message_set_http_version  (SoupMessage *msg, SoupHttpVersion version)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	msg->priv->http_version = version;
}

SoupHttpVersion
soup_message_get_http_version (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), SOUP_HTTP_1_0);

	return msg->priv->http_version;
}

gboolean
soup_message_is_keepalive (SoupMessage *msg)
{
	const char *c_conn, *s_conn;

	c_conn = soup_message_get_header (msg->request_headers, "Connection");
	s_conn = soup_message_get_header (msg->response_headers, "Connection");

	if (msg->priv->http_version == SOUP_HTTP_1_0) {
		/* Only persistent if the client requested keepalive
		 * and the server agreed.
		 */

		if (!c_conn || !s_conn)
			return FALSE;
		if (g_strcasecmp (c_conn, "Keep-Alive") != 0 ||
		    g_strcasecmp (s_conn, "Keep-Alive") != 0)
			return FALSE;

		return TRUE;
	} else {
		/* Persistent unless either side requested otherwise */

		if (c_conn && g_strcasecmp (c_conn, "close") == 0)
			return FALSE;
		if (s_conn && g_strcasecmp (s_conn, "close") == 0)
			return FALSE;

		return TRUE;
	}
}

void
soup_message_set_uri (SoupMessage *msg, const SoupUri *new_uri)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	if (msg->priv->uri && new_uri) {
		if (strcmp (msg->priv->uri->host, new_uri->host) != 0)
			soup_message_io_cancel (msg);
	} else if (!new_uri)
		soup_message_io_cancel (msg);

	if (msg->priv->uri)
		soup_uri_free (msg->priv->uri);
	msg->priv->uri = soup_uri_copy (new_uri);
}

const SoupUri *
soup_message_get_uri (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	return msg->priv->uri;
}

void
soup_message_set_status (SoupMessage *msg, guint status_code)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (status_code != 0);

	g_free ((char *) msg->reason_phrase);

	msg->status_code = status_code;
	msg->reason_phrase = g_strdup (soup_status_get_phrase (status_code));
}

void
soup_message_set_status_full (SoupMessage *msg,
			      guint        status_code,
			      const char  *reason_phrase)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (status_code != 0);
	g_return_if_fail (reason_phrase != NULL);

	g_free ((char *) msg->reason_phrase);

	msg->status_code = status_code;
	msg->reason_phrase = g_strdup (reason_phrase);
}


void
soup_message_add_chunk (SoupMessage   *msg,
			SoupOwnership  owner,
			const char    *body,
			guint          length)
{
	SoupDataBuffer *chunk;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (body != NULL || length == 0);

	chunk = g_new0 (SoupDataBuffer, 1);
	if (owner == SOUP_BUFFER_USER_OWNED) {
		chunk->owner = SOUP_BUFFER_SYSTEM_OWNED;
		chunk->body = g_memdup (body, length);
	} else {
		chunk->owner = owner;
		chunk->body = (char *)body;
	}
	chunk->length = length;

	if (msg->priv->chunks) {
		g_slist_append (msg->priv->last_chunk, chunk);
		msg->priv->last_chunk = msg->priv->last_chunk->next;
	} else {
		msg->priv->chunks = msg->priv->last_chunk =
			g_slist_append (NULL, chunk);
	}
}

void
soup_message_add_final_chunk (SoupMessage *msg)
{
	soup_message_add_chunk (msg, SOUP_BUFFER_STATIC, NULL, 0);
}

SoupDataBuffer *
soup_message_pop_chunk (SoupMessage *msg)
{
	SoupDataBuffer *chunk;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	if (!msg->priv->chunks)
		return NULL;

	chunk = msg->priv->chunks->data;
	msg->priv->chunks = g_slist_remove (msg->priv->chunks, chunk);
	if (!msg->priv->chunks)
		msg->priv->last_chunk = NULL;

	return chunk;
}

static void
free_chunks (SoupMessage *msg)
{
	SoupDataBuffer *chunk;
	GSList *ch;

	for (ch = msg->priv->chunks; ch; ch = ch->next) {
		chunk = ch->data;

		if (chunk->owner == SOUP_BUFFER_SYSTEM_OWNED)
			g_free (chunk->body);
		g_free (chunk);
	}

	g_slist_free (msg->priv->chunks);
	msg->priv->chunks = msg->priv->last_chunk = NULL;
}
