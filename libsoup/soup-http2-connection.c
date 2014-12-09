/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-http2-connection.c
 *
 * Copyright 2014 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <nghttp2/nghttp2.h>

#include "soup-http2-connection.h"

G_DEFINE_TYPE (SoupHTTP2Connection, soup_http2_connection, G_TYPE_OBJECT)

typedef struct {
	nghttp2_session *session;

	GInputStream *istream;
	GPollableInputStream *poll_istream;
	GOutputStream *ostream;
	GPollableOutputStream *poll_ostream;

} SoupHTTP2ConnectionPrivate;
#define SOUP_HTTP2_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HTTP2_CONNECTION, SoupHTTP2ConnectionPrivate))

static ssize_t
ngh2_send_cb (nghttp2_session *session,
	      const uint8_t *data, size_t length,
	      int flags, void *conn)
{
	SoupHTTP2ConnectionPrivate *priv = SOUP_HTTP2_CONNECTION_GET_PRIVATE (conn);
	gssize nwrote;
	GError *error = NULL;

	nwrote = g_pollable_output_stream_write_nonblocking (priv->ostream,
							     buf, length,
							     NULL, &error);
	if (nwrote == -1) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
			g_error_free (error);
			return NGHTTP2_ERR_WOULDBLOCK;
		}
		g_error_free (error);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	} else
		return nread;
}

static ssize_t
ngh_recv_cb (nghttp2_session *session,
	     uint8_t *buf, size_t length,
	     int flags, void *conn)
{
	SoupHTTP2ConnectionPrivate *priv = SOUP_HTTP2_CONNECTION_GET_PRIVATE (conn);
	gssize nread;
	GError *error = NULL;

	nread = g_pollable_input_stream_read_nonblocking (priv->istream,
							  buf, length,
							  NULL, &error);
	if (nread == -1) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
			g_error_free (error);
			return NGHTTP2_ERR_WOULDBLOCK;
		}
		g_error_free (error);
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	} else if (nread == 0)
		return NGHTTP2_ERR_EOF;
	else
		return nread;
}

static int
ngh2_data_chunk_recv_cb (nghttp2_session *session, uint8_t flags,
			 int32_t stream_id, const uint8_t *data, size_t len,
			 void *conn)
{
	SoupHTTP2ConnectionPrivate *priv = SOUP_HTTP2_CONNECTION_GET_PRIVATE (conn);
	SoupHTTP2Channel *channel;

	channel = g_hash_table_lookup (priv->channels, GINT_TO_POINTER (stream_id));
	if (!channel)
		return -1;

	soup_http2_channel_push_data (channel, data, len);
	return 0;
}

static int
ngh2_stream_close_cb (nghttp2_session *session,
		      int32_t stream_id, uint32_t error_code,
		      void *conn)
{
	SoupHTTP2ConnectionPrivate *priv = SOUP_HTTP2_CONNECTION_GET_PRIVATE (conn);
	SoupHTTP2Channel *channel;

	channel = g_hash_table_lookup (priv->channels, GINT_TO_POINTER (stream_id));
	if (channel) {
		soup_http2_channel_input_closed (channel, error_code);
		if (soup_http2_channel_get_output_closed (channel))
			g_hash_table_remove (GINT_TO_POINTER (stream_id));
	}
	return 0;
}

static int
ngh2_begin_headers_cb (nghttp2_session *session,
		       const nghttp2_frame *frame,
		       void *conn)
{
	SoupHTTP2ConnectionPrivate *priv = SOUP_HTTP2_CONNECTION_GET_PRIVATE (conn);
	SoupHTTP2Channel *channel;

	channel = g_hash_table_lookup (priv->channels, GINT_TO_POINTER (stream_id));
	if (channel)
		return -1;

	if (frame->hd.type != NGHTTP2_HEADERS)
		return -1;

	channel = soup_http2_channel_new (conn, frame->hd.stream_id);
	g_hash_table_insert (priv->channels, GINT_TO_POINTER (frame->hd.stream_id), channel);
	return 0
}

static int
ngh2_on_header_cb (nghttp2_session *session, const nghttp2_frame *frame,
		   const uint8_t *name, size_t namelen,
		   const uint8_t *value, size_t valuelen,
		   uint8_t flags, void *conn)
{
	SoupHTTP2ConnectionPrivate *priv = SOUP_HTTP2_CONNECTION_GET_PRIVATE (conn);
	SoupHTTP2Channel *channel;

	channel = g_hash_table_lookup (priv->channels, GINT_TO_POINTER (stream_id));
	if (!channel)
		return -1;

	if (soup_http2_channel_get_headers_complete (channel))
		return 0;

	if (!nghttp2_check_header_value (value, valuelen))
		return -1;
	if (namelen == 0 ||
	    (name[0] == ':' && !nghttp2_check_header_name (name + 1, namelen - 1)) ||
	    (name[0] != ':' && !nghttp2_check_header_name (name, namelen)))
		return -1;

	soup_http2_channel_push_header (channel,
					name, namelen,
					value, valuelen);
	return 0;
}

static int
ngh2_frame_recv_cb (nghttp2_session *session,
		    const nghttp2_frame *frame,
		    void *conn)
{
	SoupHTTP2ConnectionPrivate *priv = SOUP_HTTP2_CONNECTION_GET_PRIVATE (conn);
	SoupHTTP2Channel *channel;

	if (frame->hd.type != NGHTTP2_HEADERS)
		return 0;

	channel = g_hash_table_lookup (priv->channels, GINT_TO_POINTER (stream_id));
	if (!channel)
		return 0;

	soup_http2_channel_set_headers_complete (channel);
	return 0;
}

static void
 soup_http2_connection_init (SoupHTTP2Connection *connection)
{
	SoupHTTP2ConnectionPrivate *priv = SOUP_HTTP2_CONNECTION_GET_PRIVATE (connection);
	nghttp2_session_callbacks *callbacks;

	priv->channels = g_hash_table_new_full (NULL, NULL, NULL, g_object_unref);

	nghttp2_session_callbacks_new (&callbacks);
	nghttp2_session_callbacks_set_send_callback (callbacks, ngh2_send_cb);
	nghttp2_session_callbacks_set_recv_callback (callbacks, ngh2_recv_cb);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback (callbacks, ngh2_data_chunk_recv_cb);
	nghttp2_session_callbacks_set_on_stream_close_callback (callbacks, ngh2_stream_close_cb);
	nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, ngh2_begin_headers_cb);
	nghttp2_session_callbacks_set_on_header_callback (callbacks, ngh2_header_cb);
	nghttp2_session_callbacks_set_on_frame_recv_callback (callbacks, ngh2_frame_recv_cb);

	nghttp2_session_client_new (&priv->session, callbacks, connection);
	nghttp2_session_callbacks_del (callbacks);
}

static void
soup_http2_connection_run (SoupHTTP2Connection *conn)
{
	SoupHTTP2ConnectionPrivate *priv = SOUP_HTTP2_CONNECTION_GET_PRIVATE (connection);
	GSource *in, *out;
	GMainContext *ctx;
	GMainLoop *loop;
	int status;

	ctx = g_main_context_new ();
	g_main_context_push_thread_default (ctx);
	loop = g_main_loop_new (ctx, FALSE);

	in = g_pollable_input_stream_create_source (priv->istream, NULL);
	g_source_set_callback (in, (GSourceFunc) quit_callback, loop);
	g_source_attach (in, ctx);

	out = g_pollable_output_stream_create_source (priv->ostream, NULL);
	g_source_set_callback (out, (GSourceFunc) quit_callback, loop);
	g_source_attach (out, ctx);

	while (TRUE) {
		if (g_pollable_output_stream_is_writable (priv->ostream)) {
			status = nghttp2_session_send (priv->session);
			if (status != 0)
				break;
		}
		if (g_pollable_input_stream_is_readable (priv->ostream)) {
			status = nghttp2_session_recv (priv->session);
			if (status != 0)
				break;
		}

		if (!nghttp2_session_want_read (priv->session) &&
		    !nghttp2_session_want_write (priv->session))
			break;

		g_main_loop_run (loop);
	}

	g_source_destroy (in);
	g_source_unref (in);
	g_source_destroy (out);
	g_source_unref (out);

	g_main_loop_unref (loop);
	g_main_context_pop_thread_default (ctx);
	g_main_context_unref (ctx);
}

