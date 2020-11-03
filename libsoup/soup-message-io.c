/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-io.c: HTTP message I/O
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib/gi18n-lib.h>

#ifdef HAVE_SYSPROF
#include <sysprof-capture.h>
#endif

#include "soup.h"
#include "soup-body-input-stream.h"
#include "soup-body-output-stream.h"
#include "soup-client-input-stream.h"
#include "soup-connection.h"
#include "content-sniffer/soup-content-processor.h"
#include "content-sniffer/soup-content-sniffer-stream.h"
#include "soup-filter-input-stream.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-misc.h"

struct _SoupClientMessageIOData {
	SoupMessageIOData base;

        SoupMessageQueueItem *item;
        GCancellable         *cancellable;

#ifdef HAVE_SYSPROF
        gint64 begin_time_nsec;
#endif
};

#define RESPONSE_BLOCK_SIZE 8192
#define HEADER_SIZE_LIMIT (64 * 1024)

void
soup_client_message_io_data_free (SoupClientMessageIOData *io)
{
	if (!io)
		return;

	soup_message_io_data_cleanup (&io->base);
	soup_message_queue_item_unref (io->item);

	g_slice_free (SoupClientMessageIOData, io);
}

static int
soup_client_message_io_data_get_priority (SoupClientMessageIOData *io)
{
	if (!io->item->task)
		return G_PRIORITY_DEFAULT;

	return g_task_get_priority (io->item->task);
}

void
soup_message_io_finished (SoupMessage *msg)
{
	SoupClientMessageIOData *io;
	SoupMessageIOCompletionFn completion_cb;
	gpointer completion_data;
	SoupMessageIOCompletion completion;

	io = soup_message_get_io_data (msg);
	if (!io)
		return;

	completion_cb = io->base.completion_cb;
	completion_data = io->base.completion_data;

	if ((io->base.read_state >= SOUP_MESSAGE_IO_STATE_FINISHING &&
	     io->base.write_state >= SOUP_MESSAGE_IO_STATE_FINISHING))
		completion = SOUP_MESSAGE_IO_COMPLETE;
	else
		completion = SOUP_MESSAGE_IO_INTERRUPTED;

	g_object_ref (msg);
	soup_message_set_io_data (msg, NULL);
	if (completion_cb)
		completion_cb (G_OBJECT (msg), completion, completion_data);
	g_object_unref (msg);
}

void
soup_message_io_stolen (SoupMessage *msg)
{
	SoupClientMessageIOData *io;
	SoupMessageIOCompletionFn completion_cb;
	gpointer completion_data;

	io = soup_message_get_io_data (msg);
	if (!io)
		return;

	completion_cb = io->base.completion_cb;
	completion_data = io->base.completion_data;

	g_object_ref (msg);
	soup_message_set_io_data (msg, NULL);
	if (completion_cb)
		completion_cb (G_OBJECT (msg), SOUP_MESSAGE_IO_STOLEN, completion_data);
	g_object_unref (msg);
}

static gint
processing_stage_cmp (gconstpointer a,
                      gconstpointer b)
{
	SoupProcessingStage stage_a = soup_content_processor_get_processing_stage (SOUP_CONTENT_PROCESSOR ((gpointer)a));
	SoupProcessingStage stage_b = soup_content_processor_get_processing_stage (SOUP_CONTENT_PROCESSOR ((gpointer)b));

	if (stage_a > stage_b)
		return 1;
	if (stage_a == stage_b)
		return 0;
	return -1;
}

GInputStream *
soup_message_setup_body_istream (GInputStream *body_stream,
				 SoupMessage *msg,
				 SoupSession *session,
				 SoupProcessingStage start_at_stage)
{
	GInputStream *istream;
	GSList *p, *processors;

	istream = g_object_ref (body_stream);

	processors = soup_session_get_features (session, SOUP_TYPE_CONTENT_PROCESSOR);
	processors = g_slist_sort (processors, processing_stage_cmp);

	for (p = processors; p; p = p->next) {
		GInputStream *wrapper;
		SoupContentProcessor *processor;

		processor = SOUP_CONTENT_PROCESSOR (p->data);
		if (soup_message_disables_feature (msg, p->data) ||
		    soup_content_processor_get_processing_stage (processor) < start_at_stage)
			continue;

		wrapper = soup_content_processor_wrap_input (processor, istream, msg, NULL);
		if (wrapper) {
			g_object_unref (istream);
			istream = wrapper;
		}
	}

	g_slist_free (processors);

	return istream;
}

static void
request_body_stream_wrote_data_cb (SoupMessage *msg,
				   guint        count)
{
	soup_message_wrote_body_data (msg, count);
}

static void
request_body_stream_wrote_cb (GOutputStream *ostream,
			      GAsyncResult  *result,
			      SoupMessage   *msg)
{
	SoupClientMessageIOData *io;
	gssize nwrote;
	GCancellable *async_wait;
	GError *error = NULL;

	nwrote = g_output_stream_splice_finish (ostream, result, &error);

	io = soup_message_get_io_data (msg);
	if (!io || !io->base.async_wait || io->base.body_ostream != ostream) {
		g_clear_error (&error);
		g_object_unref (msg);
		return;
	}

	if (nwrote != -1)
		io->base.write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;

	if (error)
		g_propagate_error (&io->base.async_error, error);
	async_wait = io->base.async_wait;
	io->base.async_wait = NULL;
	g_cancellable_cancel (async_wait);
	g_object_unref (async_wait);

	g_object_unref (msg);
}

static void
closed_async (GObject      *source,
	      GAsyncResult *result,
	      gpointer      user_data)
{
	GOutputStream *body_ostream = G_OUTPUT_STREAM (source);
	SoupMessage *msg = user_data;
	SoupClientMessageIOData *io;
	GCancellable *async_wait;

	io = soup_message_get_io_data (msg);
	if (!io || !io->base.async_wait || io->base.body_ostream != body_ostream) {
		g_object_unref (msg);
		return;
	}

	g_output_stream_close_finish (body_ostream, result, &io->base.async_error);
	g_clear_object (&io->base.body_ostream);

	async_wait = io->base.async_wait;
	io->base.async_wait = NULL;
	g_cancellable_cancel (async_wait);
	g_object_unref (async_wait);

	g_object_unref (msg);
}

/*
 * There are two request/response formats: the basic request/response,
 * possibly with one or more unsolicited informational responses (such
 * as the WebDAV "102 Processing" response):
 *
 *     Client                            Server
 *      W:HEADERS  / R:NOT_STARTED    ->  R:HEADERS  / W:NOT_STARTED
 *      W:BODY     / R:NOT_STARTED    ->  R:BODY     / W:NOT_STARTED
 *     [W:DONE     / R:HEADERS (1xx)  <-  R:DONE     / W:HEADERS (1xx) ...]
 *      W:DONE     / R:HEADERS        <-  R:DONE     / W:HEADERS
 *      W:DONE     / R:BODY           <-  R:DONE     / W:BODY
 *      W:DONE     / R:DONE               R:DONE     / W:DONE
 *     
 * and the "Expect: 100-continue" request/response, with the client
 * blocking halfway through its request, and then either continuing or
 * aborting, depending on the server response:
 *
 *     Client                            Server
 *      W:HEADERS  / R:NOT_STARTED    ->  R:HEADERS  / W:NOT_STARTED
 *      W:BLOCKING / R:HEADERS        <-  R:BLOCKING / W:HEADERS
 *     [W:BODY     / R:BLOCKING       ->  R:BODY     / W:BLOCKING]
 *     [W:DONE     / R:HEADERS        <-  R:DONE     / W:HEADERS]
 *      W:DONE     / R:BODY           <-  R:DONE     / W:BODY
 *      W:DONE     / R:DONE               R:DONE     / W:DONE
 */

static void
write_headers (SoupMessage          *msg,
	       GString              *header,
	       SoupConnection       *conn,
	       SoupEncoding         *encoding)
{
	SoupURI *uri = soup_message_get_uri (msg);
	char *uri_host;
	char *uri_string;
	SoupMessageHeadersIter iter;
	const char *name, *value;

	if (strchr (uri->host, ':'))
		uri_host = g_strdup_printf ("[%.*s]", (int) strcspn (uri->host, "%"), uri->host);
	else if (g_hostname_is_non_ascii (uri->host))
		uri_host = g_hostname_to_ascii (uri->host);
	else
		uri_host = uri->host;

	if (soup_message_get_method (msg) == SOUP_METHOD_CONNECT) {
		/* CONNECT URI is hostname:port for tunnel destination */
		uri_string = g_strdup_printf ("%s:%d", uri_host, uri->port);
	} else {
		gboolean proxy = soup_connection_is_via_proxy (conn);

		/* Proxy expects full URI to destination. Otherwise
		 * just the path.
		 */
		uri_string = soup_uri_to_string (uri, !proxy);

		if (proxy && uri->fragment) {
			/* Strip fragment */
			char *fragment = strchr (uri_string, '#');
			if (fragment)
				*fragment = '\0';
		}
	}

	g_string_append_printf (header, "%s %s HTTP/1.%d\r\n",
				soup_message_get_method (msg), uri_string,
				(soup_message_get_http_version (msg) == SOUP_HTTP_1_0) ? 0 : 1);

	if (!soup_message_headers_get_one (soup_message_get_request_headers (msg), "Host")) {
		if (soup_uri_uses_default_port (uri)) {
			g_string_append_printf (header, "Host: %s\r\n",
						uri_host);
		} else {
			g_string_append_printf (header, "Host: %s:%d\r\n",
						uri_host, uri->port);
		}
	}
	g_free (uri_string);
	if (uri_host != uri->host)
		g_free (uri_host);

	*encoding = soup_message_headers_get_encoding (soup_message_get_request_headers (msg));

	soup_message_headers_iter_init (&iter, soup_message_get_request_headers (msg));
	while (soup_message_headers_iter_next (&iter, &name, &value))
		g_string_append_printf (header, "%s: %s\r\n", name, value);
	g_string_append (header, "\r\n");
}

/* Attempts to push forward the writing side of @msg's I/O. Returns
 * %TRUE if it manages to make some progress, and it is likely that
 * further progress can be made. Returns %FALSE if it has reached a
 * stopping point of some sort (need input from the application,
 * socket not writable, write is complete, etc).
 */
static gboolean
io_write (SoupMessage *msg, gboolean blocking,
	  GCancellable *cancellable, GError **error)
{
	SoupClientMessageIOData *client_io = soup_message_get_io_data (msg);
	SoupMessageIOData *io = &client_io->base;
	gssize nwrote;

	if (io->async_error) {
		g_propagate_error (error, io->async_error);
		io->async_error = NULL;
		return FALSE;
	} else if (io->async_wait) {
		g_set_error_literal (error, G_IO_ERROR,
				     G_IO_ERROR_WOULD_BLOCK,
				     _("Operation would block"));
		return FALSE;
	}

	switch (io->write_state) {
	case SOUP_MESSAGE_IO_STATE_HEADERS:
		if (!io->write_buf->len)
			write_headers (msg, io->write_buf, client_io->item->conn, &io->write_encoding);

		while (io->written < io->write_buf->len) {
			nwrote = g_pollable_stream_write (io->ostream,
							  io->write_buf->str + io->written,
							  io->write_buf->len - io->written,
							  blocking,
							  cancellable, error);
			if (nwrote == -1)
				return FALSE;
			io->written += nwrote;
		}

		io->written = 0;
		g_string_truncate (io->write_buf, 0);

		if (io->write_encoding == SOUP_ENCODING_CONTENT_LENGTH)
			io->write_length = soup_message_headers_get_content_length (soup_message_get_request_headers (msg));

		if (soup_message_headers_get_expectations (soup_message_get_request_headers (msg)) & SOUP_EXPECTATION_CONTINUE) {
			/* Need to wait for the Continue response */
			io->write_state = SOUP_MESSAGE_IO_STATE_BLOCKING;
			io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
		} else
			io->write_state = SOUP_MESSAGE_IO_STATE_BODY_START;

		soup_message_wrote_headers (msg);
		break;

	case SOUP_MESSAGE_IO_STATE_BODY_START:
		io->body_ostream = soup_body_output_stream_new (io->ostream,
								io->write_encoding,
								io->write_length);
		io->write_state = SOUP_MESSAGE_IO_STATE_BODY;
		break;

	case SOUP_MESSAGE_IO_STATE_BODY:
		if (!io->write_length &&
		    io->write_encoding != SOUP_ENCODING_EOF &&
		    io->write_encoding != SOUP_ENCODING_CHUNKED) {
			io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
			break;
		}

		if (soup_message_get_request_body_stream (msg)) {
			g_signal_connect_object (io->body_ostream,
						 "wrote-data",
						 G_CALLBACK (request_body_stream_wrote_data_cb),
						 msg, G_CONNECT_SWAPPED);
			if (blocking) {
				nwrote = g_output_stream_splice (io->body_ostream,
								 soup_message_get_request_body_stream (msg),
								 G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE,
								 cancellable,
								 error);
				if (nwrote == -1)
					return FALSE;
				io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
				break;
			} else {
				io->async_wait = g_cancellable_new ();
				g_main_context_push_thread_default (io->async_context);
				g_output_stream_splice_async (io->body_ostream,
							      soup_message_get_request_body_stream (msg),
							      G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE,
							      soup_client_message_io_data_get_priority (client_io),
							      cancellable,
							      (GAsyncReadyCallback)request_body_stream_wrote_cb,
							      g_object_ref (msg));
				g_main_context_pop_thread_default (io->async_context);
				return FALSE;
			}
		} else
			io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
		break;

	case SOUP_MESSAGE_IO_STATE_BODY_FLUSH:
		if (io->body_ostream) {
			if (blocking || io->write_encoding != SOUP_ENCODING_CHUNKED) {
				if (!g_output_stream_close (io->body_ostream, cancellable, error))
					return FALSE;
				g_clear_object (&io->body_ostream);
			} else {
				io->async_wait = g_cancellable_new ();
				g_main_context_push_thread_default (io->async_context);
				g_output_stream_close_async (io->body_ostream,
							     soup_client_message_io_data_get_priority (client_io),
							     cancellable,
							     closed_async, g_object_ref (msg));
				g_main_context_pop_thread_default (io->async_context);
			}
		}

		io->write_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;
		break;

	case SOUP_MESSAGE_IO_STATE_BODY_DONE:
		io->write_state = SOUP_MESSAGE_IO_STATE_FINISHING;
		soup_message_wrote_body (msg);
		break;

	case SOUP_MESSAGE_IO_STATE_FINISHING:
		io->write_state = SOUP_MESSAGE_IO_STATE_DONE;
		io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
		break;

	default:
		g_return_val_if_reached (FALSE);
	}

	return TRUE;
}

static guint
parse_headers (SoupMessage  *msg,
	       char         *headers,
	       guint         headers_len,
	       SoupEncoding *encoding,
	       GError      **error)
{
	SoupHTTPVersion version;
        char *reason_phrase;
        SoupStatus status;

        soup_message_set_reason_phrase (msg, NULL);

	if (!soup_headers_parse_response (headers, headers_len,
					  soup_message_get_response_headers (msg),
					  &version,
					  &status,
					  &reason_phrase)) {
		g_set_error_literal (error, SOUP_SESSION_ERROR,
				     SOUP_SESSION_ERROR_PARSING,
				     _("Could not parse HTTP response"));
		return SOUP_STATUS_MALFORMED;
	}

        soup_message_set_status_full (msg, status, reason_phrase);
        g_free (reason_phrase);

	if (version < soup_message_get_http_version (msg))
		soup_message_set_http_version (msg, version);

	if ((soup_message_get_method (msg) == SOUP_METHOD_HEAD ||
	     soup_message_get_status (msg)  == SOUP_STATUS_NO_CONTENT ||
	     soup_message_get_status (msg)  == SOUP_STATUS_NOT_MODIFIED ||
	     SOUP_STATUS_IS_INFORMATIONAL (soup_message_get_status (msg))) ||
	    (soup_message_get_method (msg) == SOUP_METHOD_CONNECT &&
	     SOUP_STATUS_IS_SUCCESSFUL (soup_message_get_status (msg))))
		*encoding = SOUP_ENCODING_NONE;
	else
		*encoding = soup_message_headers_get_encoding (soup_message_get_response_headers (msg));

	if (*encoding == SOUP_ENCODING_UNRECOGNIZED) {
		g_set_error_literal (error, SOUP_SESSION_ERROR,
				     SOUP_SESSION_ERROR_ENCODING,
				     _("Unrecognized HTTP response encoding"));
		return SOUP_STATUS_MALFORMED;
	}

	return SOUP_STATUS_OK;
}

/* Attempts to push forward the reading side of @msg's I/O. Returns
 * %TRUE if it manages to make some progress, and it is likely that
 * further progress can be made. Returns %FALSE if it has reached a
 * stopping point of some sort (need input from the application,
 * socket not readable, read is complete, etc).
 */
static gboolean
io_read (SoupMessage *msg, gboolean blocking,
	 GCancellable *cancellable, GError **error)
{
	SoupClientMessageIOData *client_io = soup_message_get_io_data (msg);
	SoupMessageIOData *io = &client_io->base;
	guint status;

	switch (io->read_state) {
	case SOUP_MESSAGE_IO_STATE_HEADERS:
		if (!soup_message_io_data_read_headers (io, blocking, cancellable, error)) {
			if (g_error_matches (*error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT))
                                soup_message_set_status (msg, SOUP_STATUS_MALFORMED);
			return FALSE;
		}

		status = parse_headers (msg,
					(char *)io->read_header_buf->data,
					io->read_header_buf->len,
					&io->read_encoding,
					error);
		g_byte_array_set_size (io->read_header_buf, 0);

		if (status != SOUP_STATUS_OK) {
			/* Either we couldn't parse the headers, or they
			 * indicated something that would mean we wouldn't
			 * be able to parse the body. (Eg, unknown
			 * Transfer-Encoding.). Skip the rest of the
			 * reading, and make sure the connection gets
			 * closed when we're done.
			 */
			soup_message_set_status (msg, status);
			soup_message_headers_append (soup_message_get_request_headers (msg),
						     "Connection", "close");
			io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
			break;
		}

		if (SOUP_STATUS_IS_INFORMATIONAL (soup_message_get_status (msg))) {
			if (soup_message_get_status (msg) == SOUP_STATUS_CONTINUE &&
			    io->write_state == SOUP_MESSAGE_IO_STATE_BLOCKING) {
				/* Pause the reader, unpause the writer */
				io->read_state =
					SOUP_MESSAGE_IO_STATE_BLOCKING;
				io->write_state =
					SOUP_MESSAGE_IO_STATE_BODY_START;
			} else {
				/* Just stay in HEADERS */
				io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
			}

			/* Informational responses have no bodies, so
			 * bail out here rather than parsing encoding, etc
			 */
			soup_message_got_informational (msg);

			/* If this was "101 Switching Protocols", then
			 * the session may have stolen the connection...
			 */
			if (client_io != soup_message_get_io_data (msg))
				return FALSE;

			soup_message_cleanup_response (msg);
			break;
		} else {
			io->read_state = SOUP_MESSAGE_IO_STATE_BODY_START;

			/* If the client was waiting for a Continue
			 * but got something else, then it's done
			 * writing.
			 */
			if (io->write_state == SOUP_MESSAGE_IO_STATE_BLOCKING)
				io->write_state = SOUP_MESSAGE_IO_STATE_FINISHING;
		}

		if (io->read_encoding == SOUP_ENCODING_CONTENT_LENGTH) {
			io->read_length = soup_message_headers_get_content_length (soup_message_get_response_headers (msg));

			if (!soup_message_is_keepalive (msg)) {
				/* Some servers suck and send
				 * incorrect Content-Length values, so
				 * allow EOF termination in this case
				 * (iff the message is too short) too.
				 */
				io->read_encoding = SOUP_ENCODING_EOF;
			}
		} else
			io->read_length = -1;

		soup_message_got_headers (msg);
		break;

	case SOUP_MESSAGE_IO_STATE_BODY_START:
		if (!io->body_istream) {
			GInputStream *body_istream = soup_body_input_stream_new (G_INPUT_STREAM (io->istream),
										 io->read_encoding,
										 io->read_length);

			io->body_istream = soup_message_setup_body_istream (body_istream, msg,
									    client_io->item->session,
									    SOUP_STAGE_MESSAGE_BODY);
			g_object_unref (body_istream);
		}

		if (soup_message_get_content_sniffer (msg)) {
			SoupContentSnifferStream *sniffer_stream = SOUP_CONTENT_SNIFFER_STREAM (io->body_istream);
			const char *content_type;
			GHashTable *params;

			if (!soup_content_sniffer_stream_is_ready (sniffer_stream, blocking,
								   cancellable, error))
				return FALSE;

			content_type = soup_content_sniffer_stream_sniff (sniffer_stream, &params);
			soup_message_content_sniffed (msg, content_type, params);
		}

		io->read_state = SOUP_MESSAGE_IO_STATE_BODY;
		break;

	case SOUP_MESSAGE_IO_STATE_BODY: {
                guchar buf[RESPONSE_BLOCK_SIZE];
		gssize nread;

		nread = g_pollable_stream_read (io->body_istream,
						buf,
						RESPONSE_BLOCK_SIZE,
						blocking,
						cancellable, error);
		if (nread == -1)
			return FALSE;

		if (nread == 0)
			io->read_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;

		break;
	}

	case SOUP_MESSAGE_IO_STATE_BODY_DONE:
		io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
		soup_message_got_body (msg);
		break;

	case SOUP_MESSAGE_IO_STATE_FINISHING:
		io->read_state = SOUP_MESSAGE_IO_STATE_DONE;
		break;

	default:
		g_return_val_if_reached (FALSE);
	}

	return TRUE;
}

static gboolean
request_is_restartable (SoupMessage *msg, GError *error)
{
	SoupClientMessageIOData *client_io = soup_message_get_io_data (msg);
	SoupMessageIOData *io = &client_io->base;

	if (!client_io)
		return FALSE;

	return (io->read_state <= SOUP_MESSAGE_IO_STATE_HEADERS &&
		io->read_header_buf->len == 0 &&
		soup_connection_get_ever_used (client_io->item->conn) &&
		!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT) &&
		!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) &&
		error->domain != G_TLS_ERROR &&
		SOUP_METHOD_IS_IDEMPOTENT (soup_message_get_method (msg)));
}

static gboolean
io_run_until (SoupMessage *msg, gboolean blocking,
	      SoupMessageIOState read_state, SoupMessageIOState write_state,
	      GCancellable *cancellable, GError **error)
{
	SoupClientMessageIOData *client_io = soup_message_get_io_data (msg);
	SoupMessageIOData *io = &client_io->base;
	gboolean progress = TRUE, done;
	GError *my_error = NULL;

	if (g_cancellable_set_error_if_cancelled (cancellable, error))
		return FALSE;
	else if (!io) {
		g_set_error_literal (error, G_IO_ERROR,
				     G_IO_ERROR_CANCELLED,
				     _("Operation was cancelled"));
		return FALSE;
	}

	g_object_ref (msg);

	while (progress && soup_message_get_io_data (msg) == client_io && !io->paused && !io->async_wait &&
	       (io->read_state < read_state || io->write_state < write_state)) {

		if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->read_state))
			progress = io_read (msg, blocking, cancellable, &my_error);
		else if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->write_state))
			progress = io_write (msg, blocking, cancellable, &my_error);
		else
			progress = FALSE;
	}

	if (my_error) {
		if (request_is_restartable (msg, my_error)) {
			/* Connection got closed, but we can safely try again */
			g_error_free (my_error);
			g_set_error_literal (error, SOUP_HTTP_ERROR,
					     SOUP_STATUS_TRY_AGAIN, "");
			g_object_unref (msg);
			return FALSE;
		}

		g_propagate_error (error, my_error);
		g_object_unref (msg);
		return FALSE;
	} else if (soup_message_get_io_data (msg) != client_io) {
		g_set_error_literal (error, G_IO_ERROR,
				     G_IO_ERROR_CANCELLED,
				     _("Operation was cancelled"));
		g_object_unref (msg);
		return FALSE;
	} else if (!io->async_wait &&
		   g_cancellable_set_error_if_cancelled (cancellable, error)) {
		g_object_unref (msg);
		return FALSE;
	}

	done = (io->read_state >= read_state &&
		io->write_state >= write_state);

	if (!blocking && !done) {
		g_set_error_literal (error, G_IO_ERROR,
				     G_IO_ERROR_WOULD_BLOCK,
				     _("Operation would block"));
		g_object_unref (msg);
		return FALSE;
	}

#ifdef HAVE_SYSPROF
	/* Allow profiling of network requests. */
	if (io->read_state == SOUP_MESSAGE_IO_STATE_DONE &&
	    io->write_state == SOUP_MESSAGE_IO_STATE_DONE) {
		SoupURI *uri = soup_message_get_uri (msg);
		char *uri_str = soup_uri_to_string (uri, FALSE);
		const gchar *last_modified = soup_message_headers_get_one (soup_message_get_request_headers (msg), "Last-Modified");
		const gchar *etag = soup_message_headers_get_one (soup_message_get_request_headers (msg), "ETag");

		/* FIXME: Expand and generalise sysprof support:
		 * https://gitlab.gnome.org/GNOME/sysprof/-/issues/43 */
		sysprof_collector_mark_printf (client_io->begin_time_nsec,
					       SYSPROF_CAPTURE_CURRENT_TIME - client_io->begin_time_nsec,
					       "libsoup", "message",
					       "%s request/response to %s: "
					       "read %" G_GOFFSET_FORMAT "B, "
					       "wrote %" G_GOFFSET_FORMAT "B, "
					       "Last-Modified: %s, "
					       "ETag: %s",
					       soup_message_get_tls_certificate (msg) ? "HTTPS" : "HTTP",
					       uri_str, io->read_length, io->write_length,
					       (last_modified != NULL) ? last_modified : "(unset)",
					       (etag != NULL) ? etag : "(unset)");
		g_free (uri_str);
	}
#endif  /* HAVE_SYSPROF */

	g_object_unref (msg);
	return done;
}

static void
soup_message_io_update_status (SoupMessage  *msg,
			       GError       *error)
{
	if (g_error_matches (error, SOUP_HTTP_ERROR, SOUP_STATUS_TRY_AGAIN)) {
		SoupClientMessageIOData *io = soup_message_get_io_data (msg);

		io->item->state = SOUP_MESSAGE_RESTARTING;
	} else if (error->domain == G_TLS_ERROR) {
		soup_message_set_status_full (msg,
					      SOUP_STATUS_SSL_FAILED,
					      error->message);
	} else if (!SOUP_STATUS_IS_TRANSPORT_ERROR (soup_message_get_status (msg)) &&
		   !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		soup_message_set_status (msg, SOUP_STATUS_IO_ERROR);
	}

	soup_message_io_finished (msg);
}

static gboolean
io_run_ready (SoupMessage *msg, gpointer user_data)
{
	soup_message_io_run (msg, FALSE);
	return FALSE;
}

void
soup_message_io_run (SoupMessage *msg,
		     gboolean     blocking)
{
	SoupClientMessageIOData *client_io = soup_message_get_io_data (msg);
	SoupMessageIOData *io = &client_io->base;
	GError *error = NULL;
	GCancellable *cancellable;

	if (io->io_source) {
		g_source_destroy (io->io_source);
		g_source_unref (io->io_source);
		io->io_source = NULL;
	}

	g_object_ref (msg);
	cancellable = client_io->cancellable ? g_object_ref (client_io->cancellable) : NULL;

	if (io_run_until (msg, blocking,
			  SOUP_MESSAGE_IO_STATE_DONE,
			  SOUP_MESSAGE_IO_STATE_DONE,
			  cancellable, &error)) {
		soup_message_io_finished (msg);
	} else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_clear_error (&error);
		io->io_source = soup_message_io_data_get_source (io, G_OBJECT (msg), NULL,
								 (SoupMessageIOSourceFunc)io_run_ready,
								 NULL);
		g_source_set_priority (io->io_source,
				       soup_client_message_io_data_get_priority (client_io));
		g_source_attach (io->io_source, io->async_context);
	} else {
		if (soup_message_get_io_data (msg) == client_io)
			soup_message_io_update_status (msg, error);
		g_error_free (error);

	}

	g_object_unref (msg);
	g_clear_object (&cancellable);
}

gboolean
soup_message_io_run_until_read (SoupMessage  *msg,
				GCancellable *cancellable,
				GError      **error)
{
	SoupClientMessageIOData *io = soup_message_get_io_data (msg);

	if (io_run_until (msg, TRUE,
			  SOUP_MESSAGE_IO_STATE_BODY,
			  SOUP_MESSAGE_IO_STATE_ANY,
			  cancellable, error))
		return TRUE;

	if (soup_message_get_io_data (msg) == io)
		soup_message_io_update_status (msg, *error);

	return FALSE;
}

static void io_run_until_read_async (SoupMessage *msg,
                                     GTask       *task);

static gboolean
io_run_until_read_ready (SoupMessage *msg,
                         gpointer     user_data)
{
        GTask *task = user_data;

        io_run_until_read_async (msg, task);
        return FALSE;
}

static void
io_run_until_read_async (SoupMessage *msg,
                         GTask       *task)
{
        SoupClientMessageIOData *client_io = soup_message_get_io_data (msg);
	SoupMessageIOData *io = &client_io->base;
        GError *error = NULL;

        if (io->io_source) {
                g_source_destroy (io->io_source);
                g_source_unref (io->io_source);
                io->io_source = NULL;
        }

        if (io_run_until (msg, FALSE,
                          SOUP_MESSAGE_IO_STATE_BODY,
                          SOUP_MESSAGE_IO_STATE_ANY,
                          g_task_get_cancellable (task),
                          &error)) {
                g_task_return_boolean (task, TRUE);
                g_object_unref (task);
                return;
        }

        if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_error_free (error);
                io->io_source = soup_message_io_data_get_source (io, G_OBJECT (msg), NULL,
								 (SoupMessageIOSourceFunc)io_run_until_read_ready,
								 task);
		g_source_set_priority (io->io_source, g_task_get_priority (task));
                g_source_attach (io->io_source, io->async_context);
                return;
        }

        if (soup_message_get_io_data (msg) == client_io)
                soup_message_io_update_status (msg, error);

        g_task_return_error (task, error);
        g_object_unref (task);
}

void
soup_message_io_run_until_read_async (SoupMessage        *msg,
				      int                 io_priority,
                                      GCancellable       *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer            user_data)
{
        GTask *task;

        task = g_task_new (msg, cancellable, callback, user_data);
	g_task_set_priority (task, io_priority);
        io_run_until_read_async (msg, task);
}

gboolean
soup_message_io_run_until_read_finish (SoupMessage  *msg,
                                       GAsyncResult *result,
                                       GError      **error)
{
        return g_task_propagate_boolean (G_TASK (result), error);
}

gboolean
soup_message_io_run_until_finish (SoupMessage   *msg,
				  gboolean       blocking,
				  GCancellable  *cancellable,
				  GError       **error)
{
	SoupClientMessageIOData *io = soup_message_get_io_data (msg);
	gboolean success;

	g_object_ref (msg);

	if (io) {
		if (io->base.read_state < SOUP_MESSAGE_IO_STATE_BODY_DONE)
			io->base.read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
	}

	success = io_run_until (msg, blocking,
				SOUP_MESSAGE_IO_STATE_DONE,
				SOUP_MESSAGE_IO_STATE_DONE,
				cancellable, error);

	g_object_unref (msg);
	return success;
}

static void
client_stream_eof (SoupClientInputStream *stream, gpointer user_data)
{
	SoupMessage *msg = user_data;
	SoupClientMessageIOData *io = soup_message_get_io_data (msg);

	if (io && io->base.read_state == SOUP_MESSAGE_IO_STATE_BODY)
		io->base.read_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;
}

GInputStream *
soup_message_io_get_response_istream (SoupMessage  *msg,
				      GError      **error)
{
	SoupClientMessageIOData *io = soup_message_get_io_data (msg);
	GInputStream *client_stream;

	if (SOUP_STATUS_IS_TRANSPORT_ERROR (soup_message_get_status (msg))) {
		g_set_error_literal (error, SOUP_HTTP_ERROR,
				     soup_message_get_status (msg), soup_message_get_reason_phrase (msg));
		return NULL;
	}

	client_stream = soup_client_input_stream_new (io->base.body_istream, msg);
	g_signal_connect (client_stream, "eof",
			  G_CALLBACK (client_stream_eof), msg);

	return client_stream;
}

void
soup_message_send_request (SoupMessageQueueItem      *item,
			   SoupMessageIOCompletionFn  completion_cb,
			   gpointer                   user_data)
{
	SoupClientMessageIOData *io;

	io = g_slice_new0 (SoupClientMessageIOData);
	io->base.completion_cb = completion_cb;
	io->base.completion_data = user_data;

	io->item = item;
	soup_message_queue_item_ref (item);
	io->cancellable = io->item->cancellable;
	io->base.iostream = g_object_ref (soup_connection_get_iostream (io->item->conn));
	io->base.istream = SOUP_FILTER_INPUT_STREAM (g_io_stream_get_input_stream (io->base.iostream));
	io->base.ostream = g_io_stream_get_output_stream (io->base.iostream);
	io->base.async_context = g_main_context_ref_thread_default ();

	io->base.read_header_buf = g_byte_array_new ();
	io->base.write_buf = g_string_new (NULL);

	io->base.read_state = SOUP_MESSAGE_IO_STATE_NOT_STARTED;
	io->base.write_state = SOUP_MESSAGE_IO_STATE_HEADERS;

#ifdef HAVE_SYSPROF
	io->begin_time_nsec = SYSPROF_CAPTURE_CURRENT_TIME;
#endif

	soup_message_set_io_data (io->item->msg, io);
}

void
soup_message_io_pause (SoupMessage *msg)
{
	SoupClientMessageIOData *io = soup_message_get_io_data (msg);

	g_return_if_fail (io != NULL);
	g_return_if_fail (io->base.read_state < SOUP_MESSAGE_IO_STATE_BODY);

	soup_message_io_data_pause (&io->base);
}

void
soup_message_io_unpause (SoupMessage *msg)
{
	SoupClientMessageIOData *io = soup_message_get_io_data (msg);

	g_return_if_fail (io != NULL);
	g_return_if_fail (io->base.read_state < SOUP_MESSAGE_IO_STATE_BODY);
	io->base.paused = FALSE;
}

/**
 * soup_message_io_in_progress:
 * @msg: a #SoupMessage
 *
 * Tests whether or not I/O is currently in progress on @msg.
 *
 * Return value: whether or not I/O is currently in progress.
 **/
gboolean
soup_message_io_in_progress (SoupMessage *msg)
{
	return soup_message_get_io_data (msg) != NULL;
}

gboolean
soup_message_is_io_paused (SoupMessage *msg)
{
	SoupClientMessageIOData *io = soup_message_get_io_data (msg);

	return io && io->base.paused;
}
