/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-session.c
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "soup-session.h"
#include "soup-connection.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-private.h"

struct SoupSessionPrivate {
	SoupMessageQueue *queue;
	guint queue_idle_tag;

};

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

static void
init (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);

	session->priv = g_new0 (SoupSessionPrivate, 1);
	session->priv->queue = soup_message_queue_new ();
}

static void
finalize (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupMessageQueueIter iter;
	SoupMessage *msg;

	if (session->priv->queue_idle_tag)
		g_source_remove (session->priv->queue_idle_tag);

	for (msg = soup_message_queue_first (session->priv->queue, &iter); msg;
	     msg = soup_message_queue_next (session->priv->queue, &iter)) {
		soup_message_queue_remove (session->priv->queue, &iter);
		soup_message_cancel (msg);
	}
	soup_message_queue_destroy (session->priv->queue);

	g_free (session->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;
}

SOUP_MAKE_TYPE (soup_session, SoupSession, class_init, init, PARENT_TYPE)


SoupSession *
soup_session_new (void)
{
	return g_object_new (SOUP_TYPE_SESSION, NULL);
}


/* Default handlers */

static void
authorize_handler (SoupMessage *msg, gpointer user_data)
{
	SoupSession *session = user_data;
	SoupContext *ctx;

	if (msg->errorcode == SOUP_ERROR_PROXY_UNAUTHORIZED)
		ctx = soup_get_proxy ();
	else
		ctx = msg->priv->context;

	if (soup_context_update_auth (ctx, msg))
		soup_session_requeue_message (session, msg);
}

static void
redirect_handler (SoupMessage *msg, gpointer user_data)
{
	SoupSession *session = user_data;
	const char *new_loc;
	const SoupUri *old_uri;
	SoupUri *new_uri;
	SoupContext *new_ctx;

	new_loc = soup_message_get_header (msg->response_headers, "Location");
	if (!new_loc)
		return;
	new_uri = soup_uri_new (new_loc);
	if (!new_uri)
		goto INVALID_REDIRECT;

	old_uri = soup_message_get_uri (msg);

	/* Copy auth info from original URI. */
	if (old_uri->user && !new_uri->user)
		soup_uri_set_auth (new_uri,
				   old_uri->user,
				   old_uri->passwd,
				   old_uri->authmech);

	new_ctx = soup_context_from_uri (new_uri);
	soup_uri_free (new_uri);
	if (!new_ctx)
		goto INVALID_REDIRECT;

	soup_message_set_context (msg, new_ctx);
	g_object_unref (new_ctx);

	soup_session_requeue_message (session, msg);
	return;

 INVALID_REDIRECT:
	soup_message_set_error_full (msg,
				     SOUP_ERROR_MALFORMED,
				     "Invalid Redirect URL");
}

static void
request_finished (SoupMessage *req, gpointer user_data)
{
	SoupSession *session = user_data;

	soup_message_queue_remove_message (session->priv->queue, req);
	req->priv->status = SOUP_MESSAGE_STATUS_FINISHED;
}

static void
final_finished (SoupMessage *req, gpointer session)
{
	if (!SOUP_MESSAGE_IS_STARTING (req)) {
		g_signal_handlers_disconnect_by_func (req, request_finished, session);
		g_signal_handlers_disconnect_by_func (req, final_finished, session);
		g_object_unref (req);
	}
}

static void
start_request (SoupConnection *conn, SoupMessage *req)
{
	req->priv->status = SOUP_MESSAGE_STATUS_RUNNING;
	soup_connection_send_request (conn, req);
}

static void
got_connection (SoupContext *ctx, SoupKnownErrorCode err,
		SoupConnection *conn, gpointer user_data)
{
	SoupMessage *req = user_data;

	req->priv->connect_tag = NULL;
	soup_message_set_connection (req, conn);

	switch (err) {
	case SOUP_ERROR_OK:
		start_request (conn, req);
		break;

	default:
		soup_message_set_error (req, err);
		soup_message_finished (req);
		break;
	}

	return;
}

static gboolean
idle_run_queue (gpointer user_data)
{
	SoupSession *session = user_data;
	SoupMessageQueueIter iter;
	SoupMessage *req;
	SoupConnection *conn;

	session->priv->queue_idle_tag = 0;

	for (req = soup_message_queue_first (session->priv->queue, &iter); req;
	     req = soup_message_queue_next (session->priv->queue, &iter)) {

		if (req->priv->status != SOUP_MESSAGE_STATUS_QUEUED)
			continue;

		conn = soup_message_get_connection (req);
		if (conn && soup_connection_is_connected (conn)) {
			start_request (conn, req);
		} else {
			gpointer connect_tag;

			req->priv->status = SOUP_MESSAGE_STATUS_CONNECTING;
			connect_tag = 
				soup_context_get_connection (
					req->priv->context,
					got_connection, req);

			if (connect_tag)
				req->priv->connect_tag = connect_tag;
		}
	}

	return FALSE;
}

static void
queue_message (SoupSession *session, SoupMessage *req, gboolean requeue)
{
	soup_message_prepare (req);

	req->priv->status = SOUP_MESSAGE_STATUS_QUEUED;
	if (!requeue)
		soup_message_queue_append (session->priv->queue, req);

	if (!session->priv->queue_idle_tag) {
		session->priv->queue_idle_tag =
			g_idle_add (idle_run_queue, session);
	}
}

/**
 * soup_session_queue_message:
 * @session: a #SoupSession
 * @req: the message to queue
 * @callback: a #SoupCallbackFn which will be called after the message
 * completes or when an unrecoverable error occurs.
 * @user_data: a pointer passed to @callback.
 * 
 * Queues the message @req for sending. All messages are processed
 * while the glib main loop runs. If @req has been processed before,
 * any resources related to the time it was last sent are freed.
 *
 * Upon message completion, the callback specified in @callback will
 * be invoked. If after returning from this callback the message has
 * not been requeued, @req will be unreffed.
 */
void
soup_session_queue_message (SoupSession *session, SoupMessage *req,
			    SoupCallbackFn callback, gpointer user_data)
{
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (req));

	g_signal_connect (req, "finished",
			  G_CALLBACK (request_finished), session);
	if (callback) {
		g_signal_connect (req, "finished",
				  G_CALLBACK (callback), user_data);
	}
	g_signal_connect_after (req, "finished",
				G_CALLBACK (final_finished), session);

	soup_message_add_error_code_handler  (req, SOUP_ERROR_UNAUTHORIZED,
					      SOUP_HANDLER_POST_BODY,
					      authorize_handler, session);
	soup_message_add_error_code_handler  (req,
					      SOUP_ERROR_PROXY_UNAUTHORIZED,
					      SOUP_HANDLER_POST_BODY,
					      authorize_handler, session);

	if (!(req->priv->msg_flags & SOUP_MESSAGE_NO_REDIRECT)) {
		soup_message_add_error_class_handler (
			req, SOUP_ERROR_CLASS_REDIRECT, SOUP_HANDLER_POST_BODY,
			redirect_handler, session);
	}

	queue_message (session, req, FALSE);
}

/**
 * soup_session_requeue_message:
 * @session: a #SoupSession
 * @req: the message to requeue
 *
 * This causes @req to be placed back on the queue to be attempted
 * again.
 **/
void
soup_session_requeue_message (SoupSession *session, SoupMessage *req)
{
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (req));

	queue_message (session, req, TRUE);
}


/**
 * soup_session_send_message:
 * @session: a #SoupSession
 * @req: the message to send
 * 
 * Synchronously send @req. This call will not return until the
 * transfer is finished successfully or there is an unrecoverable
 * error.
 *
 * @req is not freed upon return.
 *
 * Return value: the #SoupErrorClass of the error encountered while
 * sending or reading the response.
 */
SoupErrorClass
soup_session_send_message (SoupSession *session, SoupMessage *req)
{
	g_return_val_if_fail (SOUP_IS_SESSION (session), SOUP_ERROR_CLASS_TRANSPORT);
	g_return_val_if_fail (SOUP_IS_MESSAGE (req), SOUP_ERROR_CLASS_TRANSPORT);

	/* Balance out the unref that final_finished will do */
	g_object_ref (req);

	soup_session_queue_message (session, req, NULL, NULL);

	while (1) {
		g_main_iteration (TRUE);

		if (req->priv->status == SOUP_MESSAGE_STATUS_FINISHED ||
		    SOUP_ERROR_IS_TRANSPORT (req->errorcode))
			break;
	}

	return req->errorclass;
}
