/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-session-async.c
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-session-async.h"
#include "soup-connection.h"

struct SoupSessionAsyncPrivate {
	int dummy;
};

static gboolean run_queue (SoupSessionAsync *sa, gboolean try_pruning);

static void  queue_message   (SoupSession *session, SoupMessage *req,
			      SoupMessageCallbackFn callback,
			      gpointer user_data);
static guint send_message    (SoupSession *session, SoupMessage *req);

#define PARENT_TYPE SOUP_TYPE_SESSION
static SoupSessionClass *parent_class;

static void
init (GObject *object)
{
	SoupSessionAsync *sa = SOUP_SESSION_ASYNC (object);

	sa->priv = g_new0 (SoupSessionAsyncPrivate, 1);
}

static void
finalize (GObject *object)
{
	SoupSessionAsync *sa = SOUP_SESSION_ASYNC (object);

	g_free (sa->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	SoupSessionClass *session_class = SOUP_SESSION_CLASS (object_class);

	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	session_class->queue_message = queue_message;
	session_class->send_message = send_message;
	object_class->finalize = finalize;
}

SOUP_MAKE_TYPE (soup_session_async, SoupSessionAsync, class_init, init, PARENT_TYPE)

SoupSession *
soup_session_async_new (void)
{
	return g_object_new (SOUP_TYPE_SESSION_ASYNC, NULL);
}

SoupSession *
soup_session_async_new_with_options (const char *optname1, ...)
{
	SoupSession *session;
	va_list ap;

	va_start (ap, optname1);
	session = (SoupSession *)g_object_new_valist (SOUP_TYPE_SESSION_ASYNC,
						      optname1, ap);
	va_end (ap);

	return session;
}


static void
connection_closed (SoupConnection *conn, SoupSessionAsync *sa)
{
	/* Run the queue in case anyone was waiting for a connection
	 * to be closed.
	 */
	run_queue (sa, FALSE);
}

static void
got_connection (SoupConnection *conn, guint status, gpointer user_data)
{
	SoupSessionAsync *sa = user_data;

	if (status == SOUP_STATUS_OK) {
		g_signal_connect (conn, "disconnected",
				  G_CALLBACK (connection_closed),
				  sa);
	}

	/* Either we just got a connection, or we just failed to
	 * open a connection and so decremented the open connection
	 * count by one. Either way, we need to run the queue now.
	 */
	run_queue (sa, FALSE);
}

static gboolean
run_queue (SoupSessionAsync *sa, gboolean try_pruning)
{
	SoupSession *session = SOUP_SESSION (sa);
	SoupMessageQueueIter iter;
	SoupMessage *msg;
	SoupConnection *conn;
	gboolean should_prune = FALSE, started_any = FALSE, is_new;

	/* FIXME: prefer CONNECTING messages */

 try_again:
	for (msg = soup_message_queue_first (session->queue, &iter); msg; msg = soup_message_queue_next (session->queue, &iter)) {

		if (!SOUP_MESSAGE_IS_STARTING (msg))
			continue;

		conn = soup_session_get_connection (session, msg,
						    &should_prune, &is_new);
		if (!conn)
			continue;

		if (is_new) {
			soup_connection_connect_async (conn, got_connection,
						       session);
		} else
			soup_connection_send_request (conn, msg);

		started_any = TRUE;
	}

	if (try_pruning && should_prune && !started_any) {
		/* We didn't manage to start any message, but there is
		 * at least one message in the queue that could be
		 * sent if we pruned an idle connection from some
		 * other server.
		 */
		if (soup_session_try_prune_connection (session)) {
			try_pruning = FALSE;
			goto try_again;
		}
	}

	return started_any;
}

static void
request_restarted (SoupMessage *req, gpointer sa)
{
	run_queue (sa, FALSE);
}

static void
final_finished (SoupMessage *req, gpointer user_data)
{
	SoupSessionAsync *sa = user_data;

	if (!SOUP_MESSAGE_IS_STARTING (req)) {
		g_signal_handlers_disconnect_by_func (req, final_finished, sa);
		g_object_unref (req);
	}

	run_queue (sa, FALSE);
}

static void
queue_message (SoupSession *session, SoupMessage *req,
	       SoupMessageCallbackFn callback, gpointer user_data)
{
	SoupSessionAsync *sa = SOUP_SESSION_ASYNC (session);

	g_signal_connect (req, "restarted",
			  G_CALLBACK (request_restarted), sa);

	if (callback) {
		g_signal_connect (req, "finished",
				  G_CALLBACK (callback), user_data);
	}
	g_signal_connect_after (req, "finished",
				G_CALLBACK (final_finished), sa);

	SOUP_SESSION_CLASS (parent_class)->queue_message (session, req,
							  callback, user_data);

	run_queue (sa, TRUE);
}

static guint
send_message (SoupSession *session, SoupMessage *req)
{
	/* Balance out the unref that final_finished will do */
	g_object_ref (req);

	queue_message (session, req, NULL, NULL);

	while (req->status != SOUP_MESSAGE_STATUS_FINISHED &&
	       !SOUP_STATUS_IS_TRANSPORT_ERROR (req->status_code))
		g_main_iteration (TRUE);

	return req->status_code;
}
