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
#include "soup.h"
#include "soup-session-private.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-misc-private.h"

/**
 * SECTION:soup-session-async
 * @short_description: SoupSession for asynchronous (main-loop-based) I/O
 * (deprecated).
 *
 * #SoupSessionAsync is an implementation of #SoupSession that uses
 * non-blocking I/O via the glib main loop for all I/O.
 *
 * Deprecated: 2.42: Use the #SoupSession class (which uses both asynchronous
 * and synchronous I/O, depending on the API used). See the
 * <link linkend="libsoup-session-porting">porting guide</link>.
 **/

G_GNUC_BEGIN_IGNORE_DEPRECATIONS;

G_DEFINE_TYPE (SoupSessionAsync, soup_session_async, SOUP_TYPE_SESSION)

static void
soup_session_async_init (SoupSessionAsync *sa)
{
}

/**
 * soup_session_async_new:
 *
 * Creates an asynchronous #SoupSession with the default options.
 *
 * Return value: the new session.
 *
 * Deprecated: #SoupSessionAsync is deprecated; use a plain
 * #SoupSession, created with soup_session_new(). See the <link
 * linkend="libsoup-session-porting">porting guide</link>.
 **/
SoupSession *
soup_session_async_new (void)
{
	return g_object_new (SOUP_TYPE_SESSION_ASYNC, NULL);
}

/**
 * soup_session_async_new_with_options:
 * @optname1: name of first property to set
 * @...: value of @optname1, followed by additional property/value pairs
 *
 * Creates an asynchronous #SoupSession with the specified options.
 *
 * Return value: the new session.
 *
 * Deprecated: #SoupSessionAsync is deprecated; use a plain
 * #SoupSession, created with soup_session_new_with_options(). See the
 * <link linkend="libsoup-session-porting">porting guide</link>.
 **/
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

static guint
soup_session_async_send_message (SoupSession *session, SoupMessage *msg)
{
	SoupMessageQueueItem *item;
	GMainContext *async_context =
		soup_session_get_async_context (session);

	item = soup_session_append_queue_item (session, msg, TRUE, FALSE,
					       NULL, NULL);
	soup_session_kick_queue (session);

	while (item->state != SOUP_MESSAGE_FINISHED)
		g_main_context_iteration (async_context, TRUE);

	soup_message_queue_item_unref (item);

	return msg->status_code;
}

static void
soup_session_async_cancel_message (SoupSession *session, SoupMessage *msg,
				   guint status_code)
{
	SoupMessageQueue *queue;
	SoupMessageQueueItem *item;

	SOUP_SESSION_CLASS (soup_session_async_parent_class)->
		cancel_message (session, msg, status_code);

	queue = soup_session_get_queue (session);
	item = soup_message_queue_lookup (queue, msg);
	if (!item)
		return;

	/* Force it to finish immediately, so that
	 * soup_session_abort (session); g_object_unref (session);
	 * will work. (The soup_session_cancel_message() docs
	 * point out that the callback will be invoked from
	 * within the cancel call.)
	 */
	if (soup_message_io_in_progress (msg))
		soup_message_io_finished (msg);
	else if (item->state != SOUP_MESSAGE_FINISHED)
		item->state = SOUP_MESSAGE_FINISHING;

	if (item->state != SOUP_MESSAGE_FINISHED)
		soup_session_process_queue_item (session, item, NULL, FALSE);

	soup_message_queue_item_unref (item);
}

static void
soup_session_async_class_init (SoupSessionAsyncClass *soup_session_async_class)
{
	SoupSessionClass *session_class = SOUP_SESSION_CLASS (soup_session_async_class);

	/* virtual method override */
	session_class->send_message = soup_session_async_send_message;
	session_class->cancel_message = soup_session_async_cancel_message;
}

G_GNUC_END_IGNORE_DEPRECATIONS;
