/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-session-sync.c
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-session-sync.h"
#include "soup.h"
#include "soup-session-private.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"

/**
 * SECTION:soup-session-sync
 * @short_description: SoupSession for blocking I/O in multithreaded programs
 * (deprecated).
 *
 * #SoupSessionSync is an implementation of #SoupSession that uses
 * synchronous I/O, intended for use in multi-threaded programs.
 *
 * Deprecated: 2.42: Use the #SoupSession class (which uses both asynchronous
 * and synchronous I/O, depending on the API used). See the
 * <link linkend="libsoup-session-porting">porting guide</link>.
 **/

G_GNUC_BEGIN_IGNORE_DEPRECATIONS;

G_DEFINE_TYPE (SoupSessionSync, soup_session_sync, SOUP_TYPE_SESSION)

static void
soup_session_sync_init (SoupSessionSync *ss)
{
}

/**
 * soup_session_sync_new:
 *
 * Creates an synchronous #SoupSession with the default options.
 *
 * Return value: the new session.
 *
 * Deprecated: #SoupSessionSync is deprecated; use a plain
 * #SoupSession, created with soup_session_new(). See the <link
 * linkend="libsoup-session-porting">porting guide</link>.
 **/
SoupSession *
soup_session_sync_new (void)
{
	return g_object_new (SOUP_TYPE_SESSION_SYNC, NULL);
}

/**
 * soup_session_sync_new_with_options:
 * @optname1: name of first property to set
 * @...: value of @optname1, followed by additional property/value pairs
 *
 * Creates an synchronous #SoupSession with the specified options.
 *
 * Return value: the new session.
 *
 * Deprecated: #SoupSessionSync is deprecated; use a plain
 * #SoupSession, created with soup_session_new_with_options(). See the
 * <link linkend="libsoup-session-porting">porting guide</link>.
 **/
SoupSession *
soup_session_sync_new_with_options (const char *optname1, ...)
{
	SoupSession *session;
	va_list ap;

	va_start (ap, optname1);
	session = (SoupSession *)g_object_new_valist (SOUP_TYPE_SESSION_SYNC,
						      optname1, ap);
	va_end (ap);

	return session;
}

static gboolean
queue_message_callback (gpointer data)
{
	SoupMessageQueueItem *item = data;

	item->callback (item->session, item->msg, item->callback_data);
	soup_message_queue_item_unref (item);
	return FALSE;
}

static gpointer
queue_message_thread (gpointer data)
{
	SoupMessageQueueItem *item = data;

	soup_session_process_queue_item (item->session, item, NULL, TRUE);
	if (item->callback) {
		soup_add_completion (soup_session_get_async_context (item->session),
				     queue_message_callback, item);
	} else
		soup_message_queue_item_unref (item);

	return NULL;
}

static void
soup_session_sync_queue_message (SoupSession *session, SoupMessage *msg,
				 SoupSessionCallback callback, gpointer user_data)
{
	SoupMessageQueueItem *item;
	GThread *thread;

	item = soup_session_append_queue_item (session, msg, FALSE, FALSE,
					       callback, user_data);
	thread = g_thread_new ("SoupSessionSync:queue_message",
			       queue_message_thread, item);
	g_thread_unref (thread);
}

static void
soup_session_sync_class_init (SoupSessionSyncClass *session_sync_class)
{
	SoupSessionClass *session_class = SOUP_SESSION_CLASS (session_sync_class);

	/* virtual method override */
	session_class->queue_message = soup_session_sync_queue_message;
}

G_GNUC_END_IGNORE_DEPRECATIONS;
