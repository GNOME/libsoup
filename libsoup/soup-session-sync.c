/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-session-sync.c
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define LIBSOUP_I_HAVE_READ_BUG_594377_AND_KNOW_SOUP_PASSWORD_MANAGER_MIGHT_GO_AWAY

#include "soup-session-sync.h"
#include "soup.h"
#include "soup-session-private.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"

/**
 * SECTION:soup-session-sync
 * @short_description: Soup session for blocking I/O in multithreaded
 * programs.
 *
 * #SoupSessionSync is an implementation of #SoupSession that uses
 * synchronous I/O, intended for use in multi-threaded programs.
 *
 * You can use #SoupSessionSync from multiple threads concurrently.
 * Eg, you can send a #SoupMessage in one thread, and then while
 * waiting for the response, send another #SoupMessage from another
 * thread. You can also send a message from one thread and then call
 * soup_session_cancel_message() on it from any other thread (although
 * you need to be careful to avoid race conditions, where the message
 * finishes and is then unreffed by the sending thread just before you
 * cancel it).
 *
 * However, the majority of other types and methods in libsoup are not
 * MT-safe. In particular, you <emphasis>cannot</emphasis> modify or
 * examine a #SoupMessage while it is being transmitted by
 * #SoupSessionSync in another thread. Once a message has been handed
 * off to #SoupSessionSync, it can only be manipulated from its signal
 * handler callbacks, until I/O is complete.
 **/

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

static guint
soup_session_sync_send_message (SoupSession *session, SoupMessage *msg)
{
	SoupMessageQueueItem *item;
	guint status;

	item = soup_session_append_queue_item (session, msg, FALSE, FALSE,
					       NULL, NULL);
	soup_session_process_queue_item (session, item, NULL, TRUE);
	status = msg->status_code;
	soup_message_queue_item_unref (item);
	return status;
}

static void
soup_session_sync_auth_required (SoupSession *session, SoupMessage *msg,
				 SoupAuth *auth, gboolean retrying)
{
	SoupSessionFeature *password_manager;

	password_manager = soup_session_get_feature_for_message (
		session, SOUP_TYPE_PASSWORD_MANAGER, msg);
	if (password_manager) {
		soup_password_manager_get_passwords_sync (
			SOUP_PASSWORD_MANAGER (password_manager),
			msg, auth, NULL); /* FIXME cancellable */
	}

	SOUP_SESSION_CLASS (soup_session_sync_parent_class)->
		auth_required (session, msg, auth, retrying);
}

static void
soup_session_sync_class_init (SoupSessionSyncClass *session_sync_class)
{
	SoupSessionClass *session_class = SOUP_SESSION_CLASS (session_sync_class);

	/* virtual method override */
	session_class->queue_message = soup_session_sync_queue_message;
	session_class->send_message = soup_session_sync_send_message;
	session_class->auth_required = soup_session_sync_auth_required;
}
