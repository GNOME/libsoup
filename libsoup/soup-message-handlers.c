/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-handlers.c: HTTP response handlers
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup-private.h"

typedef enum {
	SOUP_HANDLER_HEADER = 1,
	SOUP_HANDLER_ERROR_CODE,
	SOUP_HANDLER_ERROR_CLASS
} SoupHandlerKind;

typedef struct {
	SoupHandlerPhase  phase;
	SoupCallbackFn    handler_cb;
	gpointer          user_data;

	SoupHandlerKind   kind;
	union {
		guint           errorcode;
		SoupErrorClass  errorclass;
		const char     *header;
	} data;
} SoupHandlerData;

static void redirect_handler (SoupMessage *msg, gpointer user_data);
static void authorize_handler (SoupMessage *msg, gpointer proxy);

static SoupHandlerData global_handlers [] = {
	/* Handle redirect response codes. */
	{
		SOUP_HANDLER_PRE_BODY,
		redirect_handler,
		NULL,
		SOUP_HANDLER_ERROR_CLASS,
		{ SOUP_ERROR_CLASS_REDIRECT }
	},

	/* Handle authorization. */
	{
		SOUP_HANDLER_PRE_BODY,
		authorize_handler,
		GINT_TO_POINTER (FALSE),
		SOUP_HANDLER_ERROR_CODE,
		{ 401 }
	},

	/* Handle proxy authorization. */
	{
		SOUP_HANDLER_PRE_BODY,
		authorize_handler,
		GINT_TO_POINTER (TRUE),
		SOUP_HANDLER_ERROR_CODE,
		{ 407 }
	},

	{ 0 }
};

static inline void
run_handler (SoupMessage     *msg,
	     SoupHandlerPhase invoke_phase,
	     SoupHandlerData *data)
{
	if (data->phase != invoke_phase)
		return;

	switch (data->kind) {
	case SOUP_HANDLER_HEADER:
		if (!soup_message_get_header (msg->response_headers,
					      data->data.header))
			return;
		break;
	case SOUP_HANDLER_ERROR_CODE:
		if (msg->errorcode != data->data.errorcode)
			return;
		break;
	case SOUP_HANDLER_ERROR_CLASS:
		if (msg->errorclass != data->data.errorclass)
			return;
		break;
	default:
		break;
	}

	(*data->handler_cb) (msg, data->user_data);
}

/*
 * Run each handler with matching criteria (first per-message then
 * global handlers). If a handler requeues a message, we stop
 * processing and terminate the current request.
 *
 * After running all handlers, if there is an error set or the invoke
 * phase was post_body, issue the final callback.
 *
 * FIXME: If the errorcode is changed by a handler, we should restart
 * the processing.
 */
void
soup_message_run_handlers (SoupMessage *msg, SoupHandlerPhase invoke_phase)
{
	GSList *list;
	SoupHandlerData *data;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	for (list = msg->priv->content_handlers; list; list = list->next) {
		run_handler (msg, invoke_phase, list->data);

		if (SOUP_MESSAGE_IS_STARTING (msg))
			return;
	}

	for (data = global_handlers; data->phase; data++) {
		run_handler (msg, invoke_phase, data);

		if (SOUP_MESSAGE_IS_STARTING (msg))
			return;
	}

	/* Issue final callback if the invoke_phase is POST_BODY and
	 * the error class is not INFORMATIONAL.
	 */
	if (invoke_phase == SOUP_HANDLER_POST_BODY &&
	    msg->errorclass != SOUP_ERROR_CLASS_INFORMATIONAL)
		soup_message_issue_callback (msg);
}

static void
add_handler (SoupMessage      *msg,
	     SoupHandlerPhase  phase,
	     SoupCallbackFn    handler_cb,
	     gpointer          user_data,
	     SoupHandlerKind   kind,
	     const char       *header,
	     guint             errorcode,
	     guint             errorclass)
{
	SoupHandlerData *data;

	data = g_new0 (SoupHandlerData, 1);
	data->phase = phase;
	data->handler_cb = handler_cb;
	data->user_data = user_data;
	data->kind = kind;

	switch (kind) {
	case SOUP_HANDLER_HEADER:
		data->data.header = header;
		break;
	case SOUP_HANDLER_ERROR_CODE:
		data->data.errorcode = errorcode;
		break;
	case SOUP_HANDLER_ERROR_CLASS:
		data->data.errorclass = errorclass;
		break;
	default:
		break;
	}

	msg->priv->content_handlers =
		g_slist_append (msg->priv->content_handlers, data);
}

void
soup_message_add_header_handler (SoupMessage      *msg,
				 const char       *header,
				 SoupHandlerPhase  phase,
				 SoupCallbackFn    handler_cb,
				 gpointer          user_data)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (header != NULL);
	g_return_if_fail (handler_cb != NULL);

	add_handler (msg, phase, handler_cb, user_data,
		     SOUP_HANDLER_HEADER,
		     header, 0, 0);
}

void
soup_message_add_error_code_handler (SoupMessage      *msg,
				     guint             errorcode,
				     SoupHandlerPhase  phase,
				     SoupCallbackFn    handler_cb,
				     gpointer          user_data)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (errorcode != 0);
	g_return_if_fail (handler_cb != NULL);

	add_handler (msg, phase, handler_cb, user_data,
		     SOUP_HANDLER_ERROR_CODE,
		     NULL, errorcode, 0);
}

void
soup_message_add_error_class_handler (SoupMessage      *msg,
				      SoupErrorClass    errorclass,
				      SoupHandlerPhase  phase,
				      SoupCallbackFn    handler_cb,
				      gpointer          user_data)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (errorclass != 0);
	g_return_if_fail (handler_cb != NULL);

	add_handler (msg, phase, handler_cb, user_data,
		     SOUP_HANDLER_ERROR_CLASS,
		     NULL, 0, errorclass);
}

void
soup_message_add_handler (SoupMessage      *msg,
			  SoupHandlerPhase  phase,
			  SoupCallbackFn    handler_cb,
			  gpointer          user_data)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (handler_cb != NULL);

	add_handler (msg, phase, handler_cb, user_data, 0, NULL, 0, 0);
}

void
soup_message_remove_handler (SoupMessage     *msg,
			     SoupHandlerPhase phase,
			     SoupCallbackFn   handler_cb,
			     gpointer         user_data)
{
	GSList *iter = msg->priv->content_handlers;

	while (iter) {
		SoupHandlerData *data = iter->data;

		if (data->handler_cb == handler_cb &&
		    data->user_data == user_data &&
		    data->phase == phase) {
			msg->priv->content_handlers =
				g_slist_remove (msg->priv->content_handlers,
						data);
			g_free (data);
			break;
		}

		iter = iter->next;
	}
}


/* FIXME: these don't belong here */

static void
authorize_handler (SoupMessage *msg, gpointer proxy)
{
	SoupContext *ctx;

	ctx = proxy ? soup_get_proxy () : msg->priv->context;
	if (soup_context_update_auth (ctx, msg))
		soup_message_requeue (msg);
	else {
		soup_message_set_error (msg,
					proxy ?
			                SOUP_ERROR_CANT_AUTHENTICATE_PROXY :
			                SOUP_ERROR_CANT_AUTHENTICATE);
	}
}

static void
redirect_handler (SoupMessage *msg, gpointer user_data)
{
	const char *new_loc;
	const SoupUri *old_uri;
	SoupUri *new_uri;
	SoupContext *new_ctx;

	if (msg->priv->msg_flags & SOUP_MESSAGE_NO_REDIRECT)
		return;

	old_uri = soup_message_get_uri (msg);

	new_loc = soup_message_get_header (msg->response_headers, "Location");
	if (!new_loc)
		return;
	new_uri = soup_uri_new (new_loc);
	if (!new_uri)
		goto INVALID_REDIRECT;

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

	soup_message_requeue (msg);
	return;

 INVALID_REDIRECT:
	soup_message_set_error_full (msg,
				     SOUP_ERROR_MALFORMED,
				     "Invalid Redirect URL");
}
