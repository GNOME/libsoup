/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <glib.h>

#include "soup-server.h"
#include "soup-headers.h"
#include "soup-private.h"

static GSList    *server_handlers;
static GMainLoop *server_main;
static guint      server_read_source_tag;

typedef struct {
	gchar                *methodname;
	SoupServerCallbackFn  cb;
	gpointer              user_data;
} SoupServerHandler;

void  
soup_server_register (const gchar          *methodname, 
		      SoupServerCallbackFn  cb,
		      gpointer              user_data)
{
	SoupServerHandler *hand = g_new0 (SoupServerHandler, 1);
	hand->methodname = g_strdup (methodname);
	hand->cb = cb;
	hand->user_data = user_data;
}

static void
soup_server_free_handler (SoupServerHandler *hand)
{
	server_handlers = g_slist_remove (server_handlers, hand);
	g_free (hand->methodname);
	g_free (hand);
}

void  
soup_server_unregister_by_name (const gchar *methodname)
{
	GSList *iter = server_handlers;
	for (iter = server_handlers; iter; iter = iter->next) {
		SoupServerHandler *hand = iter->data;
		if (!strcmp (hand->methodname, methodname))
			soup_server_free_handler (hand);
	}
}

void  
soup_server_unregister_by_cb (SoupServerCallbackFn cb)
{
	GSList *iter = server_handlers;
	for (iter = server_handlers; iter; iter = iter->next) {
		SoupServerHandler *hand = iter->data;
		if (hand->cb == cb) soup_server_free_handler (hand);
	}
}

void  
soup_server_unregister_by_data (gpointer user_data)
{
	GSList *iter = server_handlers;
	for (iter = server_handlers; iter; iter = iter->next) {
		SoupServerHandler *hand = iter->data;
		if (hand->user_data == user_data) 
			soup_server_free_handler (hand);
	}
}

static gboolean 
soup_server_read_cb (GIOChannel   *iochannel, 
		     GIOCondition  condition, 
		     gpointer      not_used) 
{
	GSList *iter;
	SoupServerCallbackFn cb = NULL;
	SoupContext *ctx;
	SoupMessage *msg;
	GHashTable *req_headers;
	gchar *req_host, *req_path, *req_method, *resp_phrase, *str, *url;
	gint len, index;
	SoupAction action;
	gpointer user_data;

	index = soup_substring_index (str, len, "\r\n\r\n");
	if (!index) goto THROW_MALFORMED_REQUEST;

	req_headers = g_hash_table_new (soup_str_case_hash, 
					soup_str_case_equal);

	if (!soup_headers_parse_request (str, 
					 index, 
					 req_headers, 
					 &req_method, 
					 &req_path))
		goto THROW_MALFORMED_HEADER;

	if ((g_strcasecmp (req_method, "POST") != 0 && 
	     g_strcasecmp (req_method, "M-POST") != 0))
		goto THROW_MALFORMED_HEADER;

	action = g_hash_table_lookup (req_headers, "SOAPAction");
	if (!action) goto THROW_MALFORMED_HEADER;

	for (iter = server_handlers; iter; iter = iter->next) {
		SoupServerHandler *hand = iter->data;
		if (!strcmp (hand->methodname, action)) {
			cb = hand->cb;
			user_data = hand->user_data;
		}
	}
	if (!cb) goto THROW_NO_HANDLER;

	req_host = g_hash_table_lookup (req_headers, "Host");
	if (req_host) 
		url = g_strconcat ("http://", req_host, req_path, NULL);
	else 
		url = g_strdup (req_path);

	ctx = soup_context_get (url);
	g_free (url);

	/* No Host, no AbsoluteUri */
	if (!ctx) {
		url = g_strconcat ("http://localhost/", req_path, NULL);
		ctx = soup_context_get (url);
		g_free (url);
	}

	if (!ctx) goto THROW_MALFORMED_HEADER;

	msg = soup_message_new (ctx, action);

	msg->action = g_strdup (action);

	msg->request.owner = SOUP_BUFFER_SYSTEM_OWNED;
	msg->request.length = len - index - 4;
	msg->request.body = &str [index + 4];
	msg->request_headers = req_headers;

	msg->response_code = 200;
	msg->response_phrase = resp_phrase = g_strdup ("OK");
	msg->response_headers = g_hash_table_new (soup_str_case_hash, 
						  soup_str_case_equal);
	g_hash_table_insert (msg->response_headers, 
			     "Content-Type",
			     "text/xml\r\n\tcharset=\"utf-8\"");

	(*cb) (msg, user_data); 

	if (msg->response_phrase != resp_phrase) g_free (resp_phrase);

	// write msg->response to STDOUT

	g_free (req_method);
	g_free (req_path);
	soup_message_free (msg);
	
 THROW_NO_HANDLER:
	return TRUE;

 THROW_MALFORMED_HEADER:
	g_hash_table_destroy (req_headers);
	g_free (req_method);
	g_free (req_path);

 THROW_MALFORMED_REQUEST:
	return TRUE;
}

static gboolean 
soup_server_error_cb (GIOChannel   *iochannel, 
		      GIOCondition  condition, 
		      gpointer      not_used) 
{
	g_source_remove (server_read_source_tag);
	soup_server_main_quit ();
	return FALSE;
}

void  
soup_server_main (void)
{
	GIOChannel *chan = g_io_channel_unix_new (STDIN_FILENO);
	server_main = g_main_new (TRUE);

	server_read_source_tag = g_io_add_watch (chan, 
						 G_IO_IN, 
						 soup_server_read_cb, 
						 server_handlers);
	g_io_add_watch (chan, 
			G_IO_ERR | G_IO_HUP | G_IO_NVAL, 
			soup_server_error_cb, 
			server_handlers);

	g_main_run (server_main);
}

void  
soup_server_main_quit (void)
{
	g_return_if_fail (server_main != NULL);
	g_main_quit (server_main);
	server_main = NULL;
}
