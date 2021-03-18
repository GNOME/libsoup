/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#pragma once

#include "soup-auth.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CONNECTION_AUTH (soup_connection_auth_get_type ())
G_DECLARE_DERIVABLE_TYPE (SoupConnectionAuth, soup_connection_auth, SOUP, CONNECTION_AUTH, SoupAuth)

struct _SoupConnectionAuthClass {
	SoupAuthClass parent_class;

	gpointer  (*create_connection_state)      (SoupConnectionAuth *auth);
	void      (*free_connection_state)        (SoupConnectionAuth *auth,
						   gpointer            conn);

	gboolean  (*update_connection)            (SoupConnectionAuth *auth,
						   SoupMessage        *msg,
						   const char         *auth_header,
						   gpointer            conn);
	char     *(*get_connection_authorization) (SoupConnectionAuth *auth,
						   SoupMessage        *msg,
						   gpointer            conn);
	gboolean  (*is_connection_ready)          (SoupConnectionAuth *auth,
						   SoupMessage        *msg,
						   gpointer            conn);
};


gpointer	soup_connection_auth_get_connection_state_for_message
						(SoupConnectionAuth *auth,
						 SoupMessage        *msg);
G_END_DECLS
