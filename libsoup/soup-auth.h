/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth.h: Authentication schemes
 *
 * Authors:
 *      Joe Shaw (joe@ximian.com)
 *
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

#ifndef SOUP_AUTH_H
#define SOUP_AUTH_H 1

#include <libsoup/soup-context.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-misc.h>

typedef   enum _SoupAuthStatus SoupAuthStatus;
typedef struct _SoupAuth       SoupAuth;

enum _SoupAuthStatus {
	SOUP_AUTH_STATUS_INVALID = 0,
	SOUP_AUTH_STATUS_PENDING,
	SOUP_AUTH_STATUS_FAILED,
	SOUP_AUTH_STATUS_SUCCESSFUL
};

struct _SoupAuth {
	SoupAuthType  type;
	gchar        *realm;

	SoupAuthStatus status;
	SoupMessage *controlling_msg;

	void     (*parse_func)   (SoupAuth      *auth,
				  const gchar   *header);

	void     (*init_func)    (SoupAuth      *auth, 
				  const SoupUri *uri);

	char    *(*auth_func)    (SoupAuth      *auth, 
				  SoupMessage   *message);

	void     (*free_func)    (SoupAuth      *auth);
};

SoupAuth *soup_auth_lookup                 (SoupContext   *ctx);

void      soup_auth_set_context            (SoupAuth      *auth,
					    SoupContext   *ctx);

void      soup_auth_invalidate             (SoupAuth      *auth,
					    SoupContext   *ctx);

SoupAuth *soup_auth_new_from_header_list   (const SoupUri *uri,
					    const GSList  *header);

void      soup_auth_initialize             (SoupAuth      *auth,
					    const SoupUri *uri);

void      soup_auth_free                   (SoupAuth      *auth);

gchar    *soup_auth_authorize              (SoupAuth      *auth, 
					    SoupMessage   *msg);

#endif /* SOUP_AUTH_H */
