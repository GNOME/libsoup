/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_MISC_H
#define SOUP_MISC_H 1

#include <glib.h>

#include "soup-context.h"
#include "soup-message.h"
#include "soup-uri.h"

void         soup_set_proxy            (SoupContext *ctx);

SoupContext *soup_get_proxy            (void);

void         soup_set_connection_limit (guint        max_conn);

guint        soup_get_connection_limit (void);

void         soup_load_config          (gchar       *config_file);

typedef enum {
	SOUP_SECURITY_DOMESTIC = 1,
	SOUP_SECURITY_EXPORT   = 2,
	SOUP_SECURITY_FRANCE   = 3
} SoupSecurityPolicy;

void         soup_set_security_policy  (SoupSecurityPolicy policy);

/* Useful debugging routines */

void         soup_debug_print_headers  (SoupMessage *req);

void         soup_debug_print_uri      (SoupUri     *uri);

#endif /* SOUP_MISC_H */
