/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_DNS_H
#define SOUP_DNS_H

#include <glib.h>
#include <sys/types.h>

#include <libsoup/soup-portability.h>

void             soup_dns_init                 (void);
char            *soup_dns_ntop                 (struct sockaddr *sa);

/**
 * SoupDNSLookup:
 *
 * An opaque type that represents a DNS lookup operation.
 **/
typedef struct SoupDNSLookup SoupDNSLookup;

SoupDNSLookup   *soup_dns_lookup_name          (const char  *name);
SoupDNSLookup   *soup_dns_lookup_address       (struct sockaddr *sockaddr);
void             soup_dns_lookup_free          (SoupDNSLookup   *lookup);

/**
 * SoupDNSCallback:
 * @lookup: the completed lookup
 * @success: %TRUE if @lookup completed successfully, %FALSE if it failed
 * @user_data: the data passed to soup_dns_lookup_resolve_async()
 *
 * The callback function passed to soup_dns_lookup_resolve_async().
 **/
typedef void (*SoupDNSCallback) (SoupDNSLookup *lookup, gboolean success, gpointer user_data);

gboolean         soup_dns_lookup_resolve       (SoupDNSLookup   *lookup);
void             soup_dns_lookup_resolve_async (SoupDNSLookup   *lookup,
						GMainContext    *async_context,
						SoupDNSCallback  callback,
						gpointer         user_data);
void             soup_dns_lookup_cancel        (SoupDNSLookup   *lookup);

char            *soup_dns_lookup_get_hostname  (SoupDNSLookup   *lookup);
struct sockaddr *soup_dns_lookup_get_address   (SoupDNSLookup   *lookup);


#endif /* SOUP_DNS_H */
