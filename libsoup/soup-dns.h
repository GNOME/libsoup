/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_DNS_H
#define SOUP_DNS_H

#include <glib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef struct SoupDNSEntry SoupDNSEntry;

SoupDNSEntry   *soup_dns_entry_from_name     (const char     *name);
SoupDNSEntry   *soup_dns_entry_from_addr     (gconstpointer   addr,
					      int             family);

gboolean        soup_dns_entry_check_lookup  (SoupDNSEntry   *entry);
void            soup_dns_entry_cancel_lookup (SoupDNSEntry   *entry);

struct hostent *soup_dns_entry_get_hostent   (SoupDNSEntry   *entry);
void            soup_dns_free_hostent        (struct hostent *h);

char           *soup_dns_ntop                (gconstpointer   addr,
					      int             family);

#endif /* SOUP_DNS_H */
