/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Authors:
 *      David Helder  (dhelder@umich.edu)
 *      Alex Graveley (alex@ximian.com)
 * 
 * Original code compliments of David Helder's GNET Networking Library.
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
 */

#ifndef SOUP_ADDRESS_H
#define SOUP_ADDRESS_H

#include <glib.h>

typedef struct _SoupAddress SoupAddress;

typedef gpointer SoupAddressNewId;

typedef enum {
	SOUP_ADDRESS_STATUS_OK,
	SOUP_ADDRESS_STATUS_ERROR
} SoupAddressStatus;

typedef void (*SoupAddressNewFn) (SoupAddress       *inetaddr, 
				  SoupAddressStatus  status, 
				  gpointer           user_data);

SoupAddressNewId     soup_address_new                (const gchar*       name, 
						      const gint         port, 
						      SoupAddressNewFn   func, 
						      gpointer           data);

void                 soup_address_new_cancel         (SoupAddressNewId   id);

SoupAddress         *soup_address_new_sync           (const gchar       *name, 
						      const gint         port);

SoupAddress         *soup_address_lookup_in_cache    (const gchar       *name, 
						      const gint         port);

void                 soup_address_ref                (SoupAddress*       ia);

void                 soup_address_unref              (SoupAddress*       ia);

SoupAddress *        soup_address_copy               (SoupAddress*       ia);


typedef gpointer SoupAddressGetNameId;

typedef void (*SoupAddressGetNameFn) (SoupAddress       *inetaddr, 
				      SoupAddressStatus  status, 
				      const gchar       *name,
				      gpointer           user_data);

SoupAddressGetNameId soup_address_get_name           (SoupAddress*         ia, 
						      SoupAddressGetNameFn func,
						      gpointer             data);

void                 soup_address_get_name_cancel    (SoupAddressGetNameId id);

const gchar         *soup_address_get_name_sync      (SoupAddress *addr);

gchar*               soup_address_get_canonical_name (SoupAddress*         ia);

gint                 soup_address_get_port           (const SoupAddress*   ia);

const struct sockaddr *
                     soup_address_get_sockaddr       (SoupAddress         *ia,
						      guint               *addrlen);

guint                soup_address_hash               (const gpointer       p);

gint                 soup_address_equal              (const gpointer       p1, 
						      const gpointer       p2);

gint                 soup_address_noport_equal       (const gpointer       p1, 
						      const gpointer       p2);

gchar*               soup_address_gethostname        (void);

SoupAddress*         soup_address_gethostaddr        (void);


#endif /* SOUP_ADDRESS_H */
