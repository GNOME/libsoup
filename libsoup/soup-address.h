/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_ADDRESS_H
#define SOUP_ADDRESS_H

#include <glib-object.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SOUP_TYPE_ADDRESS            (soup_address_get_type ())
#define SOUP_ADDRESS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_ADDRESS, SoupAddress))
#define SOUP_ADDRESS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_ADDRESS, SoupAddressClass))
#define SOUP_IS_ADDRESS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_ADDRESS))
#define SOUP_IS_ADDRESS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_ADDRESS))
#define SOUP_ADDRESS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_ADDRESS, SoupAddressClass))

typedef struct SoupAddressPrivate SoupAddressPrivate;

typedef struct {
	GObject parent;

	SoupAddressPrivate *priv;
} SoupAddress;

typedef struct {
	GObjectClass parent_class;

} SoupAddressClass;

GType soup_address_get_type (void);


typedef gpointer SoupAddressNewId;

typedef enum {
	SOUP_ADDRESS_STATUS_OK,
	SOUP_ADDRESS_STATUS_ERROR
} SoupAddressStatus;

typedef void (*SoupAddressNewFn) (SoupAddress       *inetaddr, 
				  SoupAddressStatus  status, 
				  gpointer           user_data);

SoupAddressNewId     soup_address_new                (const char        *name, 
						      SoupAddressNewFn   func, 
						      gpointer           data);

void                 soup_address_new_cancel         (SoupAddressNewId   id);

SoupAddress         *soup_address_new_sync           (const char        *name);

SoupAddress         *soup_address_ipv4_any           (void);
SoupAddress         *soup_address_ipv6_any           (void);


typedef gpointer SoupAddressGetNameId;

typedef void (*SoupAddressGetNameFn) (SoupAddress       *inetaddr, 
				      SoupAddressStatus  status, 
				      const char        *name,
				      gpointer           user_data);

SoupAddressGetNameId
             soup_address_get_name           (SoupAddress          *addr, 
					      SoupAddressGetNameFn  func,
					      gpointer              data);

void         soup_address_get_name_cancel    (SoupAddressGetNameId  id);

const char  *soup_address_get_name_sync      (SoupAddress          *addr);

char        *soup_address_get_canonical_name (SoupAddress          *addr);


SoupAddress *soup_address_new_from_sockaddr  (struct sockaddr      *sa,
					      guint                *port);

void         soup_address_make_sockaddr      (SoupAddress          *addr,
					      guint                 port,
					      struct sockaddr     **sa,
					      int                  *len);

guint        soup_address_hash               (const gpointer        p);

gint         soup_address_equal              (const gpointer        p1, 
					      const gpointer        p2);

#endif /* SOUP_ADDRESS_H */
