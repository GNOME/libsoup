/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_ADDRESS_H
#define SOUP_ADDRESS_H

#include <sys/types.h>
#include <sys/socket.h>

#include <libsoup/soup-types.h>

#define SOUP_TYPE_ADDRESS            (soup_address_get_type ())
#define SOUP_ADDRESS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_ADDRESS, SoupAddress))
#define SOUP_ADDRESS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_ADDRESS, SoupAddressClass))
#define SOUP_IS_ADDRESS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_ADDRESS))
#define SOUP_IS_ADDRESS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_ADDRESS))
#define SOUP_ADDRESS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_ADDRESS, SoupAddressClass))

typedef struct SoupAddressPrivate SoupAddressPrivate;

struct SoupAddress {
	GObject parent;

	SoupAddressPrivate *priv;
};

typedef struct {
	GObjectClass parent_class;

	/* signals */
	void (*dns_result) (SoupAddress *addr, SoupKnownErrorCode);
} SoupAddressClass;

typedef enum {
	SOUP_ADDRESS_FAMILY_IPV4 = AF_INET,
#ifdef AF_INET6
	SOUP_ADDRESS_FAMILY_IPV6 = AF_INET6
#else
	SOUP_ADDRESS_FAMILY_IPV6 = -1
#endif
} SoupAddressFamily;

#define SOUP_ADDRESS_ANY_PORT 0

GType soup_address_get_type (void);

SoupAddress     *soup_address_new                (const char          *name,
						  guint                port);
SoupAddress     *soup_address_new_from_sockaddr  (struct sockaddr     *sa,
						  int                  len);
SoupAddress     *soup_address_new_any            (SoupAddressFamily    family,
						  guint                port);

typedef void   (*SoupAddressCallback)            (SoupAddress         *addr,
						  SoupKnownErrorCode   status,
						  gpointer             data);
void             soup_address_resolve            (SoupAddress         *addr,
						  SoupAddressCallback  cb,
						  gpointer             data);

const char      *soup_address_get_name           (SoupAddress         *addr);
struct sockaddr *soup_address_get_sockaddr       (SoupAddress         *addr,
						  int                 *len);
const char      *soup_address_get_physical       (SoupAddress         *addr);
guint            soup_address_get_port           (SoupAddress         *addr);

#endif /* SOUP_ADDRESS_H */
