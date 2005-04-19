/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-address.c: Internet address handing
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>

#include "soup-address.h"
#include "soup-dns.h"
#include "soup-marshal.h"
#include "soup-misc.h"

#ifndef INET_ADDRSTRLEN
#  define INET_ADDRSTRLEN 16
#  define INET6_ADDRSTRLEN 46
#endif

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif

typedef struct {
	struct sockaddr *sockaddr;

	char *name, *physical;
	guint port;

	SoupDNSLookup *lookup;
	guint timeout_id;
} SoupAddressPrivate;
#define SOUP_ADDRESS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_ADDRESS, SoupAddressPrivate))

/* sockaddr generic macros */
#define SOUP_SIN(priv) ((struct sockaddr_in *)priv->sockaddr)
#ifdef HAVE_IPV6
#define SOUP_SIN6(priv) ((struct sockaddr_in6 *)priv->sockaddr)
#endif

/* sockaddr family macros */
#define SOUP_ADDRESS_GET_FAMILY(priv) (priv->sockaddr->sa_family)
#define SOUP_ADDRESS_SET_FAMILY(priv, family) \
	(priv->sockaddr->sa_family = family)
#ifdef HAVE_IPV6
#define SOUP_ADDRESS_FAMILY_IS_VALID(family) \
	(family == AF_INET || family == AF_INET6)
#define SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE(family) \
	(family == AF_INET ? sizeof (struct sockaddr_in) : \
			     sizeof (struct sockaddr_in6))
#define SOUP_ADDRESS_FAMILY_DATA_SIZE(family) \
	(family == AF_INET ? sizeof (struct in_addr) : \
			     sizeof (struct in6_addr))
#else
#define SOUP_ADDRESS_FAMILY_IS_VALID(family) (family == AF_INET)
#define SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE(family) sizeof (struct sockaddr_in)
#define SOUP_ADDRESS_FAMILY_DATA_SIZE(family) sizeof (struct in_addr)
#endif

/* sockaddr port macros */
#define SOUP_ADDRESS_PORT_IS_VALID(port) (port >= 0 && port <= 65535)
#ifdef HAVE_IPV6
#define SOUP_ADDRESS_GET_PORT(priv) \
	(priv->sockaddr->sa_family == AF_INET ? \
		SOUP_SIN(priv)->sin_port : \
		SOUP_SIN6(priv)->sin6_port)
#define SOUP_ADDRESS_SET_PORT(priv, port) \
	G_STMT_START {					\
	if (priv->sockaddr->sa_family == AF_INET)	\
		SOUP_SIN(priv)->sin_port = port;	\
	else						\
		SOUP_SIN6(priv)->sin6_port = port;	\
	} G_STMT_END
#else
#define SOUP_ADDRESS_GET_PORT(priv) (SOUP_SIN(priv)->sin_port)
#define SOUP_ADDRESS_SET_PORT(priv, port) (SOUP_SIN(priv)->sin_port = port)
#endif

/* sockaddr data macros */
#ifdef HAVE_IPV6
#define SOUP_ADDRESS_GET_DATA(priv) \
	(priv->sockaddr->sa_family == AF_INET ? \
		(gpointer)&SOUP_SIN(priv)->sin_addr : \
		(gpointer)&SOUP_SIN6(priv)->sin6_addr)
#else
#define SOUP_ADDRESS_GET_DATA(priv) ((gpointer)&SOUP_SIN(priv)->sin_addr)
#endif
#define SOUP_ADDRESS_SET_DATA(priv, data, length) \
	memcpy (SOUP_ADDRESS_GET_DATA (priv), data, length)


enum {
	DNS_RESULT,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (SoupAddress, soup_address, G_TYPE_OBJECT)

static void
soup_address_init (SoupAddress *addr)
{
}

static void
finalize (GObject *object)
{
	SoupAddress *addr = SOUP_ADDRESS (object);
	SoupAddressPrivate *priv = SOUP_ADDRESS_GET_PRIVATE (addr);

	if (priv->sockaddr)
		g_free (priv->sockaddr);
	if (priv->name)
		g_free (priv->name);
	if (priv->physical)
		g_free (priv->physical);

	if (priv->lookup)
		soup_dns_lookup_free (priv->lookup);
	if (priv->timeout_id)
		g_source_remove (priv->timeout_id);

	G_OBJECT_CLASS (soup_address_parent_class)->finalize (object);
}

static void
soup_address_class_init (SoupAddressClass *address_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (address_class);

	soup_dns_init ();

	g_type_class_add_private (address_class, sizeof (SoupAddressPrivate));

	/* virtual method override */
	object_class->finalize = finalize;

	/* signals */
	signals[DNS_RESULT] =
		g_signal_new ("dns_result",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupAddressClass, dns_result),
			      NULL, NULL,
			      soup_marshal_NONE__INT,
			      G_TYPE_NONE, 1,
			      G_TYPE_INT);

#ifdef G_OS_WIN32
	/* This hopefully is a good place to call WSAStartup */
	{
		WSADATA wsadata;
		if (WSAStartup (MAKEWORD (2, 0), &wsadata) != 0)
			g_error ("Windows Sockets could not be initialized");
	}
#endif
}


/**
 * soup_address_new:
 * @name: a hostname or physical address
 * @port: a port number
 *
 * Creates a #SoupAddress from @name and @port. The #SoupAddress's IP
 * address may not be available right away; the caller can call
 * soup_address_resolve_async() or soup_address_resolve_sync() to
 * force a DNS resolution.
 *
 * Return value: a #SoupAddress
 **/
SoupAddress *
soup_address_new (const char *name, guint port)
{
	SoupAddress *addr;
	SoupAddressPrivate *priv;

	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (SOUP_ADDRESS_PORT_IS_VALID (port), NULL);

	addr = g_object_new (SOUP_TYPE_ADDRESS, NULL);
	priv = SOUP_ADDRESS_GET_PRIVATE (addr);
	priv->name = g_strdup (name);
	priv->port = port;
	priv->lookup = soup_dns_lookup_name (priv->name);

	return addr;
}

/**
 * soup_address_new_from_sockaddr:
 * @sa: a pointer to a sockaddr
 * @len: size of @sa
 *
 * Returns a #SoupAddress equivalent to @sa (or %NULL if @sa's
 * address family isn't supported)
 *
 * Return value: the new #SoupAddress
 **/
SoupAddress *
soup_address_new_from_sockaddr (struct sockaddr *sa, int len)
{
	SoupAddress *addr;
	SoupAddressPrivate *priv;

	g_return_val_if_fail (sa != NULL, NULL);
	g_return_val_if_fail (SOUP_ADDRESS_FAMILY_IS_VALID (sa->sa_family), NULL);
	g_return_val_if_fail (len == SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE (sa->sa_family), NULL);

	addr = g_object_new (SOUP_TYPE_ADDRESS, NULL);
	priv = SOUP_ADDRESS_GET_PRIVATE (addr);
	priv->sockaddr = g_memdup (sa, len);
	priv->port = ntohs (SOUP_ADDRESS_GET_PORT (priv));
	priv->lookup = soup_dns_lookup_address (priv->sockaddr);

	return addr;
}

/**
 * soup_address_new_any:
 * @family: the address family
 * @port: the port number (usually %SOUP_ADDRESS_ANY_PORT)
 *
 * Returns a #SoupAddress corresponding to the "any" address
 * for @family (or %NULL if @family isn't supported), suitable for
 * passing to soup_socket_server_new().
 *
 * Return value: the new #SoupAddress
 **/
SoupAddress *
soup_address_new_any (SoupAddressFamily family, guint port)
{
	SoupAddress *addr;
	SoupAddressPrivate *priv;

	g_return_val_if_fail (SOUP_ADDRESS_FAMILY_IS_VALID (family), NULL);
	g_return_val_if_fail (SOUP_ADDRESS_PORT_IS_VALID (port), NULL);

	addr = g_object_new (SOUP_TYPE_ADDRESS, NULL);
	priv = SOUP_ADDRESS_GET_PRIVATE (addr);
	priv->port = port;

	priv->sockaddr = g_malloc0 (SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE (family));
	SOUP_ADDRESS_SET_FAMILY (priv, family);
	SOUP_ADDRESS_SET_PORT (priv, htons (port));
	priv->lookup = soup_dns_lookup_address (priv->sockaddr);

	return addr;
}

/**
 * soup_address_get_name:
 * @addr: a #SoupAddress
 *
 * Returns the hostname associated with @addr.
 *
 * Return value: the hostname, or %NULL if it is not known.
 **/
const char *
soup_address_get_name (SoupAddress *addr)
{
	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), NULL);

	return SOUP_ADDRESS_GET_PRIVATE (addr)->name;
}

/**
 * soup_address_get_sockaddr:
 * @addr: a #SoupAddress
 * @len: return location for sockaddr length
 *
 * Returns the sockaddr associated with @addr, with its length in
 * *@len. If the sockaddr is not yet know, returns %NULL.
 *
 * Return value: the sockaddr, or %NULL
 **/
struct sockaddr *
soup_address_get_sockaddr (SoupAddress *addr, int *len)
{
	SoupAddressPrivate *priv;

	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), NULL);
	priv = SOUP_ADDRESS_GET_PRIVATE (addr);

	if (priv->sockaddr && len)
		*len = SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE (SOUP_ADDRESS_GET_FAMILY (priv));

	return priv->sockaddr;
}

/**
 * soup_address_get_physical:
 * @addr: a #SoupAddress
 *
 * Returns the physical address associated with @addr as a string.
 * (Eg, "127.0.0.1"). If the address is not yet known, returns %NULL.
 *
 * Return value: the physical address, or %NULL
 **/
const char *
soup_address_get_physical (SoupAddress *addr)
{
	SoupAddressPrivate *priv;

	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), NULL);
	priv = SOUP_ADDRESS_GET_PRIVATE (addr);

	if (!priv->sockaddr)
		return NULL;

	if (!priv->physical)
		priv->physical = soup_dns_ntop (priv->sockaddr);

	return priv->physical;
}

/**
 * soup_address_get_port:
 * @addr: a #SoupAddress
 *
 * Returns the port associated with @addr.
 *
 * Return value: the port
 **/
guint
soup_address_get_port (SoupAddress *addr)
{
	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), 0);

	return SOUP_ADDRESS_GET_PRIVATE (addr)->port;
}


static void
update_address (SoupDNSLookup *lookup, gboolean success, gpointer user_data)
{
	SoupAddress *addr = user_data;
	SoupAddressPrivate *priv = SOUP_ADDRESS_GET_PRIVATE (addr);

	if (success) {
		if (!priv->name)
			priv->name = soup_dns_lookup_get_hostname (lookup);

		if (!priv->sockaddr) {
			priv->sockaddr = soup_dns_lookup_get_address (lookup);
			SOUP_ADDRESS_SET_PORT (priv, htons (priv->port));
		}
	}

	g_signal_emit (addr, signals[DNS_RESULT], 0, success ? SOUP_STATUS_OK : SOUP_STATUS_CANT_RESOLVE);
}

/**
 * soup_address_resolve_async:
 * @addr: a #SoupAddress
 * @callback: callback to call with the result
 * @user_data: data for @callback
 *
 * Asynchronously resolves the missing half of @addr. (Its IP address
 * if it was created with soup_address_new(), or its hostname if it
 * was created with soup_address_new_from_sockaddr() or
 * soup_address_new_any().) @callback will be called when the
 * resolution finishes (successfully or not).
 **/
void
soup_address_resolve_async (SoupAddress *addr,
			    SoupAddressCallback callback,
			    gpointer user_data)
{
	SoupAddressPrivate *priv;

	g_return_if_fail (SOUP_IS_ADDRESS (addr));
	priv = SOUP_ADDRESS_GET_PRIVATE (addr);

	if (callback) {
		soup_signal_connect_once (addr, "dns_result",
					  G_CALLBACK (callback), user_data);
	}

	soup_dns_lookup_resolve_async (priv->lookup, update_address, addr);
}

/**
 * soup_address_resolve_sync:
 * @addr: a #SoupAddress
 *
 * Synchronously resolves the missing half of @addr, as with
 * soup_address_resolve_async().
 *
 * Return value: %SOUP_STATUS_OK or %SOUP_STATUS_CANT_RESOLVE
 **/
guint
soup_address_resolve_sync (SoupAddress *addr)
{
	SoupAddressPrivate *priv;
	gboolean success;

	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), SOUP_STATUS_MALFORMED);
	priv = SOUP_ADDRESS_GET_PRIVATE (addr);

	success = soup_dns_lookup_resolve (priv->lookup);
	update_address (priv->lookup, success, addr);
	return success ? SOUP_STATUS_OK : SOUP_STATUS_CANT_RESOLVE;
}
