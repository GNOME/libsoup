/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-address.c: Internet address handing
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include "soup-address.h"
#include "soup-dns.h"
#include "soup-marshal.h"
#include "soup-misc.h"

#include <unistd.h>
#ifndef socklen_t
#  define socklen_t size_t
#endif

#ifndef INET_ADDRSTRLEN
#  define INET_ADDRSTRLEN 16
#  define INET6_ADDRSTRLEN 46
#endif

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif

struct SoupAddressPrivate {
	struct sockaddr *sockaddr;

	char *name, *physical;
	guint port;

	SoupDNSEntry *lookup;
	guint idle_id;
};

#define SOUP_ADDRESS_PORT_IS_VALID(port) (port >= 0 && port <= 65535)
#define SOUP_ADDRESS_FAMILY(addr) (addr->priv->sockaddr->sa_family)

#define SOUP_SIN(addr) ((struct sockaddr_in *)addr->priv->sockaddr)

#ifdef HAVE_IPV6

#  define SOUP_SIN6(addr) ((struct sockaddr_in6 *)addr->priv->sockaddr)

#  define SOUP_ADDRESS_FAMILY_IS_VALID(family) \
	(family == AF_INET || family == AF_INET6)
#  define SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE(family) \
	(family == AF_INET ? sizeof (struct sockaddr_in) : \
			     sizeof (struct sockaddr_in6))
#  define SOUP_ADDRESS_FAMILY_DATA_SIZE(family) \
	(family == AF_INET ? sizeof (struct in_addr) : \
			     sizeof (struct in6_addr))

#  define SOUP_ADDRESS_DATA(addr) \
	(addr->priv->sockaddr->sa_family == AF_INET ? \
		(gpointer)&SOUP_SIN(addr)->sin_addr : \
		(gpointer)&SOUP_SIN6(addr)->sin6_addr)
#  define SOUP_ADDRESS_PORT(addr) \
	(addr->priv->sockaddr->sa_family == AF_INET ? \
		SOUP_SIN(addr)->sin_port : \
		SOUP_SIN6(addr)->sin6_port)

#else

#  define SOUP_ADDRESS_FAMILY_IS_VALID(family) (family == AF_INET6)
#  define SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE(family) sizeof (struct sockaddr_in)
#  define SOUP_ADDRESS_FAMILY_DATA_SIZE(family) sizeof (struct in_addr)

#  define SOUP_ADDRESS_DATA(addr) ((gpointer)&SOUP_SIN(addr)->sin_addr)
#  define SOUP_ADDRESS_PORT(addr) (SOUP_SIN(addr)->sin_port)

#endif

enum {
	DNS_RESULT,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

static void
init (GObject *object)
{
	SoupAddress *addr = SOUP_ADDRESS (object);

	addr->priv = g_new0 (SoupAddressPrivate, 1);
}

static void
finalize (GObject *object)
{
	SoupAddress *addr = SOUP_ADDRESS (object);

	if (addr->priv->sockaddr)
		g_free (addr->priv->sockaddr);
	if (addr->priv->name)
		g_free (addr->priv->name);
	if (addr->priv->physical)
		g_free (addr->priv->physical);

	if (addr->priv->lookup)
		soup_dns_entry_cancel_lookup (addr->priv->lookup);
	if (addr->priv->idle_id)
		g_source_remove (addr->priv->idle_id);

	g_free (addr->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

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
}

SOUP_MAKE_TYPE (soup_address, SoupAddress, class_init, init, PARENT_TYPE)



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

	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (SOUP_ADDRESS_PORT_IS_VALID (port), NULL);

	addr = g_object_new (SOUP_TYPE_ADDRESS, NULL);
	addr->priv->name = g_strdup (name);
	addr->priv->port = port;

	return addr;
}

/**
 * soup_address_new_from_sockaddr:
 * @sa: a pointer to a sockaddr
 * @len: size of @sa
 *
 * Return value: a #SoupAddress equivalent to @sa (or %NULL if @sa's
 * address family isn't supported)
 **/
SoupAddress *
soup_address_new_from_sockaddr (struct sockaddr *sa, int len)
{
	SoupAddress *addr;

	g_return_val_if_fail (sa != NULL, NULL);
	g_return_val_if_fail (SOUP_ADDRESS_FAMILY_IS_VALID (sa->sa_family), NULL);
	g_return_val_if_fail (len == SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE (sa->sa_family), NULL);

	addr = g_object_new (SOUP_TYPE_ADDRESS, NULL);
	addr->priv->sockaddr = g_memdup (sa, len);
	addr->priv->port = ntohs (SOUP_ADDRESS_PORT (addr));
	return addr;
}

/**
 * soup_address_new_any:
 * @family: the address family
 * @port: the port number (usually 0, meaning "any port")
 *
 * Return value: a #SoupAddress corresponding to the "any" address
 * for @family (or %NULL if @family isn't supported), suitable for
 * passing to soup_socket_server_new().
 **/
SoupAddress *
soup_address_new_any (SoupAddressFamily family, guint port)
{
	SoupAddress *addr;

	g_return_val_if_fail (SOUP_ADDRESS_FAMILY_IS_VALID (family), NULL);
	g_return_val_if_fail (SOUP_ADDRESS_PORT_IS_VALID (port), NULL);

	addr = g_object_new (SOUP_TYPE_ADDRESS, NULL);
	addr->priv->port = port;

	addr->priv->sockaddr =
		g_malloc0 (SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE (family));
	SOUP_ADDRESS_FAMILY (addr) = family;
	SOUP_ADDRESS_PORT (addr) = htons (port);

	return addr;
}

/**
 * soup_address_get_name:
 * @addr: a #SoupAddress
 *
 * Return value: the hostname associated with @addr, or %NULL if
 * it is not known.
 **/
const char *
soup_address_get_name (SoupAddress *addr)
{
	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), NULL);

	return addr->priv->name;
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
	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), NULL);

	if (addr->priv->sockaddr && len)
		*len = SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE (SOUP_ADDRESS_FAMILY (addr));

	return addr->priv->sockaddr;
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
	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), NULL);

	if (!addr->priv->sockaddr)
		return NULL;

	if (!addr->priv->physical) {
		addr->priv->physical =
			soup_dns_ntop (SOUP_ADDRESS_DATA (addr),
				       SOUP_ADDRESS_FAMILY (addr));
	}

	return addr->priv->physical;
}

/**
 * soup_address_get_port:
 * @addr: a #SoupAddress
 *
 * Return value: the port associated with @addr
 **/
guint
soup_address_get_port (SoupAddress *addr)
{
	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), 0);

	return addr->priv->port;
}


static guint
update_address_from_entry (SoupAddress *addr, SoupDNSEntry *entry)
{
	struct hostent *h;

	h = soup_dns_entry_get_hostent (entry);
	if (!h)
		return SOUP_STATUS_CANT_RESOLVE;

	if (!addr->priv->name)
		addr->priv->name = g_strdup (h->h_name);

	if (!addr->priv->sockaddr &&
	    SOUP_ADDRESS_FAMILY_IS_VALID (h->h_addrtype) &&
	    SOUP_ADDRESS_FAMILY_DATA_SIZE (h->h_addrtype) == h->h_length) {
		addr->priv->sockaddr = g_malloc0 (SOUP_ADDRESS_FAMILY_SOCKADDR_SIZE (h->h_addrtype));
		SOUP_ADDRESS_FAMILY (addr) = h->h_addrtype;
		SOUP_ADDRESS_PORT (addr) = htons (addr->priv->port);
		memcpy (SOUP_ADDRESS_DATA (addr), h->h_addr, h->h_length);
	}

	soup_dns_free_hostent (h);

	if (addr->priv->name && addr->priv->sockaddr)
		return SOUP_STATUS_OK;
	else
		return SOUP_STATUS_CANT_RESOLVE;
}

static gboolean
idle_check_lookup (gpointer user_data)
{
	SoupAddress *addr = user_data;
	guint status;

	if (addr->priv->name && addr->priv->sockaddr) {
		addr->priv->idle_id = 0;
		g_signal_emit (addr, signals[DNS_RESULT], 0, SOUP_STATUS_OK);
		return FALSE;
	}

	if (!soup_dns_entry_check_lookup (addr->priv->lookup))
		return TRUE;

	status = update_address_from_entry (addr, addr->priv->lookup);
	addr->priv->lookup = NULL;
	addr->priv->idle_id = 0;

	g_signal_emit (addr, signals[DNS_RESULT], 0, status);
	return FALSE;
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
	g_return_if_fail (SOUP_IS_ADDRESS (addr));

	if (callback) {
		soup_signal_connect_once (addr, "dns_result",
					  G_CALLBACK (callback), user_data);
	}

	if (addr->priv->idle_id)
		return;

	if (!addr->priv->sockaddr) {
		addr->priv->lookup =
			soup_dns_entry_from_name (addr->priv->name);
	} else if (!addr->priv->name) {
		addr->priv->lookup =
			soup_dns_entry_from_addr (SOUP_ADDRESS_DATA (addr),
						  SOUP_ADDRESS_FAMILY (addr));
	}

	addr->priv->idle_id = g_idle_add (idle_check_lookup, addr);
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
	SoupDNSEntry *entry;

	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), SOUP_STATUS_MALFORMED);

	if (addr->priv->name)
		entry = soup_dns_entry_from_name (addr->priv->name);
	else {
		entry = soup_dns_entry_from_addr (SOUP_ADDRESS_DATA (addr),
						  SOUP_ADDRESS_FAMILY (addr));
	}

	return update_address_from_entry (addr, entry);
}
