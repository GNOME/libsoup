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
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include "soup-private.h"
#include "soup-address.h"
#include "soup-dns.h"

struct SoupAddressPrivate {
	char *name;
	int   family;
	union {
		struct in_addr  in;
#ifdef HAVE_IPV6
		struct in6_addr in6;
#endif
	} addr;
};

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

	if (addr->priv->name)
		g_free (addr->priv->name);

	g_free (addr->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;
}

SOUP_MAKE_TYPE (soup_address, SoupAddress, class_init, init, PARENT_TYPE)


static void
soup_address_new_sync_cb (SoupAddress       *addr,
			  SoupAddressStatus  status,
			  gpointer           user_data)
{
	SoupAddress **ret = user_data;
	*ret = addr;
}

/**
 * soup_address_new_sync:
 * @name: a hostname, as with soup_address_new()
 *
 * Return value: a #SoupAddress, or %NULL if the lookup fails.
 **/
SoupAddress *
soup_address_new_sync (const char *name)
{
	SoupAddress *ret = (SoupAddress *) 0xdeadbeef;

	soup_address_new (name, soup_address_new_sync_cb, &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (SoupAddress *) 0xdeadbeef) return ret;
	}

	return ret;
}

static SoupAddress *
new_address (const char *name, int family, gpointer addr_data)
{
	SoupAddress *addr;

	addr = g_object_new (SOUP_TYPE_ADDRESS, NULL);
	if (name)
		addr->priv->name = g_strdup (name);
	addr->priv->family = family;

	switch (family) {
	case AF_INET:
		memcpy (&addr->priv->addr.in, addr_data,
			sizeof (addr->priv->addr.in));
		break;

#ifdef HAVE_IPV6
	case AF_INET6:
		memcpy (&addr->priv->addr.in6, addr_data,
			sizeof (addr->priv->addr.in6));
		break;
#endif

	default:
		g_object_unref (addr);
		addr = NULL;
	}

	return addr;
}

/**
 * soup_address_new_from_sockaddr:
 * @sa: a pointer to a sockaddr
 * @port: pointer to a variable to store @sa's port number in
 *
 * This parses @sa and returns its address as a #SoupAddress
 * and its port in @port. @sa can point to a #sockaddr_in or
 * (if soup was compiled with IPv6 support) a #sockaddr_in6.
 *
 * Return value: a #SoupAddress, or %NULL if the lookup fails.
 **/
SoupAddress *
soup_address_new_from_sockaddr (struct sockaddr *sa, guint *port)
{
	switch (sa->sa_family) {
	case AF_INET:
	{
		struct sockaddr_in *sa_in = (struct sockaddr_in *)sa;

		if (port)
			*port = g_ntohs (sa_in->sin_port);
		return new_address (NULL, AF_INET, &sa_in->sin_addr);
	}

#ifdef HAVE_IPV6
	case AF_INET6:
	{
		struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *)sa;

		if (port)
			*port = g_ntohs (sa_in6->sin6_port);
		return new_address (NULL, AF_INET6, &sa_in6->sin6_addr);
	}
#endif

	default:
		return NULL;
	}
}

/**
 * soup_address_ipv4_any:
 *
 * Return value: a #SoupAddress corresponding to %INADDR_ANY, suitable
 * for passing to soup_socket_server_new().
 **/
SoupAddress *
soup_address_ipv4_any (void)
{
	static SoupAddress *ipv4_any = NULL;

	if (!ipv4_any) {
		struct sockaddr_in sa_in;

		sa_in.sin_family = AF_INET;
		sa_in.sin_addr.s_addr = INADDR_ANY;
		ipv4_any = soup_address_new_from_sockaddr ((struct sockaddr *)&sa_in, NULL);
	}

	g_object_ref (ipv4_any);
	return ipv4_any;
}

/**
 * soup_address_ipv6_any:
 *
 * Return value: If soup was compiled without IPv6 support, %NULL.
 * Otherwise, a #SoupAddress corresponding to the IPv6 address "::",
 * suitable for passing to soup_socket_server_new().
 **/
SoupAddress *
soup_address_ipv6_any (void)
{
	static SoupAddress *ipv6_any = NULL;

#ifdef HAVE_IPV6
	if (!ipv6_any) {
		struct sockaddr_in6 sa_in6;

		sa_in6.sin6_family = AF_INET6;
		sa_in6.sin6_addr = in6addr_any;
		ipv6_any = soup_address_new_from_sockaddr ((struct sockaddr *)&sa_in6, NULL);
	}

	g_object_ref (ipv6_any);
#endif
	return ipv6_any;
}

static void
soup_address_get_name_sync_cb (SoupAddress       *addr,
			       SoupAddressStatus  status,
			       const char        *name,
			       gpointer           user_data)
{
	const char **ret = user_data;
	*ret = name;
}

/**
 * soup_address_get_name_sync:
 * @addr: a #SoupAddress
 *
 * Return value: the hostname associated with @addr, as with
 * soup_address_get_name().
 **/
const char *
soup_address_get_name_sync (SoupAddress *addr)
{
	const char *ret = (const char *) 0xdeadbeef;

	soup_address_get_name (addr, soup_address_get_name_sync_cb, &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (const char *) 0xdeadbeef) return ret;
	}

	return ret;
}

/**
 * soup_address_get_canonical_name:
 * @addr: Address to get the canonical name of.
 *
 * Get the "canonical" name of an address (eg, for IP4 the dotted
 * decimal name 141.213.8.59).
 *
 * Returns: %NULL if there was an error.  The caller is responsible
 * for deleting the returned string.
 **/
char *
soup_address_get_canonical_name (SoupAddress *addr)
{
	switch (addr->priv->family) {
	case AF_INET:
	{
#ifdef HAVE_INET_NTOP
		char buffer[INET_ADDRSTRLEN];

		inet_ntop (addr->priv->family, &addr->priv->addr.in,
			   buffer, sizeof (buffer));
		return g_strdup (buffer);
#else
		return g_strdup (inet_ntoa (addr->priv->addr.in));
#endif
	}

#ifdef HAVE_IPV6
	case AF_INET6:
	{
		char buffer[INET6_ADDRSTRLEN];

		inet_ntop (addr->priv->family, &addr->priv->addr.in6,
			   buffer, sizeof (buffer));
		return g_strdup (buffer);
	}
#endif

	default:
		return NULL;
	}
}

/**
 * soup_address_make_sockaddr:
 * @addr: The %SoupAddress.
 * @port: The port number
 * @sa: Pointer to struct sockaddr * to output the sockaddr into
 * @len: Pointer to int to return the size of the sockaddr into
 *
 * This creates an appropriate struct sockaddr for @addr and @port
 * and outputs it into *@sa. The caller must free *@sa with g_free().
 **/
void
soup_address_make_sockaddr (SoupAddress *addr, guint port,
			    struct sockaddr **sa, int *len)
{
	switch (addr->priv->family) {
	case AF_INET:
	{
		struct sockaddr_in sa_in;

		memset (&sa_in, 0, sizeof (sa_in));
		sa_in.sin_family = AF_INET;
		memcpy (&sa_in.sin_addr, &addr->priv->addr.in,
			sizeof (sa_in.sin_addr));
		sa_in.sin_port = g_htons (port);

		*sa = g_memdup (&sa_in, sizeof (sa_in));
		*len = sizeof (sa_in);
		break;
	}

#ifdef HAVE_IPV6
	case AF_INET6:
	{
		struct sockaddr_in6 sa_in6;

		memset (&sa_in6, 0, sizeof (sa_in6));
		sa_in6.sin6_family = AF_INET6;
		memcpy (&sa_in6.sin6_addr, &addr->priv->addr.in6,
			sizeof (sa_in6.sin6_addr));
		sa_in6.sin6_port = g_htons (port);

		*sa = g_memdup (&sa_in6, sizeof (sa_in6));
		*len = sizeof (sa_in6);
		break;
	}
#endif
	default:
		*sa = NULL;
		*len = 0;
	}
}

/**
 * soup_address_hash:
 * @p: Pointer to an #SoupAddress.
 *
 * Hash the address.  This is useful for glib containers.
 *
 * Returns: hash value.
 **/
guint
soup_address_hash (const gpointer p)
{
	const SoupAddress *addr;

	g_return_val_if_fail (p != NULL, 0);

	addr = (const SoupAddress*) p;

	/* This isn't network byte-order transparent... (Not sure how
	 * that works in the v6 case.)
	 */

	switch (addr->priv->family) {
	case AF_INET:
		return addr->priv->addr.in.s_addr;
#ifdef HAVE_IPV6
	case AF_INET6:
	{
		guint32 *bytes = (guint32 *)&(addr->priv->addr.in6.s6_addr);
		return (bytes[0] ^ bytes[1] ^ bytes[2] ^ bytes[3]);
	}
#endif
	default:
		return 0;
	}
}

/**
 * soup_address_equal:
 * @p1: Pointer to first #SoupAddress.
 * @p2: Pointer to second #SoupAddress.
 *
 * Compare two #SoupAddress structures.
 *
 * Returns: 1 if they are the same; 0 otherwise.
 **/
gint
soup_address_equal (const gpointer p1, const gpointer p2)
{
	const SoupAddress *addr1 = (const SoupAddress*) p1;
	const SoupAddress *addr2 = (const SoupAddress*) p2;

	g_return_val_if_fail (p1 != NULL && p2 != NULL, TRUE);

	/* Note network byte order doesn't matter */
	return memcmp (&addr1->priv->addr, &addr2->priv->addr,
		       sizeof (addr1->priv->addr)) == 0;
}


typedef struct {
	SoupDNSHandle    handle;
	SoupAddressNewFn func;
	gpointer         data;
} SoupAddressLookupState;

typedef struct {
	SoupAddress          *addr;
	SoupDNSHandle         handle;
	SoupAddressGetNameFn  func;
	gpointer              data;
} SoupAddressReverseState;

static void
soup_address_new_cb (SoupDNSHandle handle, SoupKnownErrorCode status,
		     struct hostent *h, gpointer data)
{
	SoupAddressLookupState *state = (SoupAddressLookupState*) data;
	SoupAddress *addr = NULL;

	if (status == SOUP_ERROR_OK)
		addr = new_address (h->h_name, h->h_addrtype, h->h_addr);

	state->func (addr, 
		     addr ? SOUP_ADDRESS_STATUS_OK : SOUP_ADDRESS_STATUS_ERROR,
		     state->data);
	g_free (state);
}

/**
 * soup_address_new:
 * @name: a nice name (eg, mofo.eecs.umich.edu) or a dotted decimal name
 *   (eg, 141.213.8.59).
 * @func: Callback function.
 * @data: User data passed when callback function is called.
 *
 * Create a SoupAddress from a name asynchronously. Once the structure
 * is created, it will call the callback. It will call the callback if
 * there is a failure.
 *
 * Currently this routine forks and does the lookup, which can cause
 * some problems. In general, this will work ok for most programs most
 * of the time. It will be slow or even fail when using operating
 * systems that copy the entire process when forking.
 *
 * If you need to lookup a lot of addresses, you should call
 * g_main_iteration(FALSE) between calls. This will help prevent an
 * explosion of processes.
 *
 * Returns: ID of the lookup which can be used with
 * soup_address_new_cancel() to cancel it;
 **/
SoupAddressNewId
soup_address_new (const char *name, SoupAddressNewFn func, gpointer data)
{
	SoupAddressLookupState *state;

	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	state = g_new0 (SoupAddressLookupState, 1);
	state->func = func;
	state->data = data;
	state->handle = soup_gethostbyname (name, soup_address_new_cb, state);

	return state;
}

/**
 * soup_address_new_cancel:
 * @id: ID of the lookup
 *
 * Cancel an asynchronous SoupAddress creation that was started with
 * soup_address_new(). The lookup's callback will not be called.
 */
void
soup_address_new_cancel (SoupAddressNewId id)
{
	SoupAddressLookupState *state = id;

	soup_gethostby_cancel (state->handle);
	g_free (state);
}

static void
soup_address_get_name_cb (SoupDNSHandle handle, SoupKnownErrorCode status,
			  struct hostent *h, gpointer data)
{
	SoupAddressReverseState *state = data;

	if (status == SOUP_ERROR_OK && !state->addr->priv->name)
		state->addr->priv->name = g_strdup (h->h_name);

	state->func (state->addr, 
		     state->addr->priv->name ? SOUP_ADDRESS_STATUS_OK : SOUP_ADDRESS_STATUS_ERROR,
		     state->addr->priv->name,
		     state->data);

	g_object_unref (state->addr);
	g_free (state);
}

/**
 * soup_address_get_name:
 * @addr: Address to get the name of.
 * @func: Callback function.
 * @data: User data passed when callback function is called.
 *
 * Get the nice name of the address (eg, "mofo.eecs.umich.edu").
 * This function will use the callback once it knows the nice name
 * or if there is an error.
 *
 * As with soup_address_new(), this forks to do the lookup.
 *
 * Returns: ID of the lookup which can be used with
 * soup_address_get_name_cancel() to cancel it;
 **/
SoupAddressGetNameId
soup_address_get_name (SoupAddress          *addr,
		       SoupAddressGetNameFn  func,
		       gpointer              data)
{
	SoupAddressReverseState *state;

	g_return_val_if_fail (SOUP_IS_ADDRESS (addr), NULL);
	g_return_val_if_fail (func != NULL, NULL);

	state = g_new0 (SoupAddressReverseState, 1);
	state->addr = g_object_ref (addr);
	state->func = func;
	state->data = data;
	state->handle = soup_gethostbyaddr (&addr->priv->addr,
					    addr->priv->family,
					    soup_address_get_name_cb,
					    state);

	return state;
}

/**
 * soup_address_get_name_cancel:
 * @id: ID of the lookup
 *
 * Cancel an asynchronous nice name lookup that was started with
 * soup_address_get_name().
 */
void
soup_address_get_name_cancel (SoupAddressGetNameId id)
{
	SoupAddressReverseState *state = id;

	g_return_if_fail (state != NULL);

	soup_gethostby_cancel (state->handle);
	g_object_unref (state->addr);
	g_free(state);
}
