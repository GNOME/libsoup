/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-address.c: Internet address handing
 *
 * Authors:
 *      David Helder  (dhelder@umich.edu)
 *      Alex Graveley (alex@ximian.com)
 *
 * Original code compliments of David Helder's GNET Networking Library, and is
 * Copyright (C) 2000  David Helder & Andrew Lanoix.
 *
 * All else Copyright (C) 2000-2002, Ximian, Inc.
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

struct _SoupAddress {
	gchar*          name;
	int             family;
	union {
		struct in_addr  in;
#ifdef HAVE_IPV6
		struct in6_addr in6;
#endif
	} addr;

	gint            ref_count;
	gint            cached;
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
soup_address_new_from_sockaddr (struct sockaddr *sa,
				guint *port)
{
	SoupAddress *ia;

	ia = g_new0 (SoupAddress, 1);
	ia->ref_count = 1;
	ia->family = sa->sa_family;

	switch (ia->family) {
	case AF_INET:
	{
		struct sockaddr_in *sa_in = (struct sockaddr_in *)sa;

		memcpy (&ia->addr.in, &sa_in->sin_addr, sizeof (ia->addr.in));
		if (port)
			*port = g_ntohs (sa_in->sin_port);
		break;
	}

#ifdef HAVE_IPV6
	case AF_INET6:
	{
		struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *)sa;

		memcpy (&ia->addr.in6, &sa_in6->sin6_addr, sizeof (ia->addr.in6));
		if (port)
			*port = g_ntohs (sa_in6->sin6_port);
		break;
	}
#endif

	default:
		g_free (ia);
		ia = NULL;
		break;
	}

	return ia;
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

	soup_address_ref (ipv4_any);
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

	soup_address_ref (ipv6_any);
#endif
	return ipv6_any;
}

/**
 * soup_address_ref
 * @ia: SoupAddress to reference
 *
 * Increment the reference counter of the SoupAddress.
 **/
void
soup_address_ref (SoupAddress* ia)
{
	g_return_if_fail (ia != NULL);

	++ia->ref_count;
}

/**
 * soup_address_copy
 * @ia: SoupAddress to copy
 *
 * Creates a copy of the given SoupAddress
 **/
SoupAddress *
soup_address_copy (SoupAddress* ia)
{
	SoupAddress* new_ia;
	g_return_val_if_fail (ia != NULL, NULL);

	new_ia = g_new0 (SoupAddress, 1);
	new_ia->ref_count = 1;

	new_ia->name = g_strdup (ia->name);
	new_ia->family = ia->family;
	memcpy (&new_ia->addr, &ia->addr, sizeof (new_ia->addr));

	return new_ia;
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
 * @ia: a #SoupAddress
 *
 * Return value: the hostname associated with @ia, as with
 * soup_address_get_name().
 **/
const char *
soup_address_get_name_sync (SoupAddress *ia)
{
	const char *ret = (const char *) 0xdeadbeef;

	soup_address_get_name (ia, soup_address_get_name_sync_cb, &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (const char *) 0xdeadbeef) return ret;
	}

	return ret;
}

/**
 * soup_address_get_canonical_name:
 * @ia: Address to get the canonical name of.
 *
 * Get the "canonical" name of an address (eg, for IP4 the dotted
 * decimal name 141.213.8.59).
 *
 * Returns: %NULL if there was an error.  The caller is responsible
 * for deleting the returned string.
 **/
char*
soup_address_get_canonical_name (SoupAddress* ia)
{
	switch (ia->family) {
	case AF_INET:
	{
#ifdef HAVE_INET_NTOP
		char buffer[INET_ADDRSTRLEN];

		inet_ntop (ia->family, &ia->addr.in, buffer, sizeof (buffer));
		return g_strdup (buffer);
#else
		return g_strdup (inet_ntoa (ia->addr.in));
#endif
	}

#ifdef HAVE_IPV6
	case AF_INET6:
	{
		char buffer[INET6_ADDRSTRLEN];

		inet_ntop (ia->family, &ia->addr.in6, buffer, sizeof (buffer));
		return g_strdup (buffer);
	}
#endif

	default:
		return NULL;
	}
}

/**
 * soup_address_make_sockaddr:
 * @ia: The %SoupAddress.
 * @port: The port number
 * @sa: Pointer to struct sockaddr * to output the sockaddr into
 * @len: Pointer to int to return the size of the sockaddr into
 *
 * This creates an appropriate struct sockaddr for @ia and @port
 * and outputs it into *@sa. The caller must free *@sa with g_free().
 **/
void
soup_address_make_sockaddr (SoupAddress *ia, guint port,
			    struct sockaddr **sa, int *len)
{
	switch (ia->family) {
	case AF_INET:
	{
		struct sockaddr_in sa_in;

		memset (&sa_in, 0, sizeof (sa_in));
		sa_in.sin_family = AF_INET;
		memcpy (&sa_in.sin_addr, &ia->addr.in, sizeof (sa_in.sin_addr));
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
		memcpy (&sa_in6.sin6_addr, &ia->addr.in6, sizeof (sa_in6.sin6_addr));
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
	const SoupAddress* ia;

	g_assert(p != NULL);

	ia = (const SoupAddress*) p;

	/* This isn't network byte-order transparent... (Not sure how
	 * that works in the v6 case.)
	 */

	switch (ia->family) {
	case AF_INET:
		return ia->addr.in.s_addr;
#ifdef HAVE_IPV6
	case AF_INET6:
	{
		guint32 *addr = (guint32 *)&(ia->addr.in6.s6_addr);
		return (addr[0] ^ addr[1] ^ addr[2] ^ addr[3]);
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
	const SoupAddress* ia1 = (const SoupAddress*) p1;
	const SoupAddress* ia2 = (const SoupAddress*) p2;

	g_assert (p1 != NULL && p2 != NULL);

	/* Note network byte order doesn't matter */
	return memcmp (&ia1->addr, &ia2->addr, sizeof (ia1->addr)) == 0;
}

#ifdef G_ENABLE_DEBUG
#  include <sys/ptrace.h>
#  ifndef PTRACE_ATTACH
#    ifdef PT_ATTACH
#      define SOUP_PTRACE_ATTACH PT_ATTACH
#      define SOUP_PTRACE_DETACH PT_DETACH
#    endif
#  else
#    define SOUP_PTRACE_ATTACH PTRACE_ATTACH
#    define SOUP_PTRACE_DETACH PTRACE_DETACH
#  endif
#endif

/* this generally causes problems, so remove from build atm */
#ifdef SOUP_PTRACE_ATTACH
#undef SOUP_PTRACE_ATTACH
#endif

GHashTable *address_hash = NULL, *lookup_hash = NULL;

typedef struct {
	char             *name;

	GSList           *cb_list;    /* CONTAINS: SoupAddressCbData */
	pid_t             pid;
	int               fd;
	guint             watch;
	guchar            buffer [256];
	int               len;
} SoupAddressLookupState;

typedef struct {
	SoupAddressLookupState *state;
	SoupAddressNewFn        func;
	gpointer                data;
} SoupAddressCbData;

typedef struct {
	SoupAddress          *ia;
	SoupAddressGetNameFn  func;
	gpointer              data;

	pid_t                 pid;
	int                   fd;
	guint                 watch;
	guchar                buffer [256 + 1];
	int                   len;
} SoupAddressReverseState;


/* Testing Defines */
/*  #undef   HAVE_GETHOSTBYNAME_R_GLIBC */
/*  #define  HAVE_GETHOSTBYNAME_R_GLIB_MUTEX */

#ifdef HAVE_GETHOSTBYNAME_R_GLIB_MUTEX
G_LOCK_DEFINE (gethostbyname);
#endif

static gboolean
soup_gethostbyname (const char       *hostname,
		    struct sockaddr **sa,
		    int              *sa_len)
{
	struct hostent result_buf, *result = &result_buf;
	char *buf = NULL;

#if defined(HAVE_GETHOSTBYNAME_R_GLIBC)
	{
		size_t len;
		int herr, res;

		len = 1024;
		buf = g_new (char, len);

		while ((res = gethostbyname_r (hostname,
					       &result_buf,
					       buf,
					       len,
					       &result,
					       &herr)) == ERANGE) {
			len *= 2;
			buf = g_renew (char, buf, len);
		}

		if (res || result == NULL || result->h_addr_list [0] == NULL)
			result = NULL;
	}
#elif defined(HAVE_GETHOSTBYNAME_R_SOLARIS)
	{
		size_t len;
		int herr, res;

		len = 1024;
		buf = g_new (char, len);

		while ((res = gethostbyname_r (hostname,
					       &result_buf,
					       buf,
					       len,
					       &herr)) == ERANGE) {
			len *= 2;
			buf = g_renew (char, buf, len);
		}

		if (res)
			result = NULL;
	}
#elif defined(HAVE_GETHOSTBYNAME_R_HPUX)
	{
		struct hostent_data hdbuf;

		if (!gethostbyname_r (hostname, &result_buf, &hdbuf))
			result = NULL;
	}
#else
	{
#if defined(HAVE_GETHOSTBYNAME_R_GLIB_MUTEX)
		G_LOCK (gethostbyname);
#endif
		result = gethostbyname (hostname);
	}
#endif

	if (result) {
		switch (result->h_addrtype) {
		case AF_INET:
		{
			struct sockaddr_in *sa_in;

			sa_in = g_new0 (struct sockaddr_in, 1);
			sa_in->sin_family = AF_INET;
			memcpy (&sa_in->sin_addr, result->h_addr_list[0],
				sizeof (sa_in->sin_addr));

			*sa = (struct sockaddr *)sa_in;
			*sa_len = sizeof (struct sockaddr_in);
			break;
		}
#ifdef HAVE_IPV6
		case AF_INET6:
		{
			struct sockaddr_in6 *sa_in6;

			sa_in6 = g_new0 (struct sockaddr_in6, 1);
			sa_in6->sin6_family = AF_INET6;
			memcpy (&sa_in6->sin6_addr, result->h_addr_list[0],
				sizeof (sa_in6->sin6_addr));

			*sa = (struct sockaddr *)sa_in6;
			*sa_len = sizeof (struct sockaddr_in6);
			break;
		}
#endif
		default:
			result = NULL;
		}
	}

	if (buf)
		g_free (buf);
#if defined(HAVE_GETHOSTBYNAME_R_GLIB_MUTEX)
	G_UNLOCK (gethostbyname);
#endif

	return (result != NULL);
}

/*
 * Thread safe gethostbyaddr (we assume that gethostbyaddr_r follows
 * the same pattern as gethostbyname_r, so we don't have special
 * checks for it in configure.in.
 *
 * Returns the hostname, NULL if there was an error.
 */
static char *
soup_gethostbyaddr (SoupAddress *ia)
{
	struct hostent result_buf, *result = &result_buf;
	char *buf = NULL, *addr;
	int length;
	char *rv;

	switch (ia->family) {
	case AF_INET:
		addr = (char *)&ia->addr.in;
		length = sizeof (ia->addr.in);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		addr = (char *)&ia->addr.in6;
		length = sizeof (ia->addr.in6);
		break;
#endif
	default:
		return NULL;
	}

#if defined(HAVE_GETHOSTBYNAME_R_GLIBC)
	{
		size_t len;
		int herr, res;

		len = 1024;
		buf = g_new (char, len);

		while ((res = gethostbyaddr_r (addr,
					       length,
					       ia->family,
					       &result_buf,
					       buf,
					       len,
					       &result,
					       &herr)) == ERANGE) {
			len *= 2;
			buf = g_renew (char, buf, len);
		}

		if (res || result == NULL || result->h_name == NULL)
			result = NULL;
	}
#elif defined(HAVE_GETHOSTBYNAME_R_SOLARIS)
	{
		size_t len;
		int herr, res;

		len = 1024;
		buf = g_new (char, len);

		while ((res = gethostbyaddr_r (addr,
					       length,
					       ia->family,
					       &result_buf,
					       buf,
					       len,
					       &herr)) == ERANGE) {
			len *= 2;
			buf = g_renew (char, buf, len);
		}

		if (res)
			result = NULL;
	}
#elif defined(HAVE_GETHOSTBYNAME_R_HPUX)
	{
		struct hostent_data hdbuf;

		if (!gethostbyaddr_r (addr, length, ia->family, &result_buf, &hdbuf))
			result = NULL;
	}
#else
	{
#if defined(HAVE_GETHOSTBYNAME_R_GLIB_MUTEX)
		G_LOCK (gethostbyname);
#endif
		result = gethostbyaddr (addr, length, ia->family);
	}
#endif

	if (result)
		rv = g_strdup (result->h_name);
	else
		rv = NULL;
	if (buf)
		g_free (buf);
#if defined(HAVE_GETHOSTBYNAME_R_GLIB_MUTEX)
	G_UNLOCK (gethostbyname);
#endif

	return rv;
}

#define NOT_CACHED 0
#define CACHE_OK 1
#define MARKED_FOR_DELETE 2

static gboolean
soup_address_new_cb (GIOChannel* iochannel,
		     GIOCondition condition,
		     gpointer data)
{
	SoupAddressLookupState *state = (SoupAddressLookupState*) data;
	SoupAddress *ia;
	struct sockaddr *sa;
	int sa_len;
	GSList *iter;

	if (!(condition & G_IO_IN)) {
		int ret;

		g_source_remove (state->watch);
		close (state->fd);
		waitpid (state->pid, &ret, 0);

		if (WIFSIGNALED (ret) || WEXITSTATUS (ret) != 1) 
			goto ERROR;

		/* 
		 * Exit status of one means we are inside a debugger.
		 * Resolve the name synchronously.
		 */
		if (!soup_gethostbyname (state->name, &sa, &sa_len))
			g_warning ("Problem resolving host name");
	} else {
		int rv;
		char* buf;
		int length;

		buf = &state->buffer [state->len];
		length = sizeof (state->buffer) - state->len;
		if (length == 0) goto ERROR;

		rv = read (state->fd, buf, length);
		if (rv < 0) goto ERROR;

		state->len += rv;

		/* Return true if there's more to read */
		if ((state->len - 1) != state->buffer [0]) return TRUE;

		if (state->len < 2) 
			goto ERROR;

		/* Success. Copy resolved address. */
		sa = g_malloc (state->len - 1);
		memcpy (sa, state->buffer + 1, state->len - 1);

		/* Cleanup state */
		g_source_remove (state->watch);
		close (state->fd);

		/* FIXME: Wait for HUP signal before doing this */
		waitpid (state->pid, NULL, 0);
	}

	g_hash_table_remove (lookup_hash, state->name);

	ia = soup_address_new_from_sockaddr (sa, NULL);
	g_free (sa);
	ia->name = state->name;
	ia->cached = CACHE_OK;
	g_hash_table_insert (address_hash, ia->name, ia);

	for (iter = state->cb_list; iter; iter = iter->next) {
		SoupAddressCbData *cb = iter->data;

		soup_address_ref (ia);
		(*cb->func) (ia, SOUP_ADDRESS_STATUS_OK, cb->data);

		g_free (cb);
	}
	g_slist_free (state->cb_list);
	g_free (state);

	/* Each callback got its own ref, but we still own the
	 * original ref.
	 */
	soup_address_unref (ia);
	return FALSE;

 ERROR:
	/* Remove the watch now in case we don't return immediately */
	g_source_remove (state->watch);

	/* Error out and cancel each pending lookup. When the
	 * last one is canceled, state will be freed.
	 */
	for (iter = state->cb_list; iter; ) {
		SoupAddressCbData *cb_data = iter->data;

		(*cb_data->func) (NULL,
				  SOUP_ADDRESS_STATUS_ERROR,
				  cb_data->data);

		iter = iter->next;		  
		soup_address_new_cancel (cb_data);
	}

	return FALSE;
}

/**
 * soup_address_new:
 * @name: a nice name (eg, mofo.eecs.umich.edu) or a dotted decimal name
 *   (eg, 141.213.8.59).  You can delete the after the function is called.
 * @func: Callback function.
 * @data: User data passed when callback function is called.
 *
 * Create a SoupAddress from a name asynchronously.  Once the
 * structure is created, it will call the callback.  It may call the
 * callback before the function returns.  It will call the callback
 * if there is a failure.
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
 * soup_address_new_cancel() to cancel it; NULL on immediate
 * success or failure.
 **/
SoupAddressNewId
soup_address_new (const gchar* name, SoupAddressNewFn func, gpointer data)
{
	pid_t pid = -1;
	int pipes [2];
	struct in_addr inaddr;
#ifdef HAVE_IPV6
	struct in6_addr inaddr6;
#endif
	struct sockaddr *sa;
	int sa_len;
	SoupAddress *ia;
	SoupAddressLookupState *state;
	SoupAddressCbData *cb_data;
	GIOChannel *chan;
	int inaddr_ok;

	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	/* Try to read the name as if were dotted decimal */
	inaddr_ok = FALSE;

#if defined(HAVE_INET_PTON)
#ifdef HAVE_IPV6
	if (inet_pton (AF_INET6, name, &inaddr6) != 0)
		inaddr_ok = AF_INET6;
	else
#endif
	if (inet_pton (AF_INET, name, &inaddr) != 0)
		inaddr_ok = AF_INET;
#elif defined(HAVE_INET_ATON)
	if (inet_aton (name, &inaddr) != 0)
		inaddr_ok = AF_INET;
#else
	inaddr.s_addr = inet_addr (name);
	if (inaddr.s_addr == INADDR_NONE)
		inaddr_ok = FALSE;
	else
		inaddr_ok = AF_INET;
#endif

	if (inaddr_ok) {
		ia = g_new0 (SoupAddress, 1);
		ia->ref_count = 1;

		ia->family = inaddr_ok;
		switch (ia->family) {
		case AF_INET:
			memcpy (&ia->addr.in, &inaddr, sizeof (ia->addr.in));
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			memcpy (&ia->addr.in6, &inaddr6, sizeof (ia->addr.in6));
			break;
#endif
		}

		(*func) (ia, SOUP_ADDRESS_STATUS_OK, data);
		return NULL;
	}

	if (!address_hash) {
		address_hash = g_hash_table_new (soup_str_case_hash,
						 soup_str_case_equal);
	} else {
		ia = g_hash_table_lookup (address_hash, name);
		if (ia) {
			soup_address_ref (ia);
			(*func) (ia, SOUP_ADDRESS_STATUS_OK, data);
			return ia;
		}
	}

	if (!lookup_hash) {
		lookup_hash = g_hash_table_new (soup_str_case_hash,
						soup_str_case_equal);
	} else {
		state = g_hash_table_lookup (lookup_hash, name);
		if (state) {
			cb_data = g_new0 (SoupAddressCbData, 1);
			cb_data->state = state;
			cb_data->func = func;
			cb_data->data = data;

			state->cb_list = g_slist_prepend (state->cb_list,
							  cb_data);
			return cb_data;
		}
	}

	/* Check to see if we are doing synchronous DNS lookups */
	if (getenv ("SOUP_SYNC_DNS")) {
		if (!soup_gethostbyname (name, &sa, &sa_len)) {
			g_warning ("Problem resolving host name");
			(*func) (NULL, SOUP_ADDRESS_STATUS_ERROR, data);
			return NULL;
		}

		ia = soup_address_new_from_sockaddr (sa, NULL);
		g_free (sa);

		(*func) (ia, SOUP_ADDRESS_STATUS_OK, data);
		return NULL;
	}

	/* That didn't work - we need to fork */

	/* Open a pipe */
	if (pipe (pipes) == -1) {
		(*func) (NULL, SOUP_ADDRESS_STATUS_ERROR, data);
		return NULL;
	}

 FORK_AGAIN:
	errno = 0;
	pid = fork ();

	switch (pid) {
	case -1:
		if (errno == EAGAIN) {
			/* Yield the processor */
			sleep(0);
			goto FORK_AGAIN;
		}

		/* Else there was a goofy error */
		g_warning ("Fork error: %s (%d)\n",
			   g_strerror (errno),
			   errno);
		close (pipes [0]);
		close (pipes [1]);

		(*func) (NULL, SOUP_ADDRESS_STATUS_ERROR, data);

		return NULL;
	case 0:
		close (pipes [0]);

#ifdef SOUP_PTRACE_ATTACH
		signal (SIGCHLD, SIG_IGN);

		if (ptrace (SOUP_PTRACE_ATTACH, getppid (), NULL, NULL) == -1) {
			/* 
			 * Attach failed; it's probably already being
			 * debugged. 
			 */
			if (errno != EPERM)
				g_warning ("ptrace: Unexpected error: %s",
					   strerror(errno));

			_exit (1);
		}

		/* 
		 * Wait for the SIGSTOP from PTRACE_ATTACH to arrive at the
		 * parent.  
		 */
		waitpid (getppid (), NULL, WUNTRACED);

		if (ptrace (SOUP_PTRACE_DETACH, getppid (), NULL, NULL) == -1)
			g_warning ("ptrace: Detach failed: %s", 
				   strerror(errno));

		kill (getppid(), SIGCONT);
#endif /*SOUP_PTRACE_ATTACH*/

		/* 
		 * Try to get the host by name (ie, DNS) 
		 */
		if (soup_gethostbyname (name, &sa, &sa_len)) {
			guchar size = sa_len;

			if ((write (pipes [1], &size, sizeof(guchar)) == -1) ||
			    (write (pipes [1], sa, sa_len) == -1))
				g_warning ("Problem writing to pipe\n");
		} else {
			/* Write a zero */
			guchar zero = 0;

			if (write (pipes [1], &zero, sizeof(zero)) == -1)
				g_warning ("Problem writing to pipe\n");
		}

		/* Close the socket */
		close (pipes [1]);

		/* Exit (we don't want atexit called, so do _exit instead) */
		_exit (EXIT_SUCCESS);
	default:
		close (pipes [1]);
		
		/* Create a structure for the call back */
		state = g_new0 (SoupAddressLookupState, 1);
		state->name = g_strdup (name);
		state->pid = pid;
		state->fd = pipes [0];

		cb_data = g_new0 (SoupAddressCbData, 1);
		cb_data->state = state;
		cb_data->func = func;
		cb_data->data = data;
		state->cb_list = g_slist_prepend (state->cb_list, cb_data);

		g_hash_table_insert (lookup_hash, state->name, state);

		/* Set up a watch to read from the pipe */
		chan = g_io_channel_unix_new (pipes [0]);
		state->watch =
			g_io_add_watch(
				chan,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				soup_address_new_cb,
				state);
		g_io_channel_unref (chan);

		return cb_data;
	}
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
	SoupAddressCbData *cb_data = (SoupAddressCbData *)id;
	SoupAddressLookupState *state;
	GSList *iter;

	g_return_if_fail (cb_data != NULL);

	state = cb_data->state;

	for (iter = state->cb_list; iter; iter = iter->next) {
		if (iter->data == cb_data)
			break;
	}
	g_return_if_fail (iter != NULL);

	state->cb_list = g_slist_remove_link (state->cb_list, iter);
	g_slist_free_1 (iter);
	g_free (cb_data);

	if (!state->cb_list) {
		g_hash_table_remove (lookup_hash, state->name);
		g_free (state->name);

		g_source_remove (state->watch);
		close (state->fd);
		kill (state->pid, SIGKILL);
		waitpid (state->pid, NULL, 0);

		g_free (state);
	}
}

static gboolean 
prune_zeroref_addresses_foreach (gchar       *hostname,
				 SoupAddress *ia,
				 gint        *remaining)
{
	/*
	 * References exist, clear mark.
	 */
	if (ia->ref_count != 0) {
		ia->cached = CACHE_OK;
		return FALSE;
	}

	/*
	 * Kill if marked.  Otherwise mark.
	 */
	if (ia->cached == MARKED_FOR_DELETE) {
		g_free (ia->name);
		g_free (ia);
		return TRUE;
	} else
		ia->cached = MARKED_FOR_DELETE;

	/*
	 * Make sure the timeout stays around
	 */
	(*remaining)++;

	return FALSE;
}

static guint zeroref_address_timeout_tag = 0;

static gboolean 
prune_zeroref_addresses_timeout (gpointer not_used)
{
	gint remaining = 0;

	if (!address_hash)
		goto REMOVE_SOURCE;

	/*
	 * Remove all marked addresses, mark zero references.
	 */
	g_hash_table_foreach_remove (address_hash, 
				     (GHRFunc) prune_zeroref_addresses_foreach,
				     &remaining);

	/*
	 * No new marks, so remove timeout handler
	 */
	if (remaining == 0) 
		goto REMOVE_SOURCE;

	return TRUE;

 REMOVE_SOURCE:
	zeroref_address_timeout_tag = 0;
	return FALSE;
}

/**
 * soup_address_unref
 * @ia: SoupAddress to unreference
 *
 * Remove a reference from the SoupAddress.  When reference count
 * reaches 0, the address is deleted.
 **/
void
soup_address_unref (SoupAddress* ia)
{
	g_return_if_fail (ia != NULL);

	--ia->ref_count;

	if (ia->ref_count == 0) {
		if (ia->cached == NOT_CACHED) {
			g_free (ia->name);
			g_free (ia);
		}
		else if (!zeroref_address_timeout_tag) {
			/* 
			 * Cleanup zero reference addresses every 2 minutes.
			 *
			 * This involves an initial sweep to mark zero reference
			 * addresses, then on the next sweep marked addresses
			 * still not referenced are freed.
			 */
			zeroref_address_timeout_tag = 
				g_timeout_add (120000, 
					       (GSourceFunc) 
					       prune_zeroref_addresses_timeout,
					       NULL);
		}
	}
}

static gboolean
soup_address_get_name_cb (GIOChannel* iochannel,
			  GIOCondition condition,
			  gpointer data)
{
	SoupAddressReverseState* state = data;

	g_return_val_if_fail (state != NULL, FALSE);

	/* Read from the pipe */
	if (condition & G_IO_IN) {
		int rv;
		char* buf;
		int length;

		buf = &state->buffer [state->len];
		length = sizeof(state->buffer) - state->len;

		if ((rv = read (state->fd, buf, length)) >= 0) {
			state->len += rv;

			/* Return true if there's more to read */
			if ((state->len - 1) != state->buffer [0])
				return TRUE;

			/* Copy the name */
			state->ia->name = g_strndup (&state->buffer [1], 
						     state->buffer [0]);

			/* Remove the watch now in case we don't return
                           immediately */
			g_source_remove (state->watch);

			/* Call back */
			(*state->func) (state->ia,
					SOUP_ADDRESS_STATUS_OK,
					state->ia->name,
					state->data);

			close (state->fd);
			waitpid (state->pid, NULL, 0);
			g_free (state);
			return FALSE;
		}
	}

	/* Remove the watch now in case we don't return immediately */
	g_source_remove (state->watch);

	/* Call back */
	(*state->func) (state->ia,
			SOUP_ADDRESS_STATUS_ERROR,
			NULL,
			state->data);
	soup_address_get_name_cancel (state);
	return FALSE;
}

/**
 * soup_address_get_name:
 * @ia: Address to get the name of.
 * @func: Callback function.
 * @data: User data passed when callback function is called.
 *
 * Get the nice name of the address (eg, "mofo.eecs.umich.edu").
 * This function will use the callback once it knows the nice name.
 * It may even call the callback before it returns.  The callback
 * will be called if there is an error.
 *
 * As with soup_address_new(), this forks to do the lookup.
 *
 * Returns: ID of the lookup which can be used with
 * soup_address_get_name_cancel() to cancel it; NULL on
 * immediate success or failure.
 **/
SoupAddressGetNameId
soup_address_get_name (SoupAddress*         ia,
		       SoupAddressGetNameFn func,
		       gpointer             data)
{
	SoupAddressReverseState* state;
	gchar* name;
	guchar len;
	pid_t pid = -1;
	int pipes [2], lenint;

	g_return_val_if_fail (ia != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	if (ia->name) {
		(func) (ia, SOUP_ADDRESS_STATUS_OK, ia->name, data);
		return NULL;
	}

	/* FIXME: should check SOUP_SYNC_DNS here */

	/* Open a pipe */
	if (pipe (pipes) != 0) {
		(func) (ia, SOUP_ADDRESS_STATUS_ERROR, NULL, data);
		return NULL;
	}

 FORK_AGAIN:
	errno = 0;
	pid = fork ();

	switch (pid) {
	case -1:
		if (errno == EAGAIN) {
			/* Yield the processor */
			sleep(0);
			goto FORK_AGAIN;
		}

		close(pipes[0]);
		close(pipes[1]);

		/* Else there was a goofy error */
		g_warning ("Fork error: %s (%d)\n",
			   g_strerror(errno),
			   errno);

		(*func) (ia, SOUP_ADDRESS_STATUS_ERROR, NULL, data);

		return NULL;
	case 0:
		close(pipes[0]);

		/* Write the name to the pipe.  If we didn't get a name,
		   we just write the canonical name. */
		name = soup_gethostbyaddr (ia);
		if (!name)
			name = soup_address_get_canonical_name (ia);

		lenint = strlen (name);
		if (lenint > 255) {
			g_warning ("Truncating domain name: %s\n", name);
			name [256] = '\0';
			lenint = 255;
		}

		len = lenint;

		if ((write (pipes [1], &len, sizeof(len)) == -1) ||
		    (write (pipes [1], name, len) == -1) )
			g_warning ("Problem writing to pipe\n");

		g_free(name);

		/* Close the socket */
		close(pipes [1]);

		/* Exit (we don't want atexit called, so do _exit instead) */
		_exit(EXIT_SUCCESS);
	default:
		close(pipes[1]);

		soup_address_ref (ia);

		state = g_new0 (SoupAddressReverseState, 1);
		state->ia = ia;
		state->func = func;
		state->data = data;
		state->pid = pid;
		state->fd = pipes [0];

		/* Add a watch */
		state->watch =
			g_io_add_watch(g_io_channel_unix_new (pipes [0]),
				       G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL,
				       soup_address_get_name_cb,
				       state);
		return state;
	}
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
	SoupAddressReverseState* state;
	state = (SoupAddressReverseState*) id;

	g_return_if_fail(state != NULL);

	soup_address_unref (state->ia);
	g_source_remove (state->watch);

	close (state->fd);
	kill (state->pid, SIGKILL);
	waitpid (state->pid, NULL, 0);

	g_free(state);
}
