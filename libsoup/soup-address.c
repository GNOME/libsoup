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
#include <sys/utsname.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>


#include "soup-private.h"
#include "soup-address.h"

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

#define SOUP_SOCKADDR_IN(s) (*((struct sockaddr_in*) &s))

static void
soup_address_new_sync_cb (SoupAddress *addr,
			  SoupAddressStatus  status,
			  gpointer           user_data)
{
	SoupAddress **ret = user_data;
	*ret = addr;
}

SoupAddress *
soup_address_new_sync (const gchar *name, const gint port)
{
	SoupAddress *ret = (SoupAddress *) 0xdeadbeef;

	soup_address_new (name, port, soup_address_new_sync_cb, &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (SoupAddress *) 0xdeadbeef) return ret;
	}

	return ret;
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

	new_ia = g_new0(SoupAddress, 1);
	new_ia->ref_count = 1;

	new_ia->name = g_strdup (ia->name);
	memcpy (&new_ia->sa, &ia->sa, sizeof(struct sockaddr));

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

const gchar *
soup_address_get_name_sync (SoupAddress *addr)
{
	const char *ret = (const char *) 0xdeadbeef;

	soup_address_get_name (addr, 
			       soup_address_get_name_sync_cb, 
			       (gpointer) &ret);

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
 * Returns: NULL if there was an error.  The caller is responsible
 * for deleting the returned string.
 **/
gchar*
soup_address_get_canonical_name (SoupAddress* ia)
{
	gchar buffer [INET_ADDRSTRLEN];	/* defined in netinet/in.h */
	guchar* p = (guchar*) &(SOUP_SOCKADDR_IN(ia->sa).sin_addr);

	g_return_val_if_fail (ia != NULL, NULL);

	g_snprintf(buffer,
		   sizeof (buffer),
		   "%d.%d.%d.%d",
		   p [0],
		   p [1],
		   p [2],
		   p [3]);

	return g_strdup (buffer);
}

/**
 * soup_address_get_port:
 * @ia: Address to get the port number of.
 *
 * Get the port number.
 * Returns: the port number.
 */
gint
soup_address_get_port (const SoupAddress* ia)
{
	g_return_val_if_fail(ia != NULL, -1);

	return (gint) g_ntohs (((struct sockaddr_in*) &ia->sa)->sin_port);
}

/**
 * soup_address_get_sockaddr:
 * @ia: The %SoupAddress.
 * @addrlen: Pointer to socklen_t the returned sockaddr's length is to be 
 * placed in.
 *
 * Return value: const pointer to @ia's sockaddr buffer.
 **/
const struct sockaddr *
soup_address_get_sockaddr (SoupAddress *ia, guint *addrlen)
{
	g_return_val_if_fail (ia != NULL, NULL);

	if (addrlen)
		*addrlen = sizeof (struct sockaddr_in);

	return &ia->sa;
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
	guint32 port;
	guint32 addr;

	g_assert(p != NULL);

	ia = (const SoupAddress*) p;

	/* 
	 * We do pay attention to network byte order just in case the hash
	 * result is saved or sent to a different host.  
	 */
	port = (guint32) g_ntohs (((struct sockaddr_in*) &ia->sa)->sin_port);
	addr = g_ntohl (((struct sockaddr_in*) &ia->sa)->sin_addr.s_addr);

	return (port ^ addr);
}

/**
 * soup_address_equal:
 * @p1: Pointer to first #SoupAddress.
 * @p2: Pointer to second #SoupAddress.
 *
 * Compare two #SoupAddress's.
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
	return ((SOUP_SOCKADDR_IN(ia1->sa).sin_addr.s_addr ==
		 SOUP_SOCKADDR_IN(ia2->sa).sin_addr.s_addr) &&
		(SOUP_SOCKADDR_IN(ia1->sa).sin_port ==
		 SOUP_SOCKADDR_IN(ia2->sa).sin_port));
}

/**
 * soup_address_noport_equal:
 * @p1: Pointer to first SoupAddress.
 * @p2: Pointer to second SoupAddress.
 *
 * Compare two #SoupAddress's, but does not compare the port numbers.
 *
 * Returns: 1 if they are the same; 0 otherwise.
 **/
gint
soup_address_noport_equal (const gpointer p1, const gpointer p2)
{
	const SoupAddress* ia1 = (const SoupAddress*) p1;
	const SoupAddress* ia2 = (const SoupAddress*) p2;

	g_assert (p1 != NULL && p2 != NULL);

	/* Note network byte order doesn't matter */
	return (SOUP_SOCKADDR_IN(ia1->sa).sin_addr.s_addr ==
		SOUP_SOCKADDR_IN(ia2->sa).sin_addr.s_addr);
}

/**
 * soup_address_gethostaddr:
 *
 * Get the primary host's #SoupAddress.
 *
 * Returns: the #SoupAddress of the host; NULL if there was an error.
 * The caller is responsible for deleting the returned #SoupAddress.
 **/
SoupAddress *
soup_address_gethostaddr (void)
{
	gchar* name;
	struct sockaddr_in* sa_in, sa;
	SoupAddress* ia = NULL;

	name = soup_address_gethostname ();

	if (name && soup_gethostbyname (name, &sa, NULL)) {
		ia = g_new0 (SoupAddress, 1);
		ia->name = g_strdup (name);
		ia->ref_count = 1;

		sa_in = (struct sockaddr_in*) &ia->sa;
		sa_in->sin_family = AF_INET;
		sa_in->sin_port = 0;
		memcpy (&sa_in->sin_addr, &sa.sin_addr, 4);
        }

	return ia;
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

/*
 * Maintains a list of all currently valid SoupAddresses or active
 * SoupAddressState lookup requests.
 */
GHashTable *active_address_hash = NULL;

typedef struct {
	SoupAddressNewFn  func;
	gpointer          data;
} SoupAddressCbData;

typedef struct {
	SoupAddress       ia;
	SoupAddressNewFn  func;
	gpointer          data;

	GSList           *cb_list;    /* CONTAINS: SoupAddressCbData */
	pid_t             pid;
	int               fd;
	guint             watch;
	guchar            buffer [16];
	int               len;
} SoupAddressState;

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

/**
 * soup_gethostbyname:
 *
 * Thread safe gethostbyname.  The only valid fields are sin_len,
 * sin_family, and sin_addr.
 */
gboolean
soup_gethostbyname(const char*         hostname,
		   struct sockaddr_in* sa,
		   gchar**             nicename)
{
	gboolean rv = FALSE;

#ifdef HAVE_GETHOSTBYNAME_R_GLIBC
	{
		struct hostent result_buf, *result;
		size_t len;
		char* buf;
		int herr;
		int res;

		len = 1024;
		buf = g_new (gchar, len);

		while ((res = gethostbyname_r (hostname,
					       &result_buf,
					       buf,
					       len,
					       &result,
					       &herr)) == ERANGE) {
			len *= 2;
			buf = g_renew (gchar, buf, len);
		}

		if (res || result == NULL || result->h_addr_list [0] == NULL)
			goto done;

		if (sa) {
			sa->sin_family = result->h_addrtype;
			memcpy (&sa->sin_addr,
				result->h_addr_list [0],
				result->h_length);
		}

		if (nicename && result->h_name)
			*nicename = g_strdup (result->h_name);

		rv = TRUE;

	done:
		g_free(buf);
	}
#else
#ifdef HAVE_GETHOSTBYNAME_R_SOLARIS
	{
		struct hostent result;
		size_t len;
		char* buf;
		int herr;
		int res;

		len = 1024;
		buf = g_new (gchar, len);

		while ((res = gethostbyname_r (hostname,
					       &result,
					       buf,
					       len,
					       &herr)) == ERANGE) {
			len *= 2;
			buf = g_renew (gchar, buf, len);
		}

		if (res || hp == NULL || hp->h_addr_list [0] == NULL)
			goto done;

		if (sa) {
			sa->sin_family = result->h_addrtype;
			memcpy (&sa->sin_addr,
				result->h_addr_list [0],
				result->h_length);
		}

		if (nicename && result->h_name)
			*nicename = g_strdup (result->h_name);

		rv = TRUE;

	done:
		g_free(buf);
	}
#else
#ifdef HAVE_GETHOSTBYNAME_R_HPUX
	{
		struct hostent result;
		struct hostent_data buf;
		int res;

		res = gethostbyname_r (hostname, &result, &buf);

		if (res == 0) {
			if (sa) {
				sa->sin_family = result.h_addrtype;
				memcpy (&sa->sin_addr,
					result.h_addr_list [0],
					result.h_length);
			}

			if (nicename && result.h_name)
				*nicename = g_strdup(result.h_name);

			rv = TRUE;
		}
	}
#else
#ifdef HAVE_GETHOSTBYNAME_R_GLIB_MUTEX
	{
		struct hostent* he;

		G_LOCK (gethostbyname);
		he = gethostbyname (hostname);
		G_UNLOCK (gethostbyname);

		if (he != NULL && he->h_addr_list [0] != NULL) {
			if (sa) {
				sa->sin_family = he->h_addrtype;
				memcpy (&sa->sin_addr,
					he->h_addr_list [0],
					he->h_length);
			}

			if (nicename && he->h_name)
				*nicename = g_strdup (he->h_name);

			rv = TRUE;
		}
	}
#else
	{
		struct hostent* he;

		he = gethostbyname (hostname);
		if (he != NULL && he->h_addr_list [0] != NULL) {
			if (sa) {
				sa->sin_family = he->h_addrtype;
				memcpy (&sa->sin_addr,
					he->h_addr_list [0],
					he->h_length);
			}

			if (nicename && he->h_name)
				*nicename = g_strdup (he->h_name);

			rv = TRUE;
		}
	}
#endif
#endif
#endif
#endif

	return rv;
}

/*
   Thread safe gethostbyaddr (we assume that gethostbyaddr_r follows
   the same pattern as gethostbyname_r, so we don't have special
   checks for it in configure.in.

   Returns the hostname, NULL if there was an error.
*/

gchar *
soup_gethostbyaddr (const char* addr, size_t length, int type)
{
	gchar* rv = NULL;

#ifdef HAVE_GETHOSTBYNAME_R_GLIBC
	{
		struct hostent result_buf, *result;
		size_t len;
		char* buf;
		int herr;
		int res;

		len = 1024;
		buf = g_new (gchar, len);

		while ((res = gethostbyaddr_r (addr,
					       length,
					       type,
					       &result_buf,
					       buf,
					       len,
					       &result,
					       &herr)) == ERANGE) {
			len *= 2;
			buf = g_renew (gchar, buf, len);
		}

		if (res || result == NULL || result->h_name == NULL)
			goto done;

		rv = g_strdup(result->h_name);

	done:
		g_free(buf);
	}
#else
#ifdef HAVE_GETHOSTBYNAME_R_SOLARIS
	{
		struct hostent result;
		size_t len;
		char* buf;
		int herr;
		int res;

		len = 1024;
		buf = g_new (gchar, len);

		while ((res = gethostbyaddr_r (addr,
					       length,
					       type,
					       &result,
					       buf,
					       len,
					       &herr)) == ERANGE) {
			len *= 2;
			buf = g_renew (gchar, buf, len);
		}

		if (res || hp == NULL || hp->h_name == NULL)
			goto done;

		rv = g_strdup(result->h_name);

	done:
		g_free(buf);
	}
#else
#ifdef HAVE_GETHOSTBYNAME_R_HPUX
	{
		struct hostent result;
		struct hostent_data buf;
		int res;

		res = gethostbyaddr_r (addr, length, type, &result, &buf);

		if (res == 0) rv = g_strdup (result.h_name);
	}
#else
#ifdef HAVE_GETHOSTBYNAME_R_GLIB_MUTEX
	{
		struct hostent* he;

		G_LOCK (gethostbyname);
		he = gethostbyaddr (addr, length, type);
		G_UNLOCK (gethostbyname);
		if (he != NULL && he->h_name != NULL)
			rv = g_strdup (he->h_name);
	}
#else
	{
		struct hostent* he;

		he = gethostbyaddr (addr, length, type);
		if (he != NULL && he->h_name != NULL)
			rv = g_strdup (he->h_name);
	}
#endif
#endif
#endif
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
	SoupAddressState* state = (SoupAddressState*) data;
	struct sockaddr_in* sa_in;
	GSList *cb_list, *iter;
	SoupAddressNewFn cb_func;
	gpointer cb_data;	

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
		sa_in = (struct sockaddr_in*) &state->ia.sa;

		if (!soup_gethostbyname (state->ia.name, sa_in, NULL))
			g_warning ("Problem resolving host name");
	} else {
		int rv;
		char* buf;
		int length;

		buf = &state->buffer [state->len];
		length = sizeof (state->buffer) - state->len;

		rv = read (state->fd, buf, length);
		if (rv < 0) goto ERROR;

		state->len += rv;

		/* Return true if there's more to read */
		if ((state->len - 1) != state->buffer [0]) return TRUE;

		if (state->len < 2) 
			goto ERROR;

		/* Success. Copy resolved address. */
		sa_in = (struct sockaddr_in*) &state->ia.sa;
		memcpy (&sa_in->sin_addr, &state->buffer [1], (state->len - 1));

		/* Cleanup state */
		g_source_remove (state->watch);
		close (state->fd);

		/* FIXME: Wait for HUP signal before doing this */
		waitpid (state->pid, NULL, 0);
	}

	/* Get state data before realloc */
	cb_list = state->cb_list;
	cb_func = state->func;
	cb_data = state->data;

	/* Invert resolved address reference count */
	state->ia.ref_count = ~state->ia.ref_count + 1;

	/* 
	 * Realloc state to size of SoupAddress, and reinsert to resolved
	 * address table. 
	 */
	state = g_realloc (state, sizeof (SoupAddress));
	g_hash_table_insert (active_address_hash, state->ia.name, state);
	state->ia.cached = CACHE_OK;

	(*cb_func) (&state->ia, SOUP_ADDRESS_STATUS_OK, cb_data);

	for (iter = cb_list; iter; iter = iter->next) {
		SoupAddressCbData *cb = iter->data;

		(*cb->func) (&state->ia, SOUP_ADDRESS_STATUS_OK, cb->data);

		g_free (cb);
	}

	g_slist_free (cb_list);

	return FALSE;

 ERROR:
	/* Remove the watch now in case we don't return immediately */
	g_source_remove (state->watch);

	(*state->func) (NULL, SOUP_ADDRESS_STATUS_ERROR, state->data);

	for (cb_list = state->cb_list; cb_list; cb_list = cb_list->next) {
		SoupAddressCbData *cb_data = cb_list->data;
		(*cb_data->func) (NULL,
				  SOUP_ADDRESS_STATUS_ERROR,
				  cb_data->data);
	}

	/* Force cancel */
	state->ia.ref_count = -1;
	soup_address_new_cancel (state);

	return FALSE;
}

static SoupAddress *
lookup_in_cache_internal (const gchar       *name, 
			  const gint         port,
			  gboolean          *in_progress)
{
	SoupAddress* ia = NULL;

	if (in_progress)
		*in_progress = FALSE;

	if (!active_address_hash)
		return NULL;

	ia = g_hash_table_lookup (active_address_hash, name);

	if (ia && ia->ref_count >= 0) {
		/*
		 * Existing valid request, use it.
		 */
		if (soup_address_get_port (ia) == port) {
			soup_address_ref (ia);
		} else {
			/* 
			 * We can reuse the address, but we have to
			 * change port 
			 */
			SoupAddress *new_ia = soup_address_copy (ia);

			((struct sockaddr_in*) &new_ia->sa)->sin_port = 
				g_htons (port);

			ia = new_ia;
		}
	}
	else if (ia && in_progress)
		*in_progress = TRUE;

	return ia;
}

SoupAddress *
soup_address_lookup_in_cache (const gchar *name, const gint port)
{
	SoupAddress *ia;
	gboolean in_prog;

	ia = lookup_in_cache_internal (name, port, &in_prog);

	if (in_prog) 
		return NULL;

	return ia;
}

/**
 * soup_address_new:
 * @name: a nice name (eg, mofo.eecs.umich.edu) or a dotted decimal name
 *   (eg, 141.213.8.59).  You can delete the after the function is called.
 * @port: port number (0 if the port doesn't matter)
 * @func: Callback function.
 * @data: User data passed when callback function is called.
 *
 * Create a SoupAddress from a name and port asynchronously.  Once the
 * structure is created, it will call the callback.  It may call the
 * callback before the function returns.  It will call the callback
 * if there is a failure.
 *
 * The Unix version forks and does the lookup, which can cause some
 * problems.  In general, this will work ok for most programs most of
 * the time.  It will be slow or even fail when using operating
 * systems that copy the entire process when forking.
 *
 * If you need to lookup a lot of addresses, we recommend calling
 * g_main_iteration(FALSE) between calls.  This will help prevent an
 * explosion of processes.
 *
 * If you need a more robust library for Unix, look at <ulink
 * url="http://www.gnu.org/software/adns/adns.html">GNU ADNS</ulink>.
 * GNU ADNS is under the GNU GPL.
 *
 * The Windows version should work fine.  Windows has an asynchronous
 * DNS lookup function.
 *
 * Returns: ID of the lookup which can be used with
 * soup_address_new_cancel() to cancel it; NULL on immediate
 * success or failure.
 **/
SoupAddressNewId
soup_address_new (const gchar* name,
		  const gint port,
		  SoupAddressNewFn func,
		  gpointer data)
{
	pid_t pid = -1;
	int pipes [2];
#ifdef HAVE_INET_PTON
	struct in_addr inaddr;
#else
#  ifdef HAVE_INET_ATON
	struct in_addr inaddr;
#  else
	in_addr_t inaddr;
#  endif
#endif
	struct sockaddr_in sa;
	struct sockaddr_in* sa_in;
	SoupAddress* ia;
	SoupAddressState* state;
	GIOChannel *chan;
	gboolean inaddr_ok;

	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	/* Try to read the name as if were dotted decimal */
#ifdef HAVE_INET_PTON
	inaddr_ok = inet_pton (AF_INET, name, &inaddr) != 0;
#else
#  ifdef HAVE_INET_ATON
	inaddr_ok = inet_aton (name, &inaddr) != 0;
#  else
	inaddr = inet_addr (name);
	if (inaddr == INADDR_NONE)
		inaddr_ok = FALSE;
	else
		inaddr_ok = TRUE;
#  endif
#endif

	if (inaddr_ok) {
		ia = g_new0 (SoupAddress, 1);
		ia->ref_count = 1;

		sa_in = (struct sockaddr_in*) &ia->sa;
		sa_in->sin_family = AF_INET;
		sa_in->sin_port = g_htons(port);
		memcpy (&sa_in->sin_addr,
			(char*) &inaddr,
			sizeof(inaddr));

		(*func) (ia, SOUP_ADDRESS_STATUS_OK, data);
		return NULL;
	}

	if (!active_address_hash)
		active_address_hash = g_hash_table_new (soup_str_case_hash,
							soup_str_case_equal);
	else {
		gboolean in_prog;

		ia = lookup_in_cache_internal (name, port, &in_prog);
		if (in_prog) {
			/*
			 * Lookup currently in progress.
			 * Add func to list of callbacks in state.
			 * Note that if it's not the same port, we have to do
			 * the lookup again, since there's no way to communicate
			 * the port change.
			 */
			SoupAddressCbData *cb_data;

			cb_data = g_new0 (SoupAddressCbData, 1);
			cb_data->func = func;
			cb_data->data = data;

			state = (SoupAddressState *) ia;
			state->cb_list = g_slist_prepend (state->cb_list,
							  cb_data);

			state->ia.ref_count--;

			return state;
		}
		else if (ia)
			return ia;
	}

	/* Check to see if we are doing synchronous DNS lookups */
	if (getenv ("SOUP_SYNC_DNS")) {
		if (!soup_gethostbyname (name, &sa, NULL)) {
			g_warning ("Problem resolving host name");
			(*func) (NULL, SOUP_ADDRESS_STATUS_ERROR, data);
			return NULL;
		}

		sa_in = (struct sockaddr_in*) &sa;
		sa_in->sin_family = AF_INET;
		sa_in->sin_port = g_htons (port);

		ia = g_new0(SoupAddress, 1);
		ia->name = g_strdup (name);
		ia->ref_count = 1;
		ia->sa = *((struct sockaddr *) &sa);

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
		if (soup_gethostbyname (name, &sa, NULL)) {
			guchar size = 4;	/* FIX for IPv6 */

			if ((write (pipes [1], &size, sizeof(guchar)) == -1) ||
			    (write (pipes [1], &sa.sin_addr, size) == -1))
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
		state = g_new0 (SoupAddressState, 1);
		state->ia.name = g_strdup (name);
		state->ia.ref_count = -1;
		state->func = func;
		state->data = data;
		state->pid = pid;
		state->fd = pipes [0];

		sa_in = (struct sockaddr_in*) &state->ia.sa;
		sa_in->sin_family = AF_INET;
		sa_in->sin_port = g_htons (port);

		g_hash_table_insert (active_address_hash,
				     state->ia.name,
				     state);

		chan = g_io_channel_unix_new (pipes [0]);

		/* Set up an watch to read from the pipe */
		state->watch =
			g_io_add_watch(
				chan,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				soup_address_new_cb,
				state);

		g_io_channel_unref (chan);

		return state;
	}
}

/**
 * soup_address_new_cancel:
 * @id: ID of the lookup
 *
 * Cancel an asynchronous SoupAddress creation that was started with
 * soup_address_new().
 */
void
soup_address_new_cancel (SoupAddressNewId id)
{
	SoupAddressState* state = (SoupAddressState*) id;
	GSList *cb_list;

	g_return_if_fail (state != NULL);

	state->ia.ref_count++;

	if (state->ia.ref_count == 0) {
		g_hash_table_remove (active_address_hash, state->ia.name);
		g_free (state->ia.name);

		for (cb_list = state->cb_list; cb_list; cb_list = cb_list->next)
			g_free (cb_list->data);
		g_slist_free (state->cb_list);

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

	if (!active_address_hash)
		goto REMOVE_SOURCE;

	/*
	 * Remove all marked addresses, mark zero references.
	 */
	g_hash_table_foreach_remove (active_address_hash, 
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
 * The Unix version forks and does the reverse lookup.  This has
 * problems.  See the notes for soup_address_new().  The
 * Windows version should work fine.
 *
 * Returns: ID of the lookup which can be used with
 * soup_addressr_get_name_cancel() to cancel it; NULL on
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
	int pipes [2];

	g_return_val_if_fail (ia != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	if (ia->name) {
		(func) (ia, SOUP_ADDRESS_STATUS_OK, ia->name, data);
		return NULL;
	}

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
		name = soup_gethostbyaddr (
			    (char*) &((struct sockaddr_in*)&ia->sa)->sin_addr,
			    sizeof (struct in_addr),
			    AF_INET);

		if (name) {
			guint lenint = strlen(name);

			if (lenint > 255) {
				g_warning ("Truncating domain name: %s\n",
					   name);
				name [256] = '\0';
				lenint = 255;
			}

			len = lenint;

			if ((write (pipes [1], &len, sizeof(len)) == -1) ||
			    (write (pipes [1], name, len) == -1) )
				g_warning ("Problem writing to pipe\n");

			g_free(name);
		} else {
			/* defined in netinet/in.h */
			gchar buffer [INET_ADDRSTRLEN];
			guchar* p;
			p = (guchar*) &(SOUP_SOCKADDR_IN (ia->sa).sin_addr);

			g_snprintf(buffer,
				   sizeof (buffer),
				   "%d.%d.%d.%d",
				   p [0],
				   p [1],
				   p [2],
				   p [3]);
			len = strlen (buffer);

			if ((write (pipes [1], &len, sizeof(len)) == -1) ||
			    (write (pipes [1], buffer, len) == -1))
				g_warning ("Problem writing to pipe\n");
		}

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

/**
 * soup_address_gethostname:
 *
 * Get the primary host's name.
 *
 * Returns: the name of the host; NULL if there was an error.  The
 * caller is responsible for deleting the returned string.
 **/
gchar*
soup_address_gethostname (void)
{
	gchar* name = NULL;
	struct utsname myname;

	if (uname (&myname) < 0) return NULL;

	if (!soup_gethostbyname (myname.nodename, NULL, &name)) return NULL;

	return name;
}
