/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket-unix.c: Unix socket networking code.
 *
 * Authors:
 *      David Helder  (dhelder@umich.edu)
 *      Alex Graveley (alex@ximian.com)
 *
 * Original code compliments of David Helder's GNET Networking Library, and is
 * Copyright (C) 2000  David Helder & Andrew Lanoix.
 *
 * This is not originally my code.  I've tried to clean it up where possible.
 * But I make no promises towards its sanity.
 *
 * All else Copyright (C) 2000, Ximian, Inc. 
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "soup-private.h"
#include "soup-socket.h"

#include <netdb.h>
#include <resolv.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifndef PTRACE_ATTACH
#  ifdef PT_ATTACH
#    define SOUP_PTRACE_ATTACH PT_ATTACH
#    define SOUP_PTRACE_DETACH PT_DETACH
#  endif
#else
#  define SOUP_PTRACE_ATTACH PTRACE_ATTACH
#  define SOUP_PTRACE_DETACH PTRACE_DETACH
#endif

#ifndef socklen_t
#define socklen_t size_t
#endif

/*
 * Maintains a list of all currently valid SoupAddresses or active
 * SoupAddressState lookup requests.
 */
GHashTable *active_address_hash = NULL;

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46
#endif

#define SOUP_SOCKADDR_IN(s) (*((struct sockaddr_in*) &s))
#define SOUP_ANY_IO_CONDITION  (G_IO_IN | G_IO_OUT | G_IO_PRI | \
                                G_IO_ERR | G_IO_HUP | G_IO_NVAL)

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

typedef struct {
	gint             sockfd;
	SoupAddress     *addr;
	SoupSocketNewFn  func;
	gpointer         data;
	gint             flags;
	guint            connect_watch;
} SoupSocketState;

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
#ifdef HAVE_GET_HOSTBYNAME_R_SOLARIS
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
#ifdef HAVE_GET_HOSTBYNAME_R_SOLARIS
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

		if (WIFSIGNALED (ret) || WEXITSTATUS (ret) != 1) goto ERROR;

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

		if (state->len < 2) goto ERROR;

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
	cb_list = iter = state->cb_list;
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

	(*cb_func) (&state->ia, SOUP_ADDRESS_STATUS_OK, cb_data);

	while (iter) {
		SoupAddressCbData *cb = iter->data;

		(*cb->func) (&state->ia, SOUP_ADDRESS_STATUS_OK, cb->data);

		g_free (cb);
		iter = iter->next;
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
	struct in_addr inaddr;
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
	inaddr_ok = inet_aton (name, &inaddr) != 0;
#endif
	if (inaddr_ok) {
		ia = g_new0 (SoupAddress, 1);
		ia->ref_count = 1;

		sa_in = (struct sockaddr_in*) &ia->sa;
		sa_in->sin_family = AF_INET;
		sa_in->sin_port = g_htons(port);
		memcpy (&sa_in->sin_addr,
			(char*) &inaddr,
			sizeof(struct in_addr));

		(*func) (ia, SOUP_ADDRESS_STATUS_OK, data);
		return NULL;
	}

	if (!active_address_hash)
		active_address_hash = g_hash_table_new (soup_str_case_hash,
							soup_str_case_equal);
	else {
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
				soup_address_set_port (new_ia, port);
				ia = new_ia;
			}

			(*func) (ia, SOUP_ADDRESS_STATUS_OK, data);

			return NULL;
		} 
		else if (ia && soup_address_get_port (ia) == port) {
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
	 * References exist, clear kill flag.
	 */
	if (ia->ref_count != 0) {
		ia->killme = FALSE;
		return FALSE;
	}

	/*
	 * Kill if marked.  Otherwise mark.
	 */
	if (ia->killme) {
		g_free (ia->name);
		g_free (ia);
		return TRUE;
	} else
		ia->killme = TRUE;

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
		if (ia->name && !zeroref_address_timeout_tag) {
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
		} else
			g_free (ia);
	}
}

static gboolean
soup_address_get_name_cb (GIOChannel* iochannel,
			  GIOCondition condition,
			  gpointer data)
{
	SoupAddressReverseState* state;
	gchar* name = NULL;

	state = (SoupAddressReverseState*) data;

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
			name = g_new (gchar, state->buffer [0] + 1);
			strncpy (name, &state->buffer [1], state->buffer [0]);
			name [state->buffer [0]] = '\0';

			state->ia->name = name;

			/* Remove the watch now in case we don't return
                           immediately */
			g_source_remove (state->watch);

			/* Call back */
			(*state->func) (state->ia,
					SOUP_ADDRESS_STATUS_OK,
					name,
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

static gboolean
soup_socket_new_cb (GIOChannel* iochannel,
		    GIOCondition condition,
		    gpointer data)
{
	SoupSocketState* state = (SoupSocketState*) data;
	SoupSocket* s;
	gint error = 0;
	gint len = sizeof (gint);

	/* Remove the watch now in case we don't return immediately */
	g_source_remove (state->connect_watch);

	if (condition & ~(G_IO_IN | G_IO_OUT)) goto ERROR;

	errno = 0;
	if (getsockopt (state->sockfd,
			SOL_SOCKET,
			SO_ERROR,
			&error,
			&len) != 0) goto ERROR;

	if (error) goto ERROR;

	if (fcntl (state->sockfd, F_SETFL, state->flags) != 0)
		goto ERROR;

	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;
	s->sockfd = state->sockfd;
	s->addr = state->addr;

	(*state->func) (s, SOUP_SOCKET_NEW_STATUS_OK, state->data);

	g_free (state);

	return FALSE;

 ERROR:
	soup_address_unref (state->addr);
	(*state->func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, state->data);
	g_free (state);

	return FALSE;
}

/**
 * soup_socket_new:
 * @addr: Address to connect to.
 * @func: Callback function.
 * @data: User data passed when callback function is called.
 *
 * Connect to a specifed address asynchronously.  When the connection
 * is complete or there is an error, it will call the callback.  It
 * may call the callback before the function returns.  It will call
 * the callback if there is a failure.
 *
 * Returns: ID of the connection which can be used with
 * soup_socket_connect_cancel() to cancel it; NULL on
 * failure.
 **/
SoupSocketNewId
soup_socket_new (SoupAddress      *addr,
		 SoupSocketNewFn   func,
		 gpointer          data)
{
	gint sockfd;
	gint flags;
	SoupSocketState* state;
	GIOChannel *chan;

	g_return_val_if_fail(addr != NULL, NULL);
	g_return_val_if_fail(func != NULL, NULL);

	/* Create socket */
	sockfd = socket (AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

	/* Get the flags (should all be 0?) */
	flags = fcntl (sockfd, F_GETFL, 0);
	if (flags == -1) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

	if (fcntl (sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

	errno = 0;

	/* Connect (but non-blocking!) */
	if (connect (sockfd, &addr->sa, sizeof (addr->sa)) < 0 &&
	    errno != EINPROGRESS) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

	/* Unref in soup_socket_new_cb if failure */
	soup_address_ref (addr);

	/* Connect succeeded, return immediately */
	if (!errno) {
		SoupSocket *s = g_new0 (SoupSocket, 1);
		s->ref_count = 1;
		s->sockfd = sockfd;
		s->addr = addr;

		(*func) (s, SOUP_SOCKET_NEW_STATUS_OK, data);
		return NULL;
	}

	chan = g_io_channel_unix_new (sockfd);

	/* Wait for the connection */
	state = g_new0 (SoupSocketState, 1);
	state->sockfd = sockfd;
	state->addr = addr;
	state->func = func;
	state->data = data;
	state->flags = flags;
	state->connect_watch = g_io_add_watch (chan,
					       SOUP_ANY_IO_CONDITION,
					       soup_socket_new_cb,
					       state);

	g_io_channel_unref (chan);

	return state;
}

/**
 * soup_socket_new_cancel:
 * @id: ID of the connection.
 *
 * Cancel an asynchronous connection that was started with
 * soup_socket_new().
 **/
void
soup_socket_new_cancel (SoupSocketNewId id)
{
	SoupSocketState* state = (SoupSocketState*) id;

	g_source_remove (state->connect_watch);
	soup_address_unref (state->addr);
	g_free (state);
}

/**
 * soup_socket_server_accept:
 * @socket: #SoupSocket to accept connections from.
 *
 * Accept a connection from the socket.  The socket must have been
 * created using soup_socket_server_new().  This function will
 * block (use soup_socket_server_try_accept() if you don't
 * want to block).  If the socket's #GIOChannel is readable, it DOES
 * NOT mean that this function will not block.
 *
 * Returns: a new #SoupSocket if there is another connect, or NULL if
 * there's an error.
 **/
SoupSocket *
soup_socket_server_accept (SoupSocket *socket)
{
	gint sockfd;
	gint flags;
	struct sockaddr sa;
	socklen_t n;
	fd_set fdset;
	SoupSocket* s;

	g_return_val_if_fail (socket != NULL, NULL);

 try_again:
	FD_ZERO (&fdset);
	FD_SET (socket->sockfd, &fdset);

	if (select (socket->sockfd + 1, &fdset, NULL, NULL, NULL) == -1) {
		if (errno == EINTR) goto try_again;
		return NULL;
	}

	n = sizeof(s->addr->sa);

	if ((sockfd = accept (socket->sockfd, &sa, &n)) == -1) {
		if (errno == EWOULDBLOCK ||
		    errno == ECONNABORTED ||
#ifdef EPROTO		/* OpenBSD does not have EPROTO */
		    errno == EPROTO ||
#endif
		    errno == EINTR)
			goto try_again;

		return NULL;
	}

	/* Get the flags (should all be 0?) */
	flags = fcntl (sockfd, F_GETFL, 0);
	if (flags == -1) return NULL;

	/* Make the socket non-blocking */
	if (fcntl (sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
		return NULL;

	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;
	s->sockfd = sockfd;

	s->addr = g_new0 (SoupAddress, 1);
	s->addr->ref_count = 1;
	memcpy (&s->addr->sa, &sa, sizeof (s->addr->sa));

	return s;
}

/**
 * soup_socket_server_try_accept:
 * @socket: SoupSocket to accept connections from.
 *
 * Accept a connection from the socket without blocking.  The socket
 * must have been created using soup_socket_server_new().  This
 * function is best used with the sockets #GIOChannel.  If the
 * channel is readable, then you PROBABLY have a connection.  It is
 * possible for the connection to close by the time you call this, so
 * it may return NULL even if the channel was readable.
 *
 * Returns a new SoupSocket if there is another connect, or NULL
 * otherwise.
 **/
SoupSocket *
soup_socket_server_try_accept (SoupSocket *socket)
{
	gint sockfd;
	gint flags;
	struct sockaddr sa;
	socklen_t n;
	fd_set fdset;
	SoupSocket* s;
	struct timeval tv = {0, 0};

	g_return_val_if_fail (socket != NULL, NULL);

 try_again:
	FD_ZERO (&fdset);
	FD_SET (socket->sockfd, &fdset);

	if (select (socket->sockfd + 1, &fdset, NULL, NULL, &tv) == -1) {
		if (errno == EINTR) goto try_again;
		return NULL;
	}

	n = sizeof(sa);

	if ((sockfd = accept (socket->sockfd, &sa, &n)) == -1) {
		/* If we get an error, return.  We don't want to try again as we
		   do in soup_socket_server_accept() - it might cause a
		   block. */
		return NULL;
	}

	/* Get the flags (should all be 0?) */
	flags = fcntl (sockfd, F_GETFL, 0);
	if (flags == -1) return NULL;

	/* Make the socket non-blocking */
	if (fcntl (sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
		return NULL;

	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;
	s->sockfd = sockfd;

	s->addr = g_new0 (SoupAddress, 1);
	s->addr->ref_count = 1;
	memcpy (&s->addr->sa, &sa, sizeof (s->addr->sa));

	return s;
}
