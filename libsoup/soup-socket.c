/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      David Helder  (dhelder@umich.edu)
 *      Alex Graveley (alex@helixcode.com)
 *
 * Original code compliments of David Helder's GNET Networking Library.
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <glib.h>

#include "soup-private.h"
#include "soup-socket.h"

#ifndef SOUP_WIN32  /*********** Unix specific ***********/

#include <unistd.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <sys/time.h>

#include <sys/utsname.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

#ifndef socklen_t
#define socklen_t size_t
#endif

#define SOUP_CLOSE_SOCKET(SOCKFD) close(SOCKFD)
#define SOUP_SOCKET_IOCHANNEL_NEW(SOCKFD) g_io_channel_unix_new(SOCKFD)

/*
 * Maintains a list of all currently valid SoupAddresses or active
 * SoupAddressState lookup requests.
 */
static GHashTable *active_address_hash = NULL;

#else	/*********** Windows specific ***********/

#include <windows.h>
#include <winbase.h>
#include <winuser.h>
#include <io.h>

#define socklen_t gint32

#define SOUP_CLOSE_SOCKET(SOCKFD) closesocket(SOCKFD)
#define SOUP_SOCKET_IOCHANNEL_NEW(SOCKFD) g_io_channel_win32_new_stream_socket(SOCKFD)

WNDCLASSEX soupWndClass;
HWND  soup_hWnd;
guint soup_io_watch_ID;
GIOChannel *soup_iochannel;

GHashTable *soup_hash;
GHashTable *soup_select_hash; /* soup_socket_new needs its own hash */
HANDLE soup_Mutex;
HANDLE soup_select_Mutex;
HANDLE soup_hostent_Mutex;

#define IA_NEW_MSG 100		/* soup_address_new */
#define GET_NAME_MSG 101	/* soup_address_get_name */
#define TCP_SOCK_MSG 102	/* soup_socket_new  */

/* Windows does not have inet_aton, but it does have inet_addr.  TODO:
   We should write a better inet_aton because inet_addr doesn't catch
   255.255.255.255 properly. */

static int
inet_aton(const char *cp, struct in_addr *inp)
{
	inp->s_addr = inet_addr (cp);
	if (inp->s_addr == INADDR_NONE) return 0;
	return 1;
}

#endif	/*********** End Windows specific ***********/

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
#ifndef SOUP_WIN32
	pid_t             pid;
	int               fd;
	guint             watch;
	guchar            buffer [16];
	int               len;
#else
	int               WSAhandle;
	char              hostentBuffer [MAXGETHOSTSTRUCT];
	int               errorcode;
#endif
} SoupAddressState;


typedef struct {
	SoupAddress          *ia;
	SoupAddressGetNameFn  func;
	gpointer              data;
#ifndef SOUP_WIN32
	pid_t                 pid;
	int                   fd;
	guint                 watch;
	guchar                buffer [256 + 1];
	int                   len;
#else
	int                   WSAhandle;
	char                  hostentBuffer [MAXGETHOSTSTRUCT];
	int                   errorcode;
#endif
} SoupAddressReverseState;


typedef struct {
	gint             sockfd;
	SoupAddress     *addr;
	SoupSocketNewFn  func;
	gpointer         data;
	gint             flags;
	guint            connect_watch;
#ifdef SOUP_WIN32
	gint             errorcode;
#endif
} SoupSocketState;


typedef struct {
	SoupSocketConnectFn  func;
	gpointer             data;

	gpointer             inetaddr_id;
	gpointer             tcp_id;
} SoupSocketConnectState;


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
static gboolean
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
#ifdef SOUP_WIN32
	{
		struct hostent *result;

		WaitForSingleObject (soup_hostent_Mutex, INFINITE);
		result = gethostbyname (hostname);

		if (result != NULL) {
			if (sa) {
				sa->sin_family = result->h_addrtype;
				memcpy (&sa->sin_addr,
					result->h_addr_list [0],
					result->h_length);
			}

			if (nicename && result->h_name)
				*nicename = g_strdup(result->h_name);

			ReleaseMutex(soup_hostent_Mutex);
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
#endif

	return rv;
}

/*
   Thread safe gethostbyaddr (we assume that gethostbyaddr_r follows
   the same pattern as gethostbyname_r, so we don't have special
   checks for it in configure.in.

   Returns the hostname, NULL if there was an error.
*/

static gchar *
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
#ifdef SOUP_WIN32
	{
		struct hostent* he;

		WaitForSingleObject (soup_hostent_Mutex, INFINITE);
		he = gethostbyaddr (addr, length, type);
		if (he != NULL && he->h_name != NULL)
			rv = g_strdup (he->h_name);
		ReleaseMutex (soup_hostent_Mutex);
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
#endif

	return rv;
}

#ifndef SOUP_WIN32  /*********** Unix code ***********/

static gboolean
soup_address_new_cb (GIOChannel* iochannel,
		     GIOCondition condition,
		     gpointer data)
{
	SoupAddressState* state = (SoupAddressState*) data;
	int rv;
	char* buf;
	int length;
	struct sockaddr_in* sa_in;
	GSList *cb_list;

	/* Read from the pipe */
	if (!(condition & G_IO_IN)) goto ERROR;

	buf = &state->buffer [state->len];
	length = sizeof (state->buffer) - state->len;

	rv = read (state->fd, buf, length);
	if (rv < 0) goto ERROR;

	state->len += rv;

	/* Return true if there's more to read */
	if ((state->len - 1) != state->buffer [0]) return TRUE;

	/* We're done reading.  Copy into the addr if we were
	   successful. Otherwise, we got a 0 because there was
	   an error */
	if (state->len < 2) goto ERROR;

	sa_in = (struct sockaddr_in*) &state->ia.sa;
	memcpy (&sa_in->sin_addr, &state->buffer [1], (state->len - 1));

	/* Remove the watch now in case we don't return immediately */
	g_source_remove (state->watch);

	state->ia.ref_count = ~state->ia.ref_count + 1;

	/* Call back */
	(*state->func) (&state->ia, SOUP_ADDRESS_STATUS_OK, state->data);

	for (cb_list = state->cb_list; cb_list; cb_list = cb_list->next) {
		SoupAddressCbData *cb_data = cb_list->data;
		(*cb_data->func) (&state->ia,
				  SOUP_ADDRESS_STATUS_OK,
				  cb_data->data);
		g_free (cb_data);
	}

	g_slist_free (state->cb_list);

	close (state->fd);
	waitpid (state->pid, NULL, 0);

	state = g_realloc (state, sizeof (SoupAddress));
	g_hash_table_insert (active_address_hash, state->ia.name, state);

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

	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	/* Try to read the name as if were dotted decimal */
	if (inet_aton (name, &inaddr) != 0) {
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

		if (ia && ia->ref_count > 0) {
			/*
			 * Existing valid request, use it.
			 */
			soup_address_ref (ia);

			(*func) (ia, SOUP_ADDRESS_STATUS_OK, data);

			return NULL;
		} else if (ia) {
			/*
			 * Lookup currently in progress.
			 * Add func to list of callbacks in state.
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
	if (getenv("SOUP_SYNC_DNS")) {
		if (!soup_gethostbyname(name, &sa, NULL)) {
			g_warning("Problem resolving host name");
			(*func) (NULL, SOUP_ADDRESS_STATUS_ERROR, data);
			return NULL;
		}

		sa_in = (struct sockaddr_in*) &sa;
		sa_in->sin_family = AF_INET;
		sa_in->sin_port = g_htons (port);

		ia = g_new0(SoupAddress, 1);
		ia->name = g_strdup(name);
		ia->ref_count = 1;
		ia->sa = *((struct sockaddr *) &sa);

		(*func)(ia, SOUP_ADDRESS_STATUS_OK, data);

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
			   g_strerror(errno),
			   errno);

		(*func) (NULL, SOUP_ADDRESS_STATUS_ERROR, data);

		return NULL;
	case 0:
		/* Try to get the host by name (ie, DNS) */
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

#else	/*********** Windows code ***********/

static gboolean
soup_address_new_cb (GIOChannel* iochannel,
		     GIOCondition condition,
		     gpointer data)
{
	SoupAddressState* state = (SoupAddressState*) data;
	struct hostent *result;
	struct sockaddr_in *sa_in;

	if (state->errorcode) {
		(*state->func) (&state->ia,
				SOUP_ADDRESS_STATUS_ERROR,
				state->data);
		g_free (state);
		return FALSE;
	}

	result = (struct hostent*) state->hostentBuffer;

	sa_in = (struct sockaddr_in*) &state->ia.sa;
	memcpy (&sa_in->sin_addr, result->h_addr_list [0], result->h_length);

	state->ia.name = g_strdup (result->h_name);

	state = g_realloc (state, sizeof (SoupAddress));

	(*state->func) (&state->ia, SOUP_ADDRESS_STATUS_OK, state->data);
	g_free (state);

	return FALSE;
}

SoupAddressNewId
soup_address_new (const gchar* name,
		  const gint port,
		  SoupAddressNewFn func,
		  gpointer data)
{
	struct in_addr inaddr;
	struct sockaddr_in* sa_in;
	SoupAddressState* state;

	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(func != NULL, NULL);

	/* Try to read the name as if were dotted decimal */

	inaddr.s_addr = inet_addr(name);
	if (inaddr.s_addr != INADDR_NONE) {
		SoupAddress* ia = NULL;
		struct sockaddr_in* sa_in;

		ia = g_new0(SoupAddress, 1);
		ia->ref_count = 1;

		sa_in = (struct sockaddr_in*) &ia->sa;
		sa_in->sin_family = AF_INET;
		sa_in->sin_port = g_htons (port);
		memcpy (&sa_in->sin_addr,
			(char*) &inaddr,
			sizeof (struct in_addr));

		(*func) (ia, SOUP_ADDRESS_STATUS_OK, data);
		return NULL;
	}

	/* Create a structure for the call back */
	state = g_new0 (SoupAddressState, 1);
	state->ia.name = g_strdup (name);
	state->ia.ref_count = 1;
	state->func = func;
	state->data = data;

	sa_in = (struct sockaddr_in*) &state->ia.sa;
	sa_in->sin_family = AF_INET;
	sa_in->sin_port = g_htons (port);

	state->WSAhandle = (int)
		WSAAsyncGetHostByName (soup_hWnd,
				       IA_NEW_MSG,
				       name,
				       state->hostentBuffer,
				       sizeof (state->hostentBuffer));

	if (!state->WSAhandle) {
		g_free (state);
		(*func) (NULL, SOUP_ADDRESS_STATUS_ERROR, data);
		return NULL;
	}

	/*get a lock and insert the state into the hash */
	WaitForSingleObject (soup_Mutex, INFINITE);
	g_hash_table_insert (soup_hash,
			     (gpointer) state->WSAhandle,
			     (gpointer) state);
	ReleaseMutex (soup_Mutex);

	return state;
}

void
soup_address_new_cancel (SoupAddressNewId id)
{
	SoupAddressState* state = (SoupAddressState*) id;

	g_return_if_fail(state != NULL);

	WSACancelAsyncRequest ((HANDLE)state->WSAhandle);

	/*get a lock and remove the hash entry */
	WaitForSingleObject (soup_Mutex, INFINITE);
	g_hash_table_remove (soup_hash, (gpointer) state->WSAhandle);
	ReleaseMutex (soup_Mutex);
	g_free (state);
}

#endif		/*********** End Windows code ***********/

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
 * soup_address_unref
 * @ia: SoupAddress to unreference
 *
 * Remove a reference from the SoupAddress.  When reference count
 * reaches 0, the address is deleted.
 **/
void
soup_address_unref (SoupAddress* ia)
{
	g_return_if_fail(ia != NULL);

	--ia->ref_count;

	if (ia->ref_count == 0) {
		if (ia->name != NULL) {
#ifndef SOUP_WIN32
			g_hash_table_remove (active_address_hash, ia->name);
#endif
			g_free (ia->name);
		}
		g_free (ia);
	}
}

#ifndef SOUP_WIN32  /*********** Unix code ***********/

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

		/* Else there was a goofy error */
		g_warning ("Fork error: %s (%d)\n",
			   g_strerror(errno),
			   errno);

		(*func) (ia, SOUP_ADDRESS_STATUS_ERROR, NULL, data);

		return NULL;
	case 0:
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

#else	/*********** Windows code ***********/

static gboolean
soup_address_get_name_cb (GIOChannel* iochannel,
			  GIOCondition condition,
			  gpointer data)
{
	SoupAddressReverseState* state;
	gchar* name;
	struct hostent* result;
	state = (SoupAddressReverseState*) data;

	result = (struct hostent*) state->hostentBuffer;

	if (state->errorcode) {
		(*state->func) (state->ia,
				SOUP_ADDRESS_STATUS_ERROR,
				NULL,
				state->data);
		return FALSE;
	}

	state->ia->name = g_strdup (result->h_name);
	name = NULL;
	name = g_strdup (state->ia->name);

	(*state->func) (state->ia,
			SOUP_ADDRESS_STATUS_OK,
			name,
			state->data);

	g_free(state);
	return FALSE;
}

SoupAddressGetNameId
soup_address_get_name (SoupAddress* ia,
		       SoupAddressGetNameFn func,
		       gpointer data)
{
	SoupAddressReverseState* state;
	struct sockaddr_in* sa_in;

	g_return_val_if_fail(ia != NULL, NULL);
	g_return_val_if_fail(func != NULL, NULL);

	/* If we already know the name, just copy that */
	if (ia->name != NULL) {
		(func) (ia,
			SOUP_ADDRESS_STATUS_OK,
			g_strdup (ia->name),
			data);
	}

	/* Create a structure for the call back */
	state = g_new0 (SoupAddressReverseState, 1);
	state->ia = ia;
	state->func = func;
	state->data = data;

	sa_in = (struct sockaddr_in*) &ia->sa;

	state->WSAhandle = (int)
		WSAAsyncGetHostByAddr (soup_hWnd, GET_NAME_MSG,
				       (const char*) &sa_in->sin_addr,
				       (int) (sizeof (&sa_in->sin_addr)),
				       (int) &sa_in->sin_family,
				       state->hostentBuffer,
				       sizeof (state->hostentBuffer));

	if (!state->WSAhandle) {
		g_free (state);
		(func) (ia, SOUP_ADDRESS_STATUS_ERROR, NULL, data);
		return NULL;
	}

	/*get a lock and insert the state into the hash */
	WaitForSingleObject (soup_Mutex, INFINITE);
	g_hash_table_insert (soup_hash,
			     (gpointer) state->WSAhandle,
			     (gpointer) state);
	ReleaseMutex (soup_Mutex);

	return state;
}

void
soup_address_get_name_cancel (SoupAddressGetNameId id)
{
	SoupAddressReverseState* state;
	state = (SoupAddressReverseState*) id;

	g_return_if_fail(state != NULL);

	soup_address_unref (state->ia);
	WSACancelAsyncRequest ((HANDLE) state->WSAhandle);

	/*get a lock and remove the hash entry */
	WaitForSingleObject (soup_Mutex, INFINITE);
	g_hash_table_remove (soup_hash, (gpointer) state->WSAhandle);
	ReleaseMutex (soup_Mutex);

	g_free (state);
}

#endif		/*********** End Windows code ***********/

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

	soup_address_get_name (addr, soup_address_get_name_sync_cb, &ret);

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
 * soup_address_set_port:
 * @ia: Address to set the port number of.
 * @port: New port number
 *
 * Set the port number.
 **/
void
soup_address_set_port (const SoupAddress* ia, guint port)
{
	g_return_if_fail (ia != NULL);

	((struct sockaddr_in*) &ia->sa)->sin_port = g_htons (port);
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
	/* We do pay attention to network byte order just in case the hash
	   result is saved or sent to a different host.  */
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

	g_assert(p1 != NULL && p2 != NULL);

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

#ifndef SOUP_WIN32  /*********** Unix code ***********/

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

#else	/*********** Windows code ***********/

gchar*
soup_address_gethostname (void)
{
	gchar* name = NULL;
	int error = 0;

	name = g_new0 (char, 256);
	error = gethostname (name, 256);
	if (error) {
		g_free(name);
		return NULL;
	}

	return name;
}

#endif		/*********** End Windows code ***********/

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

	if (name && soup_gethostbyname(name, &sa, NULL)) {
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


static void
soup_socket_connect_tcp_cb (SoupSocket* socket,
			    SoupSocketConnectStatus status,
			    gpointer data)
{
	SoupSocketConnectState* state = (SoupSocketConnectState*) data;

	if (status == SOUP_SOCKET_NEW_STATUS_OK)
		(*state->func) (socket,
				SOUP_SOCKET_CONNECT_ERROR_NONE,
				state->data);
	else
		(*state->func) (NULL,
				SOUP_SOCKET_CONNECT_ERROR_NETWORK,
				state->data);

	g_free(state);
}

static void
soup_socket_connect_inetaddr_cb (SoupAddress* inetaddr,
				 SoupAddressStatus status,
				 gpointer data)
{
	SoupSocketConnectState* state = (SoupSocketConnectState*) data;

	if (status == SOUP_ADDRESS_STATUS_OK) {
		state->inetaddr_id = NULL;
		state->tcp_id = soup_socket_new (inetaddr,
						 soup_socket_connect_tcp_cb,
						 state);
		soup_address_unref (inetaddr);
	} else {
		(*state->func) (NULL,
				SOUP_SOCKET_CONNECT_ERROR_ADDR_RESOLVE,
				state->data);
		g_free(state);
	}
}

/**
 * soup_socket_connect:
 * @hostname: Name of host to connect to
 * @port: Port to connect to
 * @func: Callback function
 * @data: User data passed when callback function is called.
 *
 * A quick and easy non-blocking #SoupSocket constructor.  This
 * connects to the specified address and port and then calls the
 * callback with the data.  Use this function when you're a client
 * connecting to a server and you don't want to block or mess with
 * #SoupAddress's.  It may call the callback before the function
 * returns.  It will call the callback if there is a failure.
 *
 * Returns: ID of the connection which can be used with
 * soup_socket_connect_cancel() to cancel it; NULL on
 * failure.
 **/
SoupSocketConnectId
soup_socket_connect (const gchar*        hostname,
		     const gint          port,
		     SoupSocketConnectFn func,
		     gpointer            data)
{
	SoupSocketConnectState* state;
	gpointer id;

	g_return_val_if_fail (hostname != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	state = g_new0 (SoupSocketConnectState, 1);
	state->func = func;
	state->data = data;

	id = soup_address_new (hostname,
			       port,
			       soup_socket_connect_inetaddr_cb,
			       state);

	/* Note that soup_address_new can fail immediately and call
	   our callback which will delete the state.  The users callback
	   would be called in the process. */

	if (id == NULL) return NULL;

	state->inetaddr_id = id;

	return state;
}

/**
 * soup_socket_connect_cancel:
 * @id: Id of the connection.
 *
 * Cancel an asynchronous connection that was started with
 * soup_socket_connect().
 */
void
soup_socket_connect_cancel (SoupSocketConnectId id)
{
	SoupSocketConnectState* state = (SoupSocketConnectState*) id;

	g_return_if_fail (state != NULL);

	if (state->inetaddr_id)
		soup_address_new_cancel (state->inetaddr_id);
	else if (state->tcp_id)
		soup_socket_new_cancel (state->tcp_id);

	g_free (state);
}

static void
soup_socket_connect_sync_cb (SoupSocket              *socket,
			     SoupSocketConnectStatus  status,
			     gpointer                 data)
{
	SoupSocket **ret = data;
	*ret = socket;
}

SoupSocket *
soup_socket_connect_sync (const gchar *name,
			  const gint   port)
{
	SoupSocket *ret = (SoupSocket *) 0xdeadbeef;

	soup_socket_connect (name, port, soup_socket_connect_sync_cb, &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (SoupSocket *) 0xdeadbeef) return ret;
	}

	return ret;
}


#ifndef SOUP_WIN32  /*********** Unix code ***********/

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


#else	/*********** Windows code ***********/

static gboolean
soup_socket_new_cb (GIOChannel* iochannel,
		    GIOCondition condition,
		    gpointer data)
{
	SoupSocketState* state = (SoupSocketState*) data;
	SoupSocket *s;

	if (state->errorcode) {
		soup_address_unref (state->addr);
		(*state->func) ((SoupSocket *) NULL,
				SOUP_SOCKET_NEW_STATUS_ERROR,
				state->data);
		g_free (state);
		return FALSE;
	}

	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;
	s->sockfd = state->sockfd;
	s->addr = state->addr;

	(*state->func) (s, SOUP_SOCKET_NEW_STATUS_OK, state->data);
	g_free (state);
	return FALSE;
}

SoupSocketNewId
soup_socket_new (SoupAddress     *addr,
		 SoupSocketNewFn  func,
		 gpointer         data)
{
	gint sockfd;
	gint status;
	SoupSocketState* state;

	g_return_val_if_fail (addr != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	/* Create socket */
	sockfd = socket (AF_INET, SOCK_STREAM, 0);
	if (sockfd == INVALID_SOCKET) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

	/* Note: WSAAsunc automatically sets the socket to noblocking mode */
	status = WSAAsyncSelect (sockfd, soup_hWnd, TCP_SOCK_MSG, FD_CONNECT);

	if (status == SOCKET_ERROR) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

	status = connect (sockfd, &addr->sa, sizeof(addr->sa));
	/* Returning an error is ok, unless.. */
	if (status == SOCKET_ERROR) {
		status = WSAGetLastError();
		if (status != WSAEWOULDBLOCK) {
			(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
			return NULL;
		}
	}

	soup_address_ref (addr);

	if (status != SOCKET_ERROR) {
		SoupSocket *s = g_new0 (SoupSocket, 1);
		s->ref_count = 1;
		s->sockfd = sockfd;
		s->addr = addr;

		(*state->func) (s, SOUP_SOCKET_NEW_STATUS_OK, state->data);
		return NULL;
	}

	/* Wait for the connection */
	state = g_new0 (SoupSocketState, 1);
	state->addr = addr;
	state->func = func;
	state->data = data;
	state->sockfd = sockfd;

	WaitForSingleObject (soup_select_Mutex, INFINITE);
	/*using sockfd as the key into the 'select' hash */
	g_hash_table_insert (soup_select_hash,
			     (gpointer) state->sockfd,
			     (gpointer) state);
	ReleaseMutex (soup_select_Mutex);

	return state;
}

void
soup_socket_new_cancel (SoupSocketNewId id)
{
	SoupSocketState* state = (SoupSocketState*) id;

	/* Cancel event posting on the socket */
	WSAAsyncSelect (state->sockfd, soup_hWnd, 0, 0);
	soup_address_unref (state->addr);
	g_free (state);
}

#endif		/*********** End Windows code ***********/

static void
soup_socket_new_sync_cb (SoupSocket*         socket,
			 SoupSocketNewStatus status,
			 gpointer            data)
{
	SoupSocket **ret = data;
	*ret = socket;
}

SoupSocket *
soup_socket_new_sync (SoupAddress *addr)
{
	SoupSocket *ret = (SoupSocket *) 0xdeadbeef;

	soup_socket_new (addr, soup_socket_new_sync_cb, &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (SoupSocket *) 0xdeadbeef) return ret;
	}

	return ret;
}

/**
 * soup_socket_ref
 * @s: SoupSocket to reference
 *
 * Increment the reference counter of the SoupSocket.
 **/
void
soup_socket_ref (SoupSocket* s)
{
	g_return_if_fail (s != NULL);

	++s->ref_count;
}

/**
 * soup_socket_unref
 * @s: #SoupSocket to unreference
 *
 * Remove a reference from the #SoupSocket.  When reference count
 * reaches 0, the socket is deleted.
 **/
void
soup_socket_unref (SoupSocket* s)
{
	g_return_if_fail(s != NULL);

	--s->ref_count;

	if (s->ref_count == 0) {
		SOUP_CLOSE_SOCKET (s->sockfd);

		if (s->addr) soup_address_unref (s->addr);

		if (s->iochannel) g_io_channel_unref (s->iochannel);

		g_free(s);
	}
}

/**
 * soup_socket_get_iochannel:
 * @socket: SoupSocket to get GIOChannel from.
 *
 * Get the #GIOChannel for the #SoupSocket.
 *
 * For a client socket, the #GIOChannel represents the data stream.
 * Use it like you would any other #GIOChannel.
 *
 * For a server socket however, the #GIOChannel represents incoming
 * connections.  If you can read from it, there's a connection
 * waiting.
 *
 * There is one channel for every socket.  This function refs the
 * channel before returning it.  You should unref the channel when
 * you are done with it.  However, you should not close the channel -
 * this is done when you delete the socket.
 *
 * Returns: A #GIOChannel; NULL on failure.
 *
 **/
GIOChannel*
soup_socket_get_iochannel (SoupSocket* socket)
{
	g_return_val_if_fail (socket != NULL, NULL);

	if (socket->iochannel == NULL)
		socket->iochannel = SOUP_SOCKET_IOCHANNEL_NEW(socket->sockfd);

	g_io_channel_ref (socket->iochannel);

	return socket->iochannel;
}

/**
 * soup_socket_get_address:
 * @socket: #SoupSocket to get address of.
 *
 * Get the address of the socket.  If the socket is client socket,
 * the address is the address of the remote host it is connected to.
 * If the socket is a server socket, the address is the address of
 * the local host.  (Though you should use
 * soup_address_gethostaddr() to get the #SoupAddress of the local
 * host.)
 *
 * Returns: #SoupAddress of socket; NULL on failure.
 **/
SoupAddress *
soup_socket_get_address (const SoupSocket* socket)
{
	g_return_val_if_fail (socket != NULL, NULL);
	g_return_val_if_fail (socket->addr != NULL, NULL);

	soup_address_ref (socket->addr);

	return socket->addr;
}

/**
 * soup_socket_get_port:
 * @socket: SoupSocket to get the port number of.
 *
 * Get the port number the socket is bound to.
 *
 * Returns: Port number of the socket.
 **/
gint
soup_socket_get_port(const SoupSocket* socket)
{
	g_return_val_if_fail (socket != NULL, 0);

	return g_ntohs (SOUP_SOCKADDR_IN (socket->addr->sa).sin_port);
}

/**
 * soup_socket_server_new:
 * @port: Port number for the socket (SOUP_SERVER_ANY_PORT if you don't care).
 *
 * Create and open a new #SoupSocket with the specified port number.
 * Use this sort of socket when your are a server and you know what
 * the port number should be (or pass 0 if you don't care what the
 * port is).
 *
 * Returns: a new #SoupSocket, or NULL if there was a failure.
 **/
SoupSocket *
soup_socket_server_new (const gint port)
{
	SoupSocket* s;
	struct sockaddr_in* sa_in;
	socklen_t socklen;

	/* Create socket */
	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;

	if ((s->sockfd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
		g_free (s);
		return NULL;
	}

	s->addr = g_new0 (SoupAddress, 1);
	s->addr->ref_count = 1;

	/* Set up address and port for connection */
	sa_in = (struct sockaddr_in*) &s->addr->sa;
	sa_in->sin_family = AF_INET;
	sa_in->sin_addr.s_addr = g_htonl (INADDR_ANY);
	sa_in->sin_port = g_htons (port);

	/* The socket is set to non-blocking mode later in the Windows
	   version.*/
#ifndef SOUP_WIN32
	{
		const int on = 1;
		gint flags;

		/* Set REUSEADDR so we can reuse the port */
		if (setsockopt (s->sockfd,
				SOL_SOCKET,
				SO_REUSEADDR,
				&on,
				sizeof (on)) != 0)
			g_warning("Can't set reuse on tcp socket\n");

		/* Get the flags (should all be 0?) */
		flags = fcntl (s->sockfd, F_GETFL, 0);
		if (flags == -1) goto ERROR;

		/* Make the socket non-blocking */
		if (fcntl (s->sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
			goto ERROR;
	}
#endif

	/* Bind */
	if (bind (s->sockfd, &s->addr->sa, sizeof (s->addr->sa)) != 0)
		goto BIND_ERROR;

	/* Get the socket name - don't care if it fails */
	socklen = sizeof (s->addr->sa);
	getsockname (s->sockfd, &s->addr->sa, &socklen);

	/* Listen */
	if (listen (s->sockfd, 10) != 0) goto LISTEN_ERROR;

	return s;

 BIND_ERROR:
 LISTEN_ERROR:
	close (s->sockfd);
	g_free (s->addr);
	g_free (s);
	return NULL;
}

#ifndef SOUP_WIN32  /*********** Unix code ***********/

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

	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;
	s->sockfd = sockfd;

	s->addr = g_new0 (SoupAddress, 1);
	s->addr->ref_count = 1;
	memcpy (&s->addr->sa, &sa, sizeof (s->addr->sa));

	return s;
}

#else	/*********** Windows code ***********/

SoupSocket *
soup_socket_server_accept (SoupSocket *socket)
{
	gint sockfd;
	struct sockaddr sa;
	gint n;
	fd_set fdset;
	SoupSocket* s;
	u_long arg;

	g_return_val_if_fail (socket != NULL, NULL);

	FD_ZERO (&fdset);
	FD_SET ((unsigned)socket->sockfd, &fdset);

	if (select (socket->sockfd + 1, &fdset, NULL, NULL, NULL) == -1) {
		return NULL;
	}

	/* make sure the socket is in blocking mode */

	arg = 0;
	if (ioctlsocket (socket->sockfd, FIONBIO, &arg))
		return NULL;

	sockfd = accept (socket->sockfd, &sa, NULL);
	/* if it fails, looping isn't going to help */

	if (sockfd == INVALID_SOCKET) {
		return NULL;
	}

	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;
	s->sockfd = sockfd;

	s->addr = g_new0 (SoupAddress, 1);
	s->addr->ref_count = 1;
	memcpy (&s->addr->sa, &sa, sizeof (s->addr->sa));

	return s;
}

SoupSocket *
soup_socket_server_try_accept (SoupSocket *socket)
{
	gint sockfd;
	struct sockaddr sa;

	fd_set fdset;
	SoupSocket* s;
	u_long arg;

	g_return_val_if_fail (socket != NULL, NULL);
	FD_ZERO (&fdset);
	FD_SET ((unsigned)socket->sockfd, &fdset);

	if (select (socket->sockfd + 1, &fdset, NULL, NULL, NULL) == -1) {
		return NULL;
	}
	/* make sure the socket is in non-blocking mode */

	arg = 1;
	if (ioctlsocket (socket->sockfd, FIONBIO, &arg))
		return NULL;

	sockfd = accept (socket->sockfd, &sa, NULL);
	/* if it fails, looping isn't going to help */

	if (sockfd == INVALID_SOCKET) {
		return NULL;
	}

	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;
	s->sockfd = sockfd;

	s->addr = g_new0 (SoupAddress, 1);
	s->addr->ref_count = 1;
	memcpy (&s->addr->sa, &sa, sizeof (s->addr->sa));

	return s;
}
#endif		/*********** End Windows code ***********/

#ifdef SOUP_WIN32  /*********** Windows code ***********/
int
soup_MainCallBack (GIOChannel   *iochannel,
		   GIOCondition  condition,
		   void         *nodata)
{
	MSG msg;

	gpointer data;
	SoupSocketState *IAstate;
	SoupAddressReverseState *IARstate;
	SoupSocketState *TCPNEWstate;

	/*Take the msg off the message queue */
	GetMessage (&msg, NULL, 0, 0);

	switch (msg.message) {
	case IA_NEW_MSG:
		WaitForSingleObject (soup_Mutex, INFINITE);
		data = g_hash_table_lookup (soup_hash, (gpointer) msg.wParam);
		g_hash_table_remove (soup_hash, (gpointer) msg.wParam);
		ReleaseMutex (soup_Mutex);

		IAstate = (SoupAddressState*) data;
		/* NULL if OK */
		IAstate->errorcode = WSAGETASYNCERROR(msg.lParam);

		/* Now call the callback function */
		soup_address_new_cb (NULL, G_IO_IN, (gpointer) IAstate);

		break;
	case GET_NAME_MSG:
		WaitForSingleObject (soup_Mutex, INFINITE);
		data = g_hash_table_lookup (soup_hash, (gpointer) msg.wParam);
		g_hash_table_remove (soup_hash, (gpointer) msg.wParam);
		ReleaseMutex (soup_Mutex);

		IARstate = (SoupAddressReverseState*) data;
		/* NULL if OK */
		IARstate->errorcode = WSAGETASYNCERROR(msg.lParam);

		/* Now call the callback function */
		soup_address_get_name_cb (NULL,
					  G_IO_IN,
					  (gpointer) IARstate);
		break;
	case TCP_SOCK_MSG:
		WaitForSingleObject (soup_select_Mutex, INFINITE);
		data = g_hash_table_lookup (soup_select_hash,
					    (gpointer) msg.wParam);
		g_hash_table_remove (soup_select_hash, (gpointer) msg.wParam);
		ReleaseMutex (soup_select_Mutex);

		TCPNEWstate = (SoupSocketState*) data;
		TCPNEWstate->errorcode = WSAGETSELECTERROR (msg.lParam);
		soup_socket_new_cb (NULL,
				    G_IO_IN,
				    (gpointer) TCPNEWstate);
		break;
	}

	return 1;
}

LRESULT CALLBACK
SoupWndProc (HWND hwnd,        /* handle to window */
	     UINT uMsg,        /* message identifier */
	     WPARAM wParam,    /* first message parameter */
	     LPARAM lParam)    /* second message parameter */
{
	switch (uMsg) {
        case WM_CREATE:  /* Initialize the window. */
		return 0;
        case WM_PAINT:   /* Paint the window's client area. */
		return 0;
        case WM_SIZE:    /* Set the size and position of the window. */
		return 0;
        case WM_DESTROY: /* Clean up window-specific data objects. */
		return 0;

        default:
		return DefWindowProc (hwnd, uMsg, wParam, lParam);
	}
}

gboolean
RemoveHashEntry(gpointer key, gpointer value, gpointer user_data)
{
	g_free (value);
	return TRUE;
}

BOOL WINAPI
DllMain (HINSTANCE hinstDLL,  /* handle to DLL module */
	 DWORD fdwReason,     /* reason for calling functionm */
	 LPVOID lpvReserved   /* reserved */)
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	switch(fdwReason) {
	case DLL_PROCESS_ATTACH:
		/* The DLL is being mapped into process's address space */
		/* Do any required initialization on a per application basis,
		   return FALSE if failed */
		wVersionRequested = MAKEWORD (2, 0);

		err = WSAStartup (wVersionRequested, &wsaData);
		if (err != 0) {
			/* Tell the user that we could not find a usable
			   WinSock DLL.  */
			return FALSE;
		}

		/* Confirm that the WinSock DLL supports 2.0.*/
		/* Note that if the DLL supports versions greater    */
		/* than 2.0 in addition to 2.0, it will still return */
		/* 2.0 in wVersion since that is the version we      */
		/* requested.                                        */

		if (LOBYTE(wsaData.wVersion) != 2 ||
		    HIBYTE(wsaData.wVersion) != 0) {
			/* Tell the user that we could not find a usable */
			/* WinSock DLL.                                  */
			WSACleanup ();
			return FALSE;
		}

		/* The WinSock DLL is acceptable. Proceed. */

		/* Setup and register a windows class that we use for out
                   GIOchannel */
		soupWndClass.cbSize = sizeof (WNDCLASSEX);
		soupWndClass.style = CS_SAVEBITS;
		soupWndClass.lpfnWndProc = (WNDPROC) SoupWndProc;
		soupWndClass.cbClsExtra = 0;
		soupWndClass.cbWndExtra = 0;
		soupWndClass.hInstance = hinstDLL;
		soupWndClass.hIcon = NULL;
		soupWndClass.hCursor = NULL;
		soupWndClass.hbrBackground = NULL;
		soupWndClass.lpszMenuName = NULL;
		soupWndClass.lpszClassName = "Soup";
		soupWndClass.hIconSm = NULL;

		if (!RegisterClassEx (&soupWndClass)) return FALSE;

		soup_hWnd  = CreateWindowEx (0,
					     "Soup",
					     "none",
					     WS_OVERLAPPEDWINDOW,
					     CW_USEDEFAULT,
					     CW_USEDEFAULT,
					     CW_USEDEFAULT,
					     CW_USEDEFAULT,
					     (HWND) NULL,
					     (HMENU) NULL,
					     hinstDLL,
					     (LPVOID) NULL);

		if (!soup_hWnd) return FALSE;

		soup_iochannel =
			g_io_channel_win32_new_messages (
				(unsigned int) soup_hWnd);

		/* Add a watch */
		soup_io_watch_ID =
			g_io_add_watch (soup_iochannel,
					G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL,
					soup_MainCallBack,
					NULL);

		soup_hash = g_hash_table_new (NULL, NULL);
		soup_select_hash = g_hash_table_new (NULL, NULL);


		soup_Mutex = CreateMutex (NULL, FALSE, "soup_Mutex");

		if (soup_Mutex == NULL) return FALSE;

		soup_select_Mutex = CreateMutex (NULL,
						 FALSE,
						 "soup_select_Mutex");

		if (soup_select_Mutex == NULL) return FALSE;

		soup_hostent_Mutex = CreateMutex (NULL,
						  FALSE,
						  "soup_hostent_Mutex");

		if (soup_hostent_Mutex == NULL) return FALSE;

		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		/* The DLL unmapped from process's address space. Do necessary
                   cleanup */
		g_source_remove (soup_io_watch_ID);
		g_free (soup_iochannel);
		DestroyWindow (soup_hWnd);

		WaitForSingleObject (soup_Mutex, INFINITE);
		WaitForSingleObject (soup_select_Mutex, INFINITE);
		g_hash_table_foreach_remove (soup_hash, RemoveHashEntry, NULL);
		g_hash_table_foreach_remove (soup_select_hash,
					     RemoveHashEntry,
					     NULL);
		g_hash_table_destroy (soup_select_hash);
		g_hash_table_destroy (soup_hash);
		ReleaseMutex (soup_Mutex);
		ReleaseMutex (soup_select_Mutex);
		ReleaseMutex (soup_hostent_Mutex);

		WSACleanup ();

		break;
	}

	return TRUE;
}

#endif		/*********** End Windows code ***********/
