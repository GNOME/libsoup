/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-nss.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_NSS

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib.h>

#include "nss.h"
#include <ssl.h>
#include <pk11func.h>

#include "soup-nss.h"

/* NSPR Private function */
extern PRFileDesc *PR_ImportTCPSocket (int fd);

typedef struct {
	GIOChannel   channel;
	GIOChannel  *real_sock;
	PRFileDesc  *fdesc;
	gboolean     handshake_done;
} SoupNSSChannel;

static inline GIOError
translate_nss_error (int code) 
{
	switch (code) {
	case PR_INVALID_ARGUMENT_ERROR:
		return G_IO_ERROR_INVAL;
	case PR_IO_TIMEOUT_ERROR:
	case PR_WOULD_BLOCK_ERROR:
		return G_IO_ERROR_AGAIN;
	case PR_IO_ERROR:
	default:
		return G_IO_ERROR_UNKNOWN;
	}
}

static GIOError
soup_nss_read (GIOChannel   *channel,
	       gchar        *buf,
	       guint         count,
	       guint        *bytes_read)
{
	SoupNSSChannel *chan = (SoupNSSChannel *) channel;
	gint result;
	PRPollDesc pd;

	pd.fd = chan->fdesc;
	pd.in_flags = PR_POLL_READ;

	/* 
	 * FIXME: This seems to avoid blocking zero reads. 
	 *        Not sure why these aren't filtered out in soup_nss_check.
	 */
	if (PR_Poll (&pd, 1, PR_INTERVAL_NO_WAIT) != 1)
		return G_IO_ERROR_AGAIN;

	do {
		result = PR_Read (chan->fdesc, buf, count);
	} while (result < 0 && PR_GetError () == PR_PENDING_INTERRUPT_ERROR);

	if (result < 0) {
		*bytes_read = 0;
		return translate_nss_error (PR_GetError ());
	} else {
		*bytes_read = result;
		return G_IO_ERROR_NONE;
	}
}

static GIOError
soup_nss_write (GIOChannel   *channel,
		gchar        *buf,
		guint         count,
		guint        *bytes_written)
{
	SoupNSSChannel *chan = (SoupNSSChannel *) channel;
	gint result;

	do {
		result = PR_Write (chan->fdesc, buf, count);
	} while (result < 0 && PR_GetError () == PR_PENDING_INTERRUPT_ERROR);

	if (result < 0) {
		*bytes_written = 0;
		return translate_nss_error (PR_GetError ());
	} else {
		*bytes_written = result;
		return G_IO_ERROR_NONE;
	}
}

static GIOError
soup_nss_seek (GIOChannel *channel, gint offset, GSeekType type)
{
	SoupNSSChannel *chan = (SoupNSSChannel *) channel;
	int whence;
	off_t result;
	
	switch (type) {
	case G_SEEK_SET:
		whence = PR_SEEK_SET;
		break;
	case G_SEEK_CUR:
		whence = PR_SEEK_CUR;
		break;
	case G_SEEK_END:
		whence = PR_SEEK_END;
		break;
	default:
		g_warning ("soup_nss_seek: unknown seek type");
		return G_IO_ERROR_UNKNOWN;
	}
	
	result = PR_Seek (chan->fdesc, offset, whence);
	
	if (result < 0)
		return translate_nss_error (PR_GetError ());
	else
		return G_IO_ERROR_NONE;
}

static void
soup_nss_close (GIOChannel   *channel)
{
	SoupNSSChannel *chan = (SoupNSSChannel *) channel;
	PR_Close (chan->fdesc);
	g_io_channel_close (chan->real_sock);
}

static void
soup_nss_free (GIOChannel   *channel)
{
	SoupNSSChannel *chan = (SoupNSSChannel *) channel;
	g_io_channel_unref (chan->real_sock);
	g_free (chan);
}

typedef struct {
	SoupNSSChannel *channel;
	gint16          events;
	gint16          last_event;
	GIOFunc         callback;
} SoupNSSWatchData;

static gboolean 
soup_nss_prepare  (gpointer source_data, 
		   GTimeVal *current_time,
		   gint     *timeout,
		   gpointer user_data)
{
	*timeout = 0;
	return FALSE;
}

static gboolean 
soup_nss_check    (gpointer source_data,
		   GTimeVal *current_time,
		   gpointer user_data)
{
	SoupNSSWatchData *data = source_data;
	SoupNSSChannel *chan = data->channel;
	PRPollDesc pd;

	/*
	 * We must ensure the SSL handshake is completed before performing real
	 * IO otherwise NSS behaves erratically.  Unfortunately
	 * SSL_ForceHandshake blocks until handshaking is complete.  
	 */
	if (!chan->handshake_done) {
		if (SSL_ForceHandshake (chan->fdesc) == PR_FAILURE) {
			g_warning ("SSL handshake failed.");
			PR_Close (chan->fdesc);
			return FALSE;
		}
		chan->handshake_done = TRUE;
	}

	pd.fd = chan->fdesc;
	pd.in_flags = data->events;

	if (PR_Poll (&pd, 1, PR_INTERVAL_NO_WAIT) == 1) {
		data->last_event = pd.out_flags;
		return TRUE;
	}

	data->last_event = 0;
	return FALSE;
}

static gboolean
soup_nss_dispatch (gpointer source_data, 
		   GTimeVal *current_time,
		   gpointer user_data)

{
	SoupNSSWatchData *data = source_data;
	GIOCondition cond = 0;

	if (data->last_event & PR_POLL_READ)   cond |= G_IO_IN;
	if (data->last_event & PR_POLL_WRITE)  cond |= G_IO_OUT;
	if (data->last_event & PR_POLL_ERR)    cond |= G_IO_ERR;
	if (data->last_event & PR_POLL_NVAL)   cond |= G_IO_NVAL;
	if (data->last_event & PR_POLL_HUP)    cond |= G_IO_HUP;
	if (data->last_event & PR_POLL_EXCEPT) cond |= G_IO_PRI;

	return (*data->callback) ((GIOChannel *) data->channel, 
				  cond, 
				  user_data);
}

static void 
soup_nss_destroy (gpointer source_data)
{
	SoupNSSWatchData *data = source_data;

	g_io_channel_unref ((GIOChannel *) data->channel);
	g_free (data);
}

GSourceFuncs soup_nss_watch_funcs = {
	soup_nss_prepare,
	soup_nss_check,
	soup_nss_dispatch,
	soup_nss_destroy
};

static guint 
soup_nss_add_watch (GIOChannel    *channel,
		    gint           priority,
		    GIOCondition   condition,
		    GIOFunc        func,
		    gpointer       user_data,
		    GDestroyNotify notify)
{
	SoupNSSWatchData *watch = g_new0 (SoupNSSWatchData, 1);
	SoupNSSChannel *chan = (SoupNSSChannel *) channel;

	watch->channel = chan;
	g_io_channel_ref (channel);

	watch->callback = func;

	if (condition & G_IO_IN)
		watch->events |= PR_POLL_READ;

	if (condition & G_IO_OUT)
		watch->events |= PR_POLL_WRITE;

	if (condition & G_IO_PRI  ||
	    condition & G_IO_ERR  ||
	    condition & G_IO_NVAL ||
	    condition & G_IO_HUP)
		watch->events |= PR_POLL_EXCEPT;

	return g_source_add (priority, 
			     TRUE, 
			     &soup_nss_watch_funcs, 
			     watch, 
			     user_data, 
			     notify);
}

GIOFuncs soup_nss_channel_funcs = {
	soup_nss_read,
	soup_nss_write,
	soup_nss_seek,
	soup_nss_close,
	soup_nss_add_watch,
	soup_nss_free,
};

static gboolean nss_initialized = FALSE;

static SECStatus 
soup_nss_bad_cert (void *data, PRFileDesc *fd)
{
	return SECSuccess;
}

GIOChannel *
soup_nss_get_iochannel (GIOChannel *sock, SoupSSLType type)
{
	SoupNSSChannel *chan;
	GIOChannel *gchan;
	PRFileDesc *fdesc;
	int sockfd;

        g_return_val_if_fail (sock != NULL, NULL);

	if (!nss_initialized && !soup_nss_init ()) goto THROW_CREATE_ERROR;
	
	sockfd = g_io_channel_unix_get_fd (sock);
	if (!sockfd) goto THROW_CREATE_ERROR;

	fdesc = PR_ImportTCPSocket (sockfd);
	if (!fdesc) {
		g_warning ("SSL socket creation failure.\n");
		goto THROW_CREATE_ERROR;
	}

	fdesc = SSL_ImportFD (NULL, fdesc);
	if (!fdesc) {
		g_warning ("SSL object creation failure.\n");
		goto THROW_CREATE_ERROR;
	}

	SSL_OptionSet (fdesc, SSL_SECURITY, PR_TRUE);
	if (type == SOUP_SSL_TYPE_CLIENT)
		SSL_OptionSet (fdesc, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
	else
		SSL_OptionSet (fdesc, SSL_HANDSHAKE_AS_SERVER, PR_TRUE);
	SSL_BadCertHook (fdesc, soup_nss_bad_cert, NULL);

	if (SSL_ResetHandshake (fdesc, PR_FALSE) == PR_FAILURE) {
		g_warning ("SSL handshake failure.\n");
		PR_Close (fdesc);
                return NULL;
	}

	chan = g_new0 (SoupNSSChannel, 1);
	chan->real_sock = sock;
	chan->fdesc = fdesc;
	chan->handshake_done = FALSE;

	g_io_channel_ref (sock);

	gchan = (GIOChannel *) chan;
	gchan->funcs = &soup_nss_channel_funcs;
	g_io_channel_init (gchan);

	return gchan;

 THROW_CREATE_ERROR:
	return NULL;
}

gboolean
soup_nss_init (void)
{
	gchar *nss_dir;
	struct stat confstat;

	nss_dir = g_strconcat (g_get_home_dir (), 
			       G_DIR_SEPARATOR_S, 
			       ".soup", 
			       NULL);

	if (stat (nss_dir, &confstat) != 0) {
		if (errno == ENOENT) {
			if (mkdir (nss_dir, S_IRWXU) != 0) {
				g_warning ("Unable to create private "
					   "configuration directory \"%s\".", 
					   nss_dir);
				goto INIT_ERROR;
			}
		} else {
			g_warning ("Error accessing configuration directory "
				   "\"%s\": %s.",
				   nss_dir,
				   strerror (errno));
			goto INIT_ERROR;
		}
	} else if (!S_ISDIR (confstat.st_mode)) {
		g_warning ("Expecting \"%s\" to be a directory.", nss_dir);
		goto INIT_ERROR;
	}

	if (NSS_InitReadWrite (nss_dir) != SECSuccess) {
		if (NSS_NoDB_Init (nss_dir) == SECFailure) {
			g_warning ("Unable to initialize NSS SSL Library.");
			goto INIT_ERROR;
		}
	}

	NSS_SetDomesticPolicy ();

        SSL_OptionSetDefault (SSL_ENABLE_SSL2, PR_TRUE);
        SSL_OptionSetDefault (SSL_ENABLE_SSL3, PR_TRUE);
        SSL_OptionSetDefault (SSL_ENABLE_TLS, PR_TRUE);
        SSL_OptionSetDefault (SSL_V2_COMPATIBLE_HELLO, PR_TRUE);

	g_free (nss_dir);

	nss_initialized = TRUE;
	return TRUE;

 INIT_ERROR:
	g_free (nss_dir);
	return FALSE;
}

void 
soup_nss_set_security_policy (SoupSecurityPolicy policy)
{
	switch (policy) {
	case SOUP_SECURITY_DOMESTIC:
		NSS_SetDomesticPolicy ();
		break;
	case SOUP_SECURITY_EXPORT:
		NSS_SetExportPolicy ();
		break;
	case SOUP_SECURITY_FRANCE:
		NSS_SetFrancePolicy ();
		break;
	}

	SSL_ClearSessionCache ();
}

#endif /*HAVE_NSS*/

