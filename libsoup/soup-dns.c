/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-dns.c: Async DNS code
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "soup-dns.h"
#include "soup-private.h"

#ifndef socklen_t
#  define socklen_t int
#endif

#ifndef INET_ADDRSTRLEN
#  define INET_ADDRSTRLEN 16
#  define INET6_ADDRSTRLEN 46
#endif

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif

static struct hostent *
new_hostent (const char *name, int type, int length, gpointer addr)
{
	struct hostent *h;

	h = g_new0 (struct hostent, 1);
	h->h_name = g_strdup (name);
	h->h_aliases = NULL;
	h->h_addrtype = type;
	h->h_length = length;
	h->h_addr_list = g_new (char *, 2);
	h->h_addr_list[0] = g_memdup (addr, length);
	h->h_addr_list[1] = NULL;

	return h;
}

static struct hostent *
copy_hostent (struct hostent *h)
{
	return new_hostent (h->h_name, h->h_addrtype,
			    h->h_length, h->h_addr_list[0]);
}

static void
free_hostent (struct hostent *h)
{
	g_free (h->h_name);
	g_free (h->h_addr_list[0]);
	g_free (h->h_addr_list);
	g_free (h);
}

static void
write_hostent (struct hostent *h, int fd)
{
	guchar namelen = strlen (h->h_name) + 1;
	guchar addrlen = h->h_length;
	guchar addrtype = h->h_addrtype;
	struct iovec iov[5];

	iov[0].iov_base = &namelen;
	iov[0].iov_len = 1;
	iov[1].iov_base = h->h_name;
	iov[1].iov_len = namelen;
	iov[2].iov_base = &addrtype;
	iov[2].iov_len = 1;
	iov[3].iov_base = &addrlen;
	iov[3].iov_len = 1;
	iov[4].iov_base = h->h_addr_list[0];
	iov[4].iov_len = addrlen;

	if (writev (fd, iov, 5) == -1)
		g_warning ("Problem writing to pipe");
}

static struct hostent *
new_hostent_from_phys (const char *addr)
{
	struct in_addr inaddr;
#ifdef HAVE_IPV6
	struct in6_addr inaddr6;
#endif

#if defined(HAVE_INET_PTON)
#ifdef HAVE_IPV6
	if (inet_pton (AF_INET6, addr, &inaddr6) != 0)
		return new_hostent (addr, AF_INET6, sizeof (inaddr6), &inaddr6);
	else
#endif
	if (inet_pton (AF_INET, addr, &inaddr) != 0)
		return new_hostent (addr, AF_INET, sizeof (inaddr), &inaddr);
#elif defined(HAVE_INET_ATON)
	if (inet_aton (addr, &inaddr) != 0)
		return new_hostent (addr, AF_INET, sizeof (inaddr), &inaddr);
#else
	inaddr.s_addr = inet_addr (addr);
	if (inaddr.s_addr != INADDR_NONE)
		return new_hostent (addr, AF_INET, sizeof (inaddr), &inaddr);
#endif

	return NULL;
}

char *
soup_ntop (gconstpointer addr, int family)
{
	switch (family) {
	case AF_INET:
	{
#ifdef HAVE_INET_NTOP
		char buffer[INET_ADDRSTRLEN];

		inet_ntop (family, addr, buffer, sizeof (buffer));
		return g_strdup (buffer);
#else
		return g_strdup (inet_ntoa (*(struct in_addr *)addr));
#endif
	}

#ifdef HAVE_IPV6
	case AF_INET6:
	{
		char buffer[INET6_ADDRSTRLEN];

		inet_ntop (family, addr, buffer, sizeof (buffer));
		return g_strdup (buffer);
	}
#endif

	default:
		return NULL;
	}
}


/* Testing Defines */
/*  #undef   HAVE_GETHOSTBYNAME_R_GLIBC */
/*  #define  HAVE_GETHOSTBYNAME_R_GLIB_MUTEX */

#ifdef HAVE_GETHOSTBYNAME_R_GLIB_MUTEX
G_LOCK_DEFINE (gethostbyname);
#endif

static struct hostent *
soup_gethostbyname_internal (const char *hostname)
{
	struct hostent result_buf, *result = &result_buf, *out;
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

	if (result)
		out = copy_hostent (result);
	else
		out = NULL;

	if (buf)
		g_free (buf);
#if defined(HAVE_GETHOSTBYNAME_R_GLIB_MUTEX)
	G_UNLOCK (gethostbyname);
#endif

	return out;
}

static struct hostent *
soup_gethostbyaddr_internal (gpointer addr, int family)
{
	struct hostent result_buf, *result = &result_buf, *out;
	char *buf = NULL;
	int length;

	switch (family) {
	case AF_INET:
		length = sizeof (struct in_addr);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		length = sizeof (struct in6_addr);
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
					       family,
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
					       family,
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

		if (!gethostbyaddr_r (addr, length, family, &result_buf, &hdbuf))
			result = NULL;
	}
#else
	{
#if defined(HAVE_GETHOSTBYNAME_R_GLIB_MUTEX)
		G_LOCK (gethostbyname);
#endif
		result = gethostbyaddr (addr, length, family);
	}
#endif

	if (result)
		out = copy_hostent (result);
	else
		out = NULL;

	if (buf)
		g_free (buf);
#if defined(HAVE_GETHOSTBYNAME_R_GLIB_MUTEX)
	G_UNLOCK (gethostbyname);
#endif

	return out;
}


/* Cache */

typedef struct {
	char           *name;
	struct hostent *h;
	time_t          expires;

	GSList         *lookups;

	guint           source_id;
	pid_t           lookup_pid;
	int             fd;
} SoupDNSEntry;

static GHashTable *soup_dns_entries;
#define SOUP_DNS_ENTRIES_MAX 20

static void
free_entry (SoupDNSEntry *entry)
{
	g_hash_table_remove (soup_dns_entries, entry->name);
	g_free (entry->name);
	free_hostent (entry->h);
	g_free (entry);
}

static void
prune_cache_cb (gpointer key, gpointer value, gpointer data)
{
	SoupDNSEntry *entry = value, **prune_entry = data; 

	if (entry->lookups)
		return;
	if (!*prune_entry || (*prune_entry)->expires > entry->expires)
		*prune_entry = entry;
}

static void
cache_entry (SoupDNSEntry *entry)
{
	if (!soup_dns_entries) {
		soup_dns_entries = g_hash_table_new (soup_str_case_hash,
						     soup_str_case_equal);
	} else if (g_hash_table_size (soup_dns_entries) == SOUP_DNS_ENTRIES_MAX) {
		SoupDNSEntry *prune_entry = NULL;

		g_hash_table_foreach (soup_dns_entries, prune_cache_cb,
				      &prune_entry);
		if (prune_entry)
			free_entry (prune_entry);
	}

	entry->expires = time (0) + 60 * 60;
	g_hash_table_insert (soup_dns_entries, entry->name, entry);
}

static SoupDNSEntry *
lookup_entry (const char *name)
{
	if (!soup_dns_entries)
		return NULL;
	return g_hash_table_lookup (soup_dns_entries, name);
}


typedef struct {
	SoupGetHostByFn  func;
	gpointer         data;

	SoupDNSEntry    *entry;
} SoupDNSLookupInfo;

static gboolean
soup_gothost (gpointer user_data)
{
	SoupDNSEntry *entry = user_data;
	SoupDNSLookupInfo *info;

	if (entry->source_id) {
		g_source_remove (entry->source_id);
		entry->source_id = 0;
	}

	while (entry->lookups) {
		info = entry->lookups->data;
		entry->lookups = g_slist_remove (entry->lookups, info);

		(*info->func) (info, entry->h ? SOUP_ERROR_OK : SOUP_ERROR_CANT_RESOLVE, entry->h, info->data);
		g_free (info);
	}

	return FALSE;
}

static gboolean
soup_gethostby_cb (GIOChannel *iochannel,
		   GIOCondition condition,
		   gpointer data)
{
	SoupDNSEntry *entry = data;
	char buf[256], *namelenp, *name, *typep, *addrlenp, *addr;
	int nread;

	if (condition & G_IO_IN)
		nread = read (entry->fd, buf, sizeof (buf));
	else
		nread = 0;

	close (entry->fd);
	entry->fd = -1;
	kill (entry->lookup_pid, SIGKILL);
	waitpid (entry->lookup_pid, NULL, 0);
	entry->lookup_pid = 0;

	if (nread < 1)
		return soup_gothost (entry);

	namelenp = buf;
	name = namelenp + 1;
	typep = name + *namelenp;
	addrlenp = typep + 1;
	addr = addrlenp + 1;

	if (addrlenp < buf + nread && (addr + *addrlenp) == buf + nread)
		entry->h = new_hostent (name, *typep, *addrlenp, addr);
	return soup_gothost (entry);
}

static SoupDNSLookupInfo *
lookup_info (SoupDNSEntry *entry, SoupGetHostByFn func, gpointer data)
{
	SoupDNSLookupInfo *info;

	info = g_new0 (SoupDNSLookupInfo, 1);
	info->func = func;
	info->data = data;
	info->entry = entry;
	entry->lookups = g_slist_prepend (entry->lookups, info);
	if (!entry->source_id)
		entry->source_id = g_idle_add (soup_gothost, entry);

	return info;
}

/**
 * soup_gethostbyname:
 * @name: a nice name (eg, mofo.eecs.umich.edu) or a dotted decimal name
 *   (eg, 141.213.8.59).
 * @func: Callback function.
 * @data: User data passed when @func is called.
 *
 * Resolves a DNS name asynchronously. @func will be called with the
 * result (or an error).
 *
 * Currently this routine forks and does the lookup, which can cause
 * some problems. In general, this will work ok for most programs most
 * of the time. It will be slow or even fail when using operating
 * systems that copy the entire process when forking.
 *
 * If you need to lookup a lot of addresses, you should call
 * g_main_iteration(%FALSE) between calls. This will help prevent an
 * explosion of processes.
 *
 * Returns: ID of the lookup which can be used with
 * soup_gethostbyname_cancel() to cancel it.
 **/
SoupDNSHandle
soup_gethostbyname (const char *name, SoupGetHostByFn func, gpointer data)
{
	SoupDNSEntry *entry;
	int pipes[2];
	GIOChannel *chan;

	/* Try the cache */
	entry = lookup_entry (name);
	if (entry) {
		if (entry->expires < time (0) && !entry->source_id)
			free_entry (entry);
		else
			return lookup_info (entry, func, data);
	}

	entry = g_new0 (SoupDNSEntry, 1);
	entry->name = g_strdup (name);
	cache_entry (entry);

	/* Try to read the name as if it were dotted decimal */
	entry->h = new_hostent_from_phys (name);
	if (entry->h)
		return lookup_info (entry, func, data);

	/* Check to see if we are doing synchronous DNS lookups */
	if (getenv ("SOUP_SYNC_DNS")) {
		entry->h = soup_gethostbyname_internal (name);
		return lookup_info (entry, func, data);
	}

	/* Ok, we need to start a new lookup */

	if (pipe (pipes) == -1)
		return lookup_info (entry, func, data);

	entry->lookup_pid = fork ();
	switch (entry->lookup_pid) {
	case -1:
		g_warning ("Fork error: %s (%d)\n", g_strerror (errno), errno);
		close (pipes[0]);
		close (pipes[1]);

		return lookup_info (entry, func, data);

	case 0:
		/* Child */
		close (pipes[0]);

		entry->h = soup_gethostbyname_internal (name);
		if (entry->h)
			write_hostent (entry->h, pipes[1]);

		/* Close the socket */
		close (pipes[1]);

		/* Exit (we don't want atexit called, so do _exit instead) */
		_exit (EXIT_SUCCESS);

	default:
		/* Parent */
		close (pipes[1]);

		entry->fd = pipes[0];

		/* Set up a watch to read from the pipe */
		chan = g_io_channel_unix_new (pipes[0]);
		entry->source_id =
			g_io_add_watch (
				chan,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				soup_gethostby_cb,
				entry);
		g_io_channel_unref (chan);

		return lookup_info (entry, func, data);
	}
}

SoupDNSHandle
soup_gethostbyaddr (gpointer addr, int family,
		    SoupGetHostByFn func, gpointer data)
{
	SoupDNSEntry *entry;
	int pipes[2];
	GIOChannel *chan;
	char *name;

	name = soup_ntop (addr, family);
	g_return_val_if_fail (name != NULL, NULL);

	/* Try the cache */
	entry = lookup_entry (name);
	if (entry) {
		if (entry->expires > time (0))
			free_entry (entry);
		else {
			g_free (name);
			return lookup_info (entry, func, data);
		}
	}

	entry = g_new0 (SoupDNSEntry, 1);
	entry->name = name;
	cache_entry (entry);

	/* Check to see if we are doing synchronous DNS lookups */
	if (getenv ("SOUP_SYNC_DNS")) {
		entry->h = soup_gethostbyaddr_internal (addr, family);
		return lookup_info (entry, func, data);
	}

	if (pipe (pipes) != 0)
		return lookup_info (entry, func, data);

	entry->lookup_pid = fork ();
	switch (entry->lookup_pid) {
	case -1:
		close (pipes[0]);
		close (pipes[1]);

		g_warning ("Fork error: %s (%d)\n", g_strerror(errno), errno);
		return lookup_info (entry, func, data);

	case 0:
		/* Child */
		close (pipes[0]);

		entry->h = soup_gethostbyaddr_internal (addr, family);
		if (entry->h)
			write_hostent (entry->h, pipes[1]);

		/* Close the socket */
		close (pipes[1]);

		/* Exit (we don't want atexit called, so do _exit instead) */
		_exit (EXIT_SUCCESS);

	default:
		/* Parent */
		close (pipes[1]);

		entry->fd = pipes[0];

		/* Set up a watch to read from the pipe */
		chan = g_io_channel_unix_new (pipes[0]);
		entry->source_id =
			g_io_add_watch (
				chan,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				soup_gethostby_cb,
				entry);
		g_io_channel_unref (chan);

		return lookup_info (entry, func, data);
	}
}

void
soup_gethostby_cancel (SoupDNSHandle id)
{
	SoupDNSLookupInfo *info = id;
	SoupDNSEntry *entry = info->entry;

	entry->lookups = g_slist_remove (entry->lookups, info);
	g_free (info);

	if (!entry->lookups && entry->source_id) {
		g_source_remove (entry->source_id);
		if (entry->lookup_pid) {
			close (entry->fd);
			kill (entry->lookup_pid, SIGKILL);
			waitpid (entry->lookup_pid, NULL, 0);
			free_entry (entry);
		}
	}
}
