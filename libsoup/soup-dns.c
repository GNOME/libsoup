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
#include <sys/select.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "soup-dns.h"
#include "soup-misc.h"

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

void
soup_dns_free_hostent (struct hostent *h)
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
soup_dns_ntop (gconstpointer addr, int family)
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
		result = gethostbyname (hostname);
	}
#endif

	if (result)
		out = copy_hostent (result);
	else
		out = NULL;

	if (buf)
		g_free (buf);

	return out;
}

static struct hostent *
soup_gethostbyaddr_internal (gconstpointer addr, int family)
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
		result = gethostbyaddr (addr, length, family);
	}
#endif

	if (result)
		out = copy_hostent (result);
	else
		out = NULL;

	if (buf)
		g_free (buf);

	return out;
}


/* Cache */

struct SoupDNSEntry {
	char           *name;
	struct hostent *h;
	gboolean        resolved;

	time_t          expires;
	guint           ref_count;

	pid_t           lookup_pid;
	int             fd;
};

static GHashTable *soup_dns_entries;

#define SOUP_DNS_ENTRIES_MAX 20

static GStaticMutex soup_dns_mutex = G_STATIC_MUTEX_INIT;
#define soup_dns_lock() g_static_mutex_lock (&soup_dns_mutex)
#define soup_dns_unlock() g_static_mutex_unlock (&soup_dns_mutex)

static void
soup_dns_entry_ref (SoupDNSEntry *entry)
{
	entry->ref_count++;
}

static void
soup_dns_entry_unref (SoupDNSEntry *entry)
{
	if (!--entry->ref_count) {
		g_free (entry->name);

		if (entry->h)
			soup_dns_free_hostent (entry->h);

		if (entry->fd)
			close (entry->fd);
		if (entry->lookup_pid) {
			kill (entry->lookup_pid, SIGKILL);
			waitpid (entry->lookup_pid, NULL, 0);
		}

		g_free (entry);
	}
}

static void
uncache_entry (SoupDNSEntry *entry)
{
	g_hash_table_remove (soup_dns_entries, entry->name);
	soup_dns_entry_unref (entry);
}

static void
prune_cache_cb (gpointer key, gpointer value, gpointer data)
{
	SoupDNSEntry *entry = value, **prune_entry = data; 

	if (!*prune_entry || (*prune_entry)->expires > entry->expires)
		*prune_entry = entry;
}

static SoupDNSEntry *
soup_dns_entry_new (const char *name)
{
	SoupDNSEntry *entry;

	entry = g_new0 (SoupDNSEntry, 1);
	entry->name = g_strdup (name);
	entry->ref_count = 2; /* One for the caller, one for the cache */

	if (!soup_dns_entries) {
		soup_dns_entries = g_hash_table_new (soup_str_case_hash,
						     soup_str_case_equal);
	} else if (g_hash_table_size (soup_dns_entries) == SOUP_DNS_ENTRIES_MAX) {
		SoupDNSEntry *prune_entry = NULL;

		g_hash_table_foreach (soup_dns_entries, prune_cache_cb,
				      &prune_entry);
		if (prune_entry)
			uncache_entry (prune_entry);
	}

	entry->expires = time (0) + 60 * 60;
	g_hash_table_insert (soup_dns_entries, entry->name, entry);

	return entry;
}

static SoupDNSEntry *
soup_dns_lookup_entry (const char *name)
{
	SoupDNSEntry *entry;

	if (!soup_dns_entries)
		return NULL;

	entry = g_hash_table_lookup (soup_dns_entries, name);
	if (entry)
		soup_dns_entry_ref (entry);
	return entry;
}

/**
 * soup_dns_entry_from_name:
 * @name: a nice name (eg, mofo.eecs.umich.edu) or a dotted decimal name
 *   (eg, 141.213.8.59).
 *
 * Begins asynchronous resolution of @name. The caller should
 * periodically call soup_entry_check_lookup() to see if it is done,
 * and call soup_entry_get_hostent() when soup_entry_check_lookup()
 * returns %TRUE.
 *
 * Currently, this routine forks and does the lookup, which can cause
 * some problems. In general, this will work ok for most programs most
 * of the time. It will be slow or even fail when using operating
 * systems that copy the entire process when forking.
 *
 * Returns: a #SoupDNSEntry, which will be freed when you call
 * soup_entry_get_hostent() or soup_entry_cancel_lookup().
 **/
SoupDNSEntry *
soup_dns_entry_from_name (const char *name)
{
	SoupDNSEntry *entry;
	int pipes[2];

	soup_dns_lock ();

	/* Try the cache */
	entry = soup_dns_lookup_entry (name);
	if (entry) {
		soup_dns_unlock ();
		return entry;
	}

	entry = soup_dns_entry_new (name);

	/* Try to read the name as if it were dotted decimal */
	entry->h = new_hostent_from_phys (name);
	if (entry->h) {
		entry->resolved = TRUE;
		soup_dns_unlock ();
		return entry;
	}

	/* Check to see if we are doing synchronous DNS lookups */
	if (getenv ("SOUP_SYNC_DNS")) {
		entry->h = soup_gethostbyname_internal (name);
		entry->resolved = TRUE;
		soup_dns_unlock ();
		return entry;
	}

	/* Ok, we need to start a new lookup */

	if (pipe (pipes) == -1) {
		entry->resolved = TRUE;
		soup_dns_unlock ();
		return entry;
	}

	entry->lookup_pid = fork ();
	switch (entry->lookup_pid) {
	case -1:
		g_warning ("Fork error: %s (%d)\n", g_strerror (errno), errno);
		close (pipes[0]);
		close (pipes[1]);

		entry->resolved = TRUE;
		soup_dns_unlock ();
		return entry;

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
		soup_dns_unlock ();
		return entry;
	}
}

/**
 * soup_dns_entry_from_addr:
 * @addr: pointer to address data (eg, an #in_addr_t)
 * @family: address family of @addr
 *
 * Begins asynchronous resolution of @addr. The caller should
 * periodically call soup_entry_check_lookup() to see if it is done,
 * and call soup_entry_get_hostent() when soup_entry_check_lookup()
 * returns %TRUE.
 *
 * Currently, this routine forks and does the lookup, which can cause
 * some problems. In general, this will work ok for most programs most
 * of the time. It will be slow or even fail when using operating
 * systems that copy the entire process when forking.
 *
 * Returns: a #SoupDNSEntry, which will be freed when you call
 * soup_entry_get_hostent() or soup_entry_cancel_lookup().
 **/
SoupDNSEntry *
soup_dns_entry_from_addr (gconstpointer addr, int family)
{
	SoupDNSEntry *entry;
	int pipes[2];
	char *name;

	name = soup_dns_ntop (addr, family);
	g_return_val_if_fail (name != NULL, NULL);

	soup_dns_lock ();

	/* Try the cache */
	entry = soup_dns_lookup_entry (name);
	if (entry) {
		g_free (name);
		soup_dns_unlock ();
		return entry;
	}

	entry = soup_dns_entry_new (name);

	/* Check to see if we are doing synchronous DNS lookups */
	if (getenv ("SOUP_SYNC_DNS")) {
		entry->h = soup_gethostbyaddr_internal (addr, family);
		entry->resolved = TRUE;
		soup_dns_unlock ();
		return entry;
	}

	if (pipe (pipes) != 0) {
		entry->resolved = TRUE;
		soup_dns_unlock ();
		return entry;
	}

	entry->lookup_pid = fork ();
	switch (entry->lookup_pid) {
	case -1:
		close (pipes[0]);
		close (pipes[1]);

		g_warning ("Fork error: %s (%d)\n", g_strerror(errno), errno);
		entry->resolved = TRUE;
		soup_dns_unlock ();
		return entry;

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
		soup_dns_unlock ();
		return entry;
	}
}

static void
check_hostent (SoupDNSEntry *entry, gboolean block)
{
	char buf[256], *namelenp, *name, *typep, *addrlenp, *addr;
	int bytes_read, nread, status;
	fd_set readfds;
	struct timeval tv = { 0, 0 }, *tvp;

	soup_dns_lock ();

	if (entry->resolved) {
		soup_dns_unlock ();
		return;
	}

	if (block)
		tvp = NULL;
	else
		tvp = &tv;

	do {
		FD_ZERO (&readfds);
		FD_SET (entry->fd, &readfds);
		status = select (entry->fd + 1, &readfds, NULL, NULL, tvp);
	} while (status == -1 && errno == EINTR);

	if (status == 0) {
		soup_dns_unlock ();
		return;
	}
	
	nread = 0;
	do {
		bytes_read = read (entry->fd, buf + nread, 
		                   sizeof (buf) - nread);

		if (bytes_read > 0)
			nread += bytes_read;
	} while (bytes_read > 0 || (bytes_read == -1 && errno == EINTR));

	close (entry->fd);
	entry->fd = -1;
	kill (entry->lookup_pid, SIGKILL);
	waitpid (entry->lookup_pid, NULL, 0);
	entry->lookup_pid = 0;
	entry->resolved = TRUE;

	if (nread < 1) {
		soup_dns_unlock ();
		return;
	}

	namelenp = buf;
	name = namelenp + 1;
	typep = name + *namelenp;
	addrlenp = typep + 1;
	addr = addrlenp + 1;

	if (addrlenp < buf + nread && (addr + *addrlenp) == buf + nread)
		entry->h = new_hostent (name, *typep, *addrlenp, addr);
	soup_dns_unlock ();
}

gboolean
soup_dns_entry_check_lookup (SoupDNSEntry *entry)
{
	check_hostent (entry, FALSE);

	if (entry->resolved && entry->h == NULL)
		uncache_entry (entry);

	return entry->resolved;
}

struct hostent *
soup_dns_entry_get_hostent (SoupDNSEntry *entry)
{
	struct hostent *h;

	check_hostent (entry, TRUE);
	h = entry->h ? copy_hostent (entry->h) : NULL;
	soup_dns_entry_unref (entry);

	return h;
}

void
soup_dns_entry_cancel_lookup (SoupDNSEntry *entry)
{
	soup_dns_entry_unref (entry);
}
