#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libsoup/soup.h>

static void rev_read (SoupSocket *sock, GString *buf);
static void rev_write (SoupSocket *sock, GString *buf);

gboolean nonblocking = TRUE;

static void
reverse (GString *buf)
{
	char tmp, *a, *b;

	a = buf->str;
	b = buf->str + buf->len - 1;

	while (isspace ((unsigned char)*b) && b > a)
		b--;

	while (a < b) {
		tmp = *a;
		*a++ = *b;
		*b-- = tmp;
	}
}

static void
rev_done (SoupSocket *sock, GString *buf)
{
	g_signal_handlers_disconnect_by_func (sock, rev_read, buf);
	g_signal_handlers_disconnect_by_func (sock, rev_write, buf);
	g_object_unref (sock);
	g_string_free (buf, TRUE);
}

static void
rev_write (SoupSocket *sock, GString *buf)
{
	SoupSocketIOStatus status;
	guint nwrote;

	do {
		status = soup_socket_write (sock, buf->str, buf->len, &nwrote);
		memmove (buf->str, buf->str + nwrote, buf->len - nwrote);
		buf->len -= nwrote;
	} while (status == SOUP_SOCKET_OK && buf->len);

	switch (status) {
	case SOUP_SOCKET_OK:
		rev_read (sock, buf);
		break;

	case SOUP_SOCKET_WOULD_BLOCK:
		g_assert (nonblocking == TRUE);
		break;

	default:
		g_warning ("Socket error");
		/* fall through */

	case SOUP_SOCKET_EOF:
		rev_done (sock, buf);
		break;
	}
}

static void
rev_read (SoupSocket *sock, GString *buf)
{
	SoupSocketIOStatus status;
	char tmp[10];
	guint nread;
	gboolean eol;

	do {
		status = soup_socket_read_until (sock, tmp, sizeof (tmp),
						 "\n", 1, &nread, &eol);
		if (status == SOUP_SOCKET_OK)
			g_string_append_len (buf, tmp, nread);
	} while (status == SOUP_SOCKET_OK && !eol);

	switch (status) {
	case SOUP_SOCKET_OK:
		reverse (buf);
		rev_write (sock, buf);
		break;

	case SOUP_SOCKET_WOULD_BLOCK:
		g_assert (nonblocking == TRUE);
		break;

	default:
		g_warning ("Socket error");
		/* fall through */

	case SOUP_SOCKET_EOF:
		rev_done (sock, buf);
		break;
	}
}

static void
new_connection (SoupSocket *listener, SoupSocket *client, gpointer user_data)
{
	GString *buf;

	g_object_ref (client);
	buf = g_string_new (NULL);

	if (nonblocking) {
		g_signal_connect (client, "readable",
				  G_CALLBACK (rev_read), buf);
		g_signal_connect (client, "writable",
				  G_CALLBACK (rev_write), buf);
	} else
		soup_socket_set_flag (client, SOUP_SOCKET_FLAG_NONBLOCKING, FALSE);

	rev_read (client, buf);
}

int
main (int argc, char **argv)
{
	SoupSocket *listener;
	SoupAddressFamily family = SOUP_ADDRESS_FAMILY_IPV4;
	guint port = SOUP_ADDRESS_ANY_PORT;
	SoupAddress *addr;
	GMainLoop *loop;
	int opt;

	g_type_init ();

	while ((opt = getopt (argc, argv, "6bp:")) != -1) {
		switch (opt) {
		case '6':
			family = SOUP_ADDRESS_FAMILY_IPV6;
			break;
		case 'b':
			nonblocking = FALSE;
			break;
		case 'p':
			port = atoi (optarg);
			break;
		default:
			fprintf (stderr, "Usage: %s [-6] [-b] [-p port]\n",
				 argv[0]);
			exit (1);
		}
	}

	addr = soup_address_new_any (family, port);
	if (!addr) {
		fprintf (stderr, "Could not create listener address\n");
		exit (1);
	}

	listener = soup_socket_server_new (addr, port,
					   new_connection, NULL);
	g_object_unref (addr);
	if (!listener) {
		fprintf (stderr, "Could not create listening socket\n");
		exit (1);
	}
	printf ("Listening on port %d\n",
		soup_address_get_port (
			soup_socket_get_local_address (listener)));

	loop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run (loop);

	g_object_unref (listener);
	return 0;
}
