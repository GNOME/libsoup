#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libsoup/soup.h>

static void
got_address (SoupAddress *addr, SoupKnownErrorCode status, gpointer user_data)
{
	SoupSocket *client = user_data;
	const char *name, *phys;
	time_t now;
	char *timebuf;
	GIOChannel *chan;
	gsize wrote;

	name = soup_address_get_name (addr);
	phys = soup_address_get_physical (addr);

	printf ("got connection from %s (%s) port %d\n",
		name ? name : "?", phys,
		soup_address_get_port (addr));

	now = time (NULL);
	timebuf = ctime (&now);

	chan = soup_socket_get_iochannel (client);
	g_io_channel_write (chan, timebuf, strlen (timebuf), &wrote);
	g_io_channel_unref (chan);

	g_object_unref (client);
}

static void
new_connection (SoupSocket *listener, SoupSocket *client, gpointer user_data)
{
	SoupAddress *addr;

	g_object_ref (client);
	addr = soup_socket_get_remote_address (client);
	soup_address_resolve (addr, got_address, client);
}

int
main (int argc, char **argv)
{
	SoupSocket *listener;
	SoupAddressFamily family;
	SoupAddress *addr;
	guint port;
	GMainLoop *loop;

	g_type_init ();

	if (argc >=2 && !strcmp (argv[1], "-6")) {
		family = SOUP_ADDRESS_FAMILY_IPV6;
		argc--;
		argv++;
	} else
		family = SOUP_ADDRESS_FAMILY_IPV4;

	if (argc > 2) {
		fprintf (stderr, "Usage: %s [-6] [port]\n", argv[0]);
		exit (1);
	}

	if (argc == 2)
		port = atoi (argv[1]);
	else
		port = SOUP_ADDRESS_ANY_PORT;

	addr = soup_address_new_any (SOUP_ADDRESS_FAMILY_IPV4, port);
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
