/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-socket-properties.h"
#include "soup.h"

SoupSocketProperties *
soup_socket_properties_new (GInetSocketAddress *local_addr,
			    GTlsInteraction    *tls_interaction,
			    guint               io_timeout,
			    guint               idle_timeout)
{
	SoupSocketProperties *props;

	props = g_slice_new0 (SoupSocketProperties);

        g_atomic_ref_count_init (&props->ref_count);

	props->proxy_use_default = TRUE;
	props->tlsdb_use_default = TRUE;

	props->local_addr = local_addr ? g_object_ref (local_addr) : NULL;
	props->tls_interaction = tls_interaction ? g_object_ref (tls_interaction) : NULL;

	props->io_timeout = io_timeout;
	props->idle_timeout = idle_timeout;

	return props;
}

SoupSocketProperties *
soup_socket_properties_ref (SoupSocketProperties *props)
{
	g_atomic_ref_count_inc (&props->ref_count);
	return props;
}

void
soup_socket_properties_unref (SoupSocketProperties *props)
{
	if (!g_atomic_ref_count_dec (&props->ref_count))
		return;

	g_clear_object (&props->proxy_resolver);
	g_clear_object (&props->local_addr);
	g_clear_object (&props->tlsdb);
	g_clear_object (&props->tls_interaction);

	g_slice_free (SoupSocketProperties, props);
}

void
soup_socket_properties_set_proxy_resolver (SoupSocketProperties *props,
					   GProxyResolver       *proxy_resolver)
{
	props->proxy_use_default = FALSE;

	if (props->proxy_resolver == proxy_resolver)
		return;

	g_clear_object (&props->proxy_resolver);
	props->proxy_resolver = proxy_resolver ? g_object_ref (proxy_resolver) : NULL;
}

void
soup_socket_properties_set_tls_database (SoupSocketProperties *props,
					 GTlsDatabase         *tlsdb)
{
	props->tlsdb_use_default = FALSE;

	if (props->tlsdb == tlsdb)
		return;

	g_clear_object (&props->tlsdb);
	props->tlsdb = tlsdb ? g_object_ref (tlsdb) : NULL;
}

G_DEFINE_BOXED_TYPE (SoupSocketProperties, soup_socket_properties, soup_socket_properties_ref, soup_socket_properties_unref)
