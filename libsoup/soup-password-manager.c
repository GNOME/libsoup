/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-password-manager.c: HTTP auth password manager interface
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-password-manager.h"
#include "soup.h"

G_DEFINE_INTERFACE_WITH_CODE (SoupPasswordManager, soup_password_manager, G_TYPE_OBJECT,
			      g_type_interface_add_prerequisite (g_define_type_id, SOUP_TYPE_SESSION_FEATURE);
			      )

static void
soup_password_manager_default_init (SoupPasswordManagerInterface *iface)
{
}

/**
 * soup_password_manager_get_passwords_async:
 * @callback: (scope async)
 */
void
soup_password_manager_get_passwords_async (SoupPasswordManager  *password_manager,
					   SoupMessage          *msg,
					   SoupAuth             *auth,
					   gboolean              retrying,
					   GMainContext         *async_context,
					   GCancellable         *cancellable,
					   SoupPasswordManagerCallback callback,
					   gpointer              user_data)
{
	g_warn_if_reached ();
}

void
soup_password_manager_get_passwords_sync (SoupPasswordManager  *password_manager,
					  SoupMessage          *msg,
					  SoupAuth             *auth,
					  GCancellable         *cancellable)
{
	g_warn_if_reached ();
}
