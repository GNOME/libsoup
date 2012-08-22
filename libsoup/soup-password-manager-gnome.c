/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-password-manager-gnome.c: GNOME-keyring-based password manager
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

/* This is just a stub now; eventually it will go away completely. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-password-manager-gnome.h"
#include "soup.h"

G_DEFINE_TYPE_EXTENDED (SoupPasswordManagerGNOME, soup_password_manager_gnome, G_TYPE_OBJECT, 0,
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE, NULL))

static void
soup_password_manager_gnome_init (SoupPasswordManagerGNOME *manager_gnome)
{
}

static void
soup_password_manager_gnome_class_init (SoupPasswordManagerGNOMEClass *gnome_class)
{
}
