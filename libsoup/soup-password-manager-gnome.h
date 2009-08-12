/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef SOUP_PASSWORD_MANAGER_GNOME_H
#define SOUP_PASSWORD_MANAGER_GNOME_H 1

#include <libsoup/soup-password-manager.h>

#define SOUP_TYPE_PASSWORD_MANAGER_GNOME            (soup_password_manager_gnome_get_type ())
#define SOUP_PASSWORD_MANAGER_GNOME(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_PASSWORD_MANAGER_GNOME, SoupPasswordManagerGNOME))
#define SOUP_PASSWORD_MANAGER_GNOME_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_PASSWORD_MANAGER_GNOME, SoupPasswordManagerGNOMEClass))
#define SOUP_IS_PASSWORD_MANAGER_GNOME(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_PASSWORD_MANAGER_GNOME))
#define SOUP_IS_PASSWORD_MANAGER_GNOME_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_PASSWORD_MANAGER_GNOME))
#define SOUP_PASSWORD_MANAGER_GNOME_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_PASSWORD_MANAGER_GNOME, SoupPasswordManagerGNOMEClass))

typedef struct {
	GObject parent;

} SoupPasswordManagerGNOME;

typedef struct {
	GObjectClass parent_class;

} SoupPasswordManagerGNOMEClass;

GType soup_password_manager_gnome_get_type (void);

SoupPasswordManager *soup_password_manager_gnome_new (void);

#endif /* SOUP_PASSWORD_MANAGER_GNOME_H */
