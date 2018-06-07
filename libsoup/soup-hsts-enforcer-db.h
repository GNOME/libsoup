/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2016, 2017, 2018 Igalia S.L.
 * Copyright (C) 2017, 2018 Metrological Group B.V.
 */

#ifndef __SOUP_HSTS_ENFORCER_DB_H__
#define __SOUP_HSTS_ENFORCER_DB_H__ 1

#include <libsoup/soup-hsts-enforcer.h>

G_BEGIN_DECLS

#define SOUP_TYPE_HSTS_ENFORCER_DB            (soup_hsts_enforcer_db_get_type ())
#define SOUP_HSTS_ENFORCER_DB(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HSTS_ENFORCER_DB, SoupHSTSEnforcerDB))
#define SOUP_HSTS_ENFORCER_DB_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HSTS_ENFORCER_DB, SoupHSTSEnforcerDBClass))
#define SOUP_IS_HSTS_ENFORCER_DB(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HSTS_ENFORCER_DB))
#define SOUP_IS_HSTS_ENFORCER_DB_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HSTS_ENFORCER_DB))
#define SOUP_HSTS_ENFORCER_DB_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HSTS_ENFORCER_DB, SoupHSTSEnforcerDBClass))

typedef struct _SoupHSTSEnforcerDBPrivate SoupHSTSEnforcerDBPrivate;

typedef struct {
	SoupHSTSEnforcer parent;

	SoupHSTSEnforcerDBPrivate *priv;

} SoupHSTSEnforcerDB;

typedef struct {
	SoupHSTSEnforcerClass parent_class;

	/* Padding for future expansion */
	void (*_libsoup_reserved1) (void);
	void (*_libsoup_reserved2) (void);
	void (*_libsoup_reserved3) (void);
	void (*_libsoup_reserved4) (void);
} SoupHSTSEnforcerDBClass;

#define SOUP_HSTS_ENFORCER_DB_FILENAME  "filename"

SOUP_AVAILABLE_IN_2_68
GType soup_hsts_enforcer_db_get_type (void);

SOUP_AVAILABLE_IN_2_68
SoupHSTSEnforcer *soup_hsts_enforcer_db_new (const char *filename);

G_END_DECLS

#endif /* __SOUP_HSTS_ENFORCER_DB_H__ */
