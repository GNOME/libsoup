/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_PRIVATE_H
#define SOUP_PRIVATE_H 1

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libsoup/soup-types.h>
#include <libsoup/soup-auth.h>
#include <libsoup/soup-misc.h>

#define RESPONSE_BLOCK_SIZE 8192

extern gboolean    soup_initialized;

extern SoupAuthorizeFn soup_auth_fn;
extern gpointer        soup_auth_fn_user_data;

#ifdef HAVE_IPV6
#define soup_sockaddr_max sockaddr_in6
#else
#define soup_sockaddr_max sockaddr_in
#endif

/* from soup-misc.c */

guint     soup_str_case_hash   (gconstpointer  key);
gboolean  soup_str_case_equal  (gconstpointer  v1,
				gconstpointer  v2);

#define SOUP_MAKE_TYPE(l,t,ci,i,parent) \
GType l##_get_type(void)\
{\
	static GType type = 0;				\
	if (!type){					\
		static GTypeInfo const object_info = {	\
			sizeof (t##Class),		\
							\
			(GBaseInitFunc) NULL,		\
			(GBaseFinalizeFunc) NULL,	\
							\
			(GClassInitFunc) ci,		\
			(GClassFinalizeFunc) NULL,	\
			NULL,	/* class_data */	\
							\
			sizeof (t),			\
			0,	/* n_preallocs */	\
			(GInstanceInitFunc) i,		\
		};					\
		type = g_type_register_static (parent, #t, &object_info, 0); \
	}						\
	return type;					\
}

#endif /*SOUP_PRIVATE_H*/
