/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Ximian, Inc.
 */

#ifndef SOUP_TYPES_H
#define SOUP_TYPES_H 1

#include <glib/gtypes.h>
#include <glib-object.h>

#include <libsoup/soup-status.h>

typedef struct SoupAddress           SoupAddress;
typedef struct SoupConnection        SoupConnection;
typedef struct SoupMessage           SoupMessage;
typedef struct SoupMessageFilter     SoupMessageFilter;
typedef struct SoupServer            SoupServer;
typedef union  SoupServerAuth        SoupServerAuth;
typedef struct SoupServerAuthContext SoupServerAuthContext;
typedef struct SoupServerMessage     SoupServerMessage;
typedef struct SoupSession           SoupSession;
typedef struct SoupSessionAsync      SoupSessionAsync;
typedef struct SoupSessionSync       SoupSessionSync;
typedef struct SoupSocket            SoupSocket;
typedef struct SoupUri               SoupUri;

#define SOUP_MAKE_TYPE(type_name,TypeName,class_init,init,parent) \
GType type_name##_get_type(void)\
{\
	static GType type = 0;				\
	if (!type){					\
		static GTypeInfo const object_info = {	\
			sizeof (TypeName##Class),	\
							\
			(GBaseInitFunc) NULL,		\
			(GBaseFinalizeFunc) NULL,	\
							\
			(GClassInitFunc) class_init,	\
			(GClassFinalizeFunc) NULL,	\
			NULL,	/* class_data */	\
							\
			sizeof (TypeName),		\
			0,	/* n_preallocs */	\
			(GInstanceInitFunc) init,	\
		};					\
		type = g_type_register_static (parent, #TypeName, &object_info, 0); \
	}						\
	return type;					\
}

#define SOUP_MAKE_INTERFACE(type_name,TypeName,base_init) \
GType type_name##_get_type(void)\
{\
	static GType type = 0;				\
	if (!type){					\
		static GTypeInfo const object_info = {	\
			sizeof (TypeName##Class),	\
							\
			(GBaseInitFunc) base_init,	\
			(GBaseFinalizeFunc) NULL,	\
							\
			(GClassInitFunc) NULL,		\
			(GClassFinalizeFunc) NULL,	\
			NULL,	/* class_data */	\
							\
			0,				\
			0,	/* n_preallocs */	\
			(GInstanceInitFunc) NULL,	\
		};					\
		type = g_type_register_static (G_TYPE_INTERFACE, #TypeName, &object_info, 0); \
	}						\
	return type;					\
}

#define SOUP_MAKE_TYPE_WITH_IFACE(type_name,TypeName,class_init,init,parent,iface_init,iparent) \
GType type_name##_get_type(void)\
{\
	static GType type = 0;				\
	if (!type){					\
		static GTypeInfo const object_info = {	\
			sizeof (TypeName##Class),	\
							\
			(GBaseInitFunc) NULL,		\
			(GBaseFinalizeFunc) NULL,	\
							\
			(GClassInitFunc) class_init,	\
			(GClassFinalizeFunc) NULL,	\
			NULL,	/* class_data */	\
							\
			sizeof (TypeName),		\
			0,	/* n_preallocs */	\
			(GInstanceInitFunc) init,	\
		};					\
		static GInterfaceInfo const iface_info = {	\
			(GInterfaceInitFunc) iface_init,	\
			NULL,					\
			NULL					\
		};						\
		type = g_type_register_static (parent, #TypeName, &object_info, 0);	\
		g_type_add_interface_static (type, iparent, &iface_info);		\
	}						\
	return type;					\
}

#endif
