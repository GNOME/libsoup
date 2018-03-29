/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_AUTH_BASIC_H__
#define __SOUP_AUTH_BASIC_H__ 1

#include "soup-auth.h"

#define SOUP_AUTH_BASIC(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_AUTH_BASIC, SoupAuthBasic))
#define SOUP_AUTH_BASIC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_AUTH_BASIC, SoupAuthBasicClass))
#define SOUP_IS_AUTH_BASIC(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_AUTH_BASIC))
#define SOUP_IS_AUTH_BASIC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_AUTH_BASIC))
#define SOUP_AUTH_BASIC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_AUTH_BASIC, SoupAuthBasicClass))

typedef struct {
	SoupAuth parent;

} SoupAuthBasic;

typedef struct {
	SoupAuthClass  parent_class;

} SoupAuthBasicClass;

#endif /* __SOUP_AUTH_BASIC_H__ */
