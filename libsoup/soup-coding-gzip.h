/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef SOUP_CODING_GZIP_H
#define SOUP_CODING_GZIP_H 1

#include "soup-coding.h"

#define SOUP_TYPE_CODING_GZIP            (soup_coding_gzip_get_type ())
#define SOUP_CODING_GZIP(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_CODING_GZIP, SoupCodingGzip))
#define SOUP_CODING_GZIP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CODING_GZIP, SoupCodingGzipClass))
#define SOUP_IS_CODING_GZIP(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_CODING_GZIP))
#define SOUP_IS_CODING_GZIP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_CODING_GZIP))
#define SOUP_CODING_GZIP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CODING_GZIP, SoupCodingGzipClass))

typedef struct {
	SoupCoding parent;

} SoupCodingGzip;

typedef struct {
	SoupCodingClass  parent_class;

} SoupCodingGzipClass;

GType soup_coding_gzip_get_type (void);

SoupCoding *soup_coding_gzip_new (SoupCodingDirection direction);

#endif /* SOUP_CODING_GZIP_H */
