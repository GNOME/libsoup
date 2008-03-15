/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005, Novell, Inc.
 * Copyright (C) 2008, Red Hat, Inc.
 */

#ifndef SOUP_CODING_H
#define SOUP_CODING_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-message-body.h>

#define SOUP_TYPE_CODING            (soup_coding_get_type ())
#define SOUP_CODING(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_CODING, SoupCoding))
#define SOUP_CODING_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CODING, SoupCodingClass))
#define SOUP_IS_CODING(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_CODING))
#define SOUP_IS_CODING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_CODING))
#define SOUP_CODING_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CODING, SoupCodingClass))

typedef enum {
	SOUP_CODING_ENCODE,
	SOUP_CODING_DECODE
} SoupCodingDirection;

typedef enum {
	SOUP_CODING_STATUS_OK,
	SOUP_CODING_STATUS_ERROR,
	SOUP_CODING_STATUS_NEED_SPACE,
	SOUP_CODING_STATUS_COMPLETE,
} SoupCodingStatus;

typedef struct {
	GObject parent;

	SoupCodingDirection direction;
} SoupCoding;

typedef struct {
	GObjectClass parent_class;

	const char *name;

	SoupBuffer *     (*apply)      (SoupCoding     *coding,
					gconstpointer   input,
					gsize           input_length,
					gboolean        done,
					GError        **error);
	SoupCodingStatus (*apply_into) (SoupCoding     *coding,
					gconstpointer   input,
					gsize           input_length,
					gsize          *input_used,
					gpointer        output,
					gsize           output_length,
					gsize          *output_used,
					gboolean        done,
					GError        **error);

	/* Padding for future expansion */
	void (*_libsoup_reserved1) (void);
	void (*_libsoup_reserved2) (void);
	void (*_libsoup_reserved3) (void);
	void (*_libsoup_reserved4) (void);
} SoupCodingClass;

#define SOUP_CODING_DIRECTION "direction"

GType             soup_coding_get_type   (void);

SoupBuffer       *soup_coding_apply      (SoupCoding     *coding,
					  gconstpointer   input,
					  gsize           input_length,
					  gboolean        done,
					  GError        **error);
SoupCodingStatus  soup_coding_apply_into (SoupCoding     *coding,
					  gconstpointer   input,
					  gsize           input_length,
					  gsize          *input_used,
					  gpointer        output,
					  gsize           output_length,
					  gsize          *output_used,
					  gboolean        done,
					  GError        **error);

#define SOUP_CODING_ERROR soup_coding_error_quark()
GQuark soup_coding_error_quark (void);

typedef enum {
	SOUP_CODING_ERROR_DATA_ERROR,
	SOUP_CODING_ERROR_INTERNAL_ERROR
} SoupCodingError;

#endif /* SOUP_CODING_H */
