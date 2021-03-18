/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2012 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_FILTER_INPUT_STREAM            (soup_filter_input_stream_get_type ())
G_DECLARE_DERIVABLE_TYPE (SoupFilterInputStream, soup_filter_input_stream, SOUP, FILTER_INPUT_STREAM, GFilterInputStream)

struct _SoupFilterInputStreamClass {
	GFilterInputStreamClass parent_class;
};

GInputStream *soup_filter_input_stream_new        (GInputStream           *base_stream);

gssize        soup_filter_input_stream_read_line  (SoupFilterInputStream  *fstream,
						   void                   *buffer,
						   gsize                   length,
						   gboolean                blocking,
						   gboolean               *got_line,
						   GCancellable           *cancellable,
						   GError                **error);
gssize        soup_filter_input_stream_read_until (SoupFilterInputStream  *fstream,
						   void                   *buffer,
						   gsize                   length,
						   const void             *boundary,
						   gsize                   boundary_len,
						   gboolean                blocking,
						   gboolean                include_boundary,
						   gboolean               *got_boundary,
						   GCancellable           *cancellable,
						   GError                **error);

G_END_DECLS
