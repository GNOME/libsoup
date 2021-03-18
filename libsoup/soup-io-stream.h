/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2012 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_IO_STREAM            (soup_io_stream_get_type ())
G_DECLARE_FINAL_TYPE (SoupIOStream, soup_io_stream, SOUP, IO_STREAM, GIOStream)

GIOStream *soup_io_stream_new (GIOStream *base_iostream,
			       gboolean   close_on_dispose);

GIOStream *soup_io_stream_get_base_iostream (SoupIOStream *stream);

G_END_DECLS
