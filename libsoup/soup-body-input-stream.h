/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2012 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-filter-input-stream.h"
#include "soup-message-headers.h"

G_BEGIN_DECLS

#define SOUP_TYPE_BODY_INPUT_STREAM            (soup_body_input_stream_get_type ())
G_DECLARE_FINAL_TYPE (SoupBodyInputStream, soup_body_input_stream, SOUP, BODY_INPUT_STREAM, GFilterInputStream)


GInputStream *soup_body_input_stream_new (GInputStream *base_stream,
					  SoupEncoding  encoding,
					  goffset       content_length);

G_END_DECLS
