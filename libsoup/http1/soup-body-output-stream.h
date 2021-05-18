/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2012 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-message-headers.h"

G_BEGIN_DECLS

#define SOUP_TYPE_BODY_OUTPUT_STREAM            (soup_body_output_stream_get_type ())
G_DECLARE_FINAL_TYPE (SoupBodyOutputStream, soup_body_output_stream, SOUP, BODY_OUTPUT_STREAM, GFilterOutputStream)

GOutputStream *soup_body_output_stream_new (GOutputStream *base_stream,
					    SoupEncoding   encoding,
					    goffset        content_length);

G_END_DECLS
