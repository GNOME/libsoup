/*
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup-types.h"
#include "soup-logger.h"

G_BEGIN_DECLS

#define SOUP_TYPE_LOGGER_INPUT_STREAM (soup_logger_input_stream_get_type ())
G_DECLARE_FINAL_TYPE (SoupLoggerInputStream,
                      soup_logger_input_stream,
                      SOUP,
                      LOGGER_INPUT_STREAM,
                      GFilterInputStream)

SoupLogger *soup_logger_input_stream_get_logger (SoupLoggerInputStream *stream);

G_END_DECLS
