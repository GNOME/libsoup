/*
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup-logger.h"
#include "soup-body-output-stream.h"

G_BEGIN_DECLS

void soup_logger_log_request_data (SoupLogger *logger, SoupMessage *msg, const char *buffer, gsize len);

G_END_DECLS
