/*
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup-logger.h"
#include "soup-body-output-stream.h"

G_BEGIN_DECLS

void soup_logger_request_body_setup (SoupLogger           *logger,
                                     SoupMessage          *msg,
                                     SoupBodyOutputStream *stream);

G_END_DECLS
