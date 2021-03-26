/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2021 Igalia S.L.
 */

#pragma once

#include "soup-message-metrics.h"

G_BEGIN_DECLS

struct _SoupMessageMetrics {
        guint64 fetch_start;
        guint64 dns_start;
        guint64 dns_end;
        guint64 connect_start;
        guint64 connect_end;
        guint64 tls_start;
        guint64 request_start;
        guint64 response_start;
        guint64 response_end;
};

SoupMessageMetrics *soup_message_metrics_new (void);

G_END_DECLS
