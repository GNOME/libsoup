/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup-connection.h"
#include <gio/gio.h>

G_BEGIN_DECLS

#define SOUP_TYPE_TLS_INTERACTION (soup_tls_interaction_get_type ())
G_DECLARE_FINAL_TYPE (SoupTlsInteraction, soup_tls_interaction, SOUP, TLS_INTERACTION, GTlsInteraction)

GType            soup_tls_interaction_get_type (void);
GTlsInteraction *soup_tls_interaction_new      (SoupConnection *conn);

G_END_DECLS
