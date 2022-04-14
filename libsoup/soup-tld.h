/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2012 Igalia S.L.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

SOUP_AVAILABLE_IN_ALL
const char *soup_tld_get_base_domain         (const char *hostname,
					      GError    **error);

SOUP_AVAILABLE_IN_ALL
gboolean    soup_tld_domain_is_public_suffix (const char *domain);


/**
 * soup_tld_error_quark:
 * Registers error quark for soup_tld_get_base_domain() if needed.
 *
 * Returns: Error quark for Soup TLD functions.
 */
SOUP_AVAILABLE_IN_ALL
GQuark soup_tld_error_quark (void);
#define SOUP_TLD_ERROR soup_tld_error_quark()

typedef enum {
	SOUP_TLD_ERROR_INVALID_HOSTNAME,
	SOUP_TLD_ERROR_IS_IP_ADDRESS,
	SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS,
	SOUP_TLD_ERROR_NO_BASE_DOMAIN,
	SOUP_TLD_ERROR_NO_PSL_DATA,
} SoupTLDError;

G_END_DECLS
