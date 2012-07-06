/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2012 Igalia S.L.
 */

#ifndef __SOUP_TLD_H__
#define __SOUP_TLD_H__

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

const char *soup_tld_get_base_domain         (const char *hostname,
					      GError    **error);

gboolean    soup_tld_domain_is_public_suffix (const char *domain);

/* Errors */
#define SOUP_TLD_ERROR soup_tld_error_quark()
GQuark soup_tld_error_quark (void);

typedef enum {
	SOUP_TLD_ERROR_INVALID_HOSTNAME,
	SOUP_TLD_ERROR_IS_IP_ADDRESS,
	SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS
} SoupTLDError;

G_END_DECLS

#endif /* __SOUP_TLD_H__ */
