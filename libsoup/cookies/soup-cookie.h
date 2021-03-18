/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/* 
 * Copyright 2007, 2008 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

/**
 * SoupSameSitePolicy:
 * @SOUP_SAME_SITE_POLICY_NONE: The cookie is exposed with both cross-site and same-site requests
 * @SOUP_SAME_SITE_POLICY_LAX: The cookie is withheld on cross-site requests but exposed on cross-site navigations
 * @SOUP_SAME_SITE_POLICY_STRICT: The cookie is only exposed for same-site requests
 *
 * Represents the same-site policies of a cookie.
 */
typedef enum {
	SOUP_SAME_SITE_POLICY_NONE,
	SOUP_SAME_SITE_POLICY_LAX,
	SOUP_SAME_SITE_POLICY_STRICT,
} SoupSameSitePolicy;

typedef struct _SoupCookie SoupCookie;

SOUP_AVAILABLE_IN_ALL
GType soup_cookie_get_type (void);
#define SOUP_TYPE_COOKIE (soup_cookie_get_type())

#define SOUP_COOKIE_MAX_AGE_ONE_HOUR (60 * 60)
#define SOUP_COOKIE_MAX_AGE_ONE_DAY  (SOUP_COOKIE_MAX_AGE_ONE_HOUR * 24)
#define SOUP_COOKIE_MAX_AGE_ONE_WEEK (SOUP_COOKIE_MAX_AGE_ONE_DAY * 7)
#define SOUP_COOKIE_MAX_AGE_ONE_YEAR (SOUP_COOKIE_MAX_AGE_ONE_DAY * 365.2422)

SOUP_AVAILABLE_IN_ALL
SoupCookie *soup_cookie_new                     (const char  *name,
						 const char  *value,
						 const char  *domain,
						 const char  *path,
						 int          max_age);
SOUP_AVAILABLE_IN_ALL
SoupCookie *soup_cookie_parse                   (const char  *header,
						 GUri        *origin);
SOUP_AVAILABLE_IN_ALL
SoupCookie *soup_cookie_copy                    (SoupCookie  *cookie);

SOUP_AVAILABLE_IN_ALL
const char *soup_cookie_get_name                (SoupCookie  *cookie);
SOUP_AVAILABLE_IN_ALL
void        soup_cookie_set_name                (SoupCookie  *cookie,
						 const char  *name);
SOUP_AVAILABLE_IN_ALL
const char *soup_cookie_get_value               (SoupCookie  *cookie);
SOUP_AVAILABLE_IN_ALL
void        soup_cookie_set_value               (SoupCookie  *cookie,
						 const char  *value);
SOUP_AVAILABLE_IN_ALL
const char *soup_cookie_get_domain              (SoupCookie  *cookie);
SOUP_AVAILABLE_IN_ALL
void        soup_cookie_set_domain              (SoupCookie  *cookie,
						 const char  *domain);
SOUP_AVAILABLE_IN_ALL
const char *soup_cookie_get_path                (SoupCookie  *cookie);
SOUP_AVAILABLE_IN_ALL
void        soup_cookie_set_path                (SoupCookie  *cookie,
						 const char  *path);
SOUP_AVAILABLE_IN_ALL
void        soup_cookie_set_max_age             (SoupCookie  *cookie,
						 int          max_age);
SOUP_AVAILABLE_IN_ALL
GDateTime   *soup_cookie_get_expires            (SoupCookie  *cookie);
SOUP_AVAILABLE_IN_ALL
void        soup_cookie_set_expires             (SoupCookie  *cookie,
						 GDateTime    *expires);
SOUP_AVAILABLE_IN_ALL
gboolean    soup_cookie_get_secure              (SoupCookie  *cookie);
SOUP_AVAILABLE_IN_ALL
void        soup_cookie_set_secure              (SoupCookie  *cookie,
						 gboolean     secure);
SOUP_AVAILABLE_IN_ALL
gboolean    soup_cookie_get_http_only           (SoupCookie  *cookie);
SOUP_AVAILABLE_IN_ALL
void        soup_cookie_set_http_only           (SoupCookie  *cookie,
						 gboolean     http_only);

SOUP_AVAILABLE_IN_ALL
void        soup_cookie_set_same_site_policy    (SoupCookie         *cookie,
                                                 SoupSameSitePolicy  policy);
SOUP_AVAILABLE_IN_ALL
SoupSameSitePolicy soup_cookie_get_same_site_policy (SoupCookie     *cookie);

SOUP_AVAILABLE_IN_ALL
char       *soup_cookie_to_set_cookie_header    (SoupCookie  *cookie);
SOUP_AVAILABLE_IN_ALL
char       *soup_cookie_to_cookie_header        (SoupCookie  *cookie);

SOUP_AVAILABLE_IN_ALL
gboolean    soup_cookie_applies_to_uri          (SoupCookie  *cookie,
						 GUri        *uri);
SOUP_AVAILABLE_IN_ALL
gboolean    soup_cookie_equal                   (SoupCookie  *cookie1,
						 SoupCookie  *cookie2);

SOUP_AVAILABLE_IN_ALL
void        soup_cookie_free                    (SoupCookie  *cookie);

SOUP_AVAILABLE_IN_ALL
GSList     *soup_cookies_from_response          (SoupMessage *msg);
SOUP_AVAILABLE_IN_ALL
GSList     *soup_cookies_from_request           (SoupMessage *msg);

SOUP_AVAILABLE_IN_ALL
void        soup_cookies_to_response            (GSList      *cookies,
						 SoupMessage *msg);
SOUP_AVAILABLE_IN_ALL
void        soup_cookies_to_request             (GSList      *cookies,
						 SoupMessage *msg);

SOUP_AVAILABLE_IN_ALL
void        soup_cookies_free                   (GSList      *cookies);

SOUP_AVAILABLE_IN_ALL
char       *soup_cookies_to_cookie_header       (GSList      *cookies);

SOUP_AVAILABLE_IN_ALL
gboolean    soup_cookie_domain_matches          (SoupCookie  *cookie,
						 const char  *host);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupCookie, soup_cookie_free)

G_END_DECLS
