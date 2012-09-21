/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-version.c: Version information
 *
 * Copyright (C) 2012 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-version.h"

/**
 * SECTION:soup-version
 * @short_description: Variables and functions to check the libsoup version
 **/

/**
 * SOUP_MAJOR_VERSION:
 *
 * Like soup_get_major_version(), but from the headers used at
 * application compile time, rather than from the library linked
 * against at application run time.
 *
 * Since: 2.42
 */

/**
 * SOUP_MINOR_VERSION:
 *
 * Like soup_get_minor_version(), but from the headers used at
 * application compile time, rather than from the library linked
 * against at application run time.
 *
 * Since: 2.42
 */

/**
 * SOUP_MICRO_VERSION:
 *
 * Like soup_get_micro_version(), but from the headers used at
 * application compile time, rather than from the library linked
 * against at application run time.
 *
 * Since: 2.42
 */

/**
 * SOUP_CHECK_VERSION:
 * @major: major version (e.g. 2 for version 2.42.0)
 * @minor: minor version (e.g. 42 for version 2.42.0)
 * @micro: micro version (e.g. 0 for version 2.42.0)
 *
 * Returns: %TRUE if the version of the libsoup header files
 * is the same as or newer than the passed-in version.
 *
 * Since: 2.42
 */

/**
 * soup_get_major_version:
 *
 * Returns the major version number of the libsoup library.
 * (e.g. in libsoup version 2.42.0 this is 2.)
 *
 * This function is in the library, so it represents the libsoup library
 * your code is running against. Contrast with the #SOUP_MAJOR_VERSION
 * macro, which represents the major version of the libsoup headers you
 * have included when compiling your code.
 *
 * Returns: the major version number of the libsoup library
 *
 * Since: 2.42
 */
guint
soup_get_major_version (void)
{
    return SOUP_MAJOR_VERSION;
}

/**
 * soup_get_minor_version:
 *
 * Returns the minor version number of the libsoup library.
 * (e.g. in libsoup version 2.42.0 this is 42.)
 *
 * This function is in the library, so it represents the libsoup library
 * your code is running against. Contrast with the #SOUP_MINOR_VERSION
 * macro, which represents the minor version of the libsoup headers you
 * have included when compiling your code.
 *
 * Returns: the minor version number of the libsoup library
 *
 * Since: 2.42
 */
guint
soup_get_minor_version (void)
{
    return SOUP_MINOR_VERSION;
}

/**
 * soup_get_micro_version:
 *
 * Returns the micro version number of the libsoup library.
 * (e.g. in libsoup version 2.42.0 this is 0.)
 *
 * This function is in the library, so it represents the libsoup library
 * your code is running against. Contrast with the #SOUP_MICRO_VERSION
 * macro, which represents the micro version of the libsoup headers you
 * have included when compiling your code.
 *
 * Returns: the micro version number of the libsoup library
 *
 * Since: 2.42
 */
guint
soup_get_micro_version (void)
{
    return SOUP_MICRO_VERSION;
}

/**
 * soup_check_version:
 * @major: the major version to check
 * @minor: the minor version to check
 * @micro: the micro version to check
 *
 * Like SOUP_CHECK_VERSION, but the check for soup_check_version is
 * at runtime instead of compile time. This is useful for compiling
 * against older versions of libsoup, but using features from newer
 * versions.
 *
 * Returns: %TRUE if the version of the libsoup currently loaded
 * is the same as or newer than the passed-in version.
 *
 * Since: 2.42
 */
gboolean
soup_check_version (guint major,
                    guint minor,
                    guint micro)
{
    return SOUP_CHECK_VERSION (major, minor, micro);
}
