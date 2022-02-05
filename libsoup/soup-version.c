/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
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
 * SOUP_MAJOR_VERSION:
 *
 * Like [func@get_major_version], but from the headers used at application
 * compile time, rather than from the library linked against at application run
 * time.
 *
 */

/**
 * SOUP_MINOR_VERSION:
 *
 * Like [func@get_minor_version], but from the headers used at
 * application compile time, rather than from the library linked
 * against at application run time.
 *
 */

/**
 * SOUP_MICRO_VERSION:
 *
 * Like [func@get_micro_version], but from the headers used at
 * application compile time, rather than from the library linked
 * against at application run time.
 *
 */

/**
 * SOUP_CHECK_VERSION:
 * @major: major version (e.g. 2 for version 2.42.0)
 * @minor: minor version (e.g. 42 for version 2.42.0)
 * @micro: micro version (e.g. 0 for version 2.42.0)
 *
 * Macro to test the version of libsoup being compiled against.
 *
 * Returns %TRUE if the version of the libsoup header files
 * is the same as or newer than the passed-in version.
 */

/**
 * soup_get_major_version:
 *
 * Returns the major version number of the libsoup library.
 *
 * e.g. in libsoup version 2.42.0 this is 2.
 *
 * This function is in the library, so it represents the libsoup library
 * your code is running against. Contrast with the #SOUP_MAJOR_VERSION
 * macro, which represents the major version of the libsoup headers you
 * have included when compiling your code.
 *
 * Returns: the major version number of the libsoup library
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
 *
 * e.g. in libsoup version 2.42.0 this is 42.
 *
 * This function is in the library, so it represents the libsoup library
 * your code is running against. Contrast with the #SOUP_MINOR_VERSION
 * macro, which represents the minor version of the libsoup headers you
 * have included when compiling your code.
 *
 * Returns: the minor version number of the libsoup library
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
 *
 * e.g. in libsoup version 2.42.0 this is 0.
 *
 * This function is in the library, so it represents the libsoup library
 * your code is running against. Contrast with the #SOUP_MICRO_VERSION
 * macro, which represents the micro version of the libsoup headers you
 * have included when compiling your code.
 *
 * Returns: the micro version number of the libsoup library
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
 * Like [func@CHECK_VERSION], but the check for soup_check_version is
 * at runtime instead of compile time.
 *
 * This is useful for compiling against older versions of libsoup, but using
 * features from newer versions.
 *
 * Returns: %TRUE if the version of the libsoup currently loaded
 *   is the same as or newer than the passed-in version.
 */
gboolean
soup_check_version (guint major,
                    guint minor,
                    guint micro)
{
    return SOUP_CHECK_VERSION (major, (int)minor, micro);
}

/**
 * SOUP_VERSION_MIN_REQUIRED:
 *
 * A macro that should be defined by the user prior to including
 * `libsoup.h`.
 *
 * The definition should be one of the predefined libsoup
 * version macros: %SOUP_VERSION_2_24, %SOUP_VERSION_2_26, ...
 *
 * This macro defines the earliest version of libsoup that the package
 * is required to be able to compile against.
 *
 * If the compiler is configured to warn about the use of deprecated
 * functions, then using functions that were deprecated in version
 * %SOUP_VERSION_MIN_REQUIRED or earlier will cause warnings (but
 * using functions deprecated in later releases will not).
 */

/**
 * SOUP_VERSION_MAX_ALLOWED:
 *
 * A macro that should be defined by the user prior to including
 * libsoup.h.
 *
 * The definition should be one of the predefined libsoup
 * version macros: %SOUP_VERSION_2_24, %SOUP_VERSION_2_26, ...
 *
 * This macro defines the latest version of the libsoup API that the
 * package is allowed to make use of.
 *
 * If the compiler is configured to warn about the use of deprecated
 * functions, then using functions added after version
 * %SOUP_VERSION_MAX_ALLOWED will cause warnings.
 *
 * Unless you are using [func@CHECK_VERSION] or the like to compile
 * different code depending on the libsoup version, then this should be
 * set to the same value as %SOUP_VERSION_MIN_REQUIRED.
 */
