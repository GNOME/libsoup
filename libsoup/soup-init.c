/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-session.c
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include "gconstructor.h"

#ifdef G_OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

HMODULE soup_dll;
#else
#include <dlfcn.h>
#endif

static gboolean
soup2_is_loaded (void)
{
	gboolean result = FALSE;

	/* Skip on PE/COFF, as it doesn't have a flat symbol namespace */
#ifndef G_OS_WIN32
	gpointer handle;
	gpointer func;

	handle = dlopen (NULL, RTLD_LAZY | RTLD_GLOBAL);
	if (handle != NULL) {
		func = dlsym (handle, "soup_uri_new");
		result = (func != NULL);
		dlclose (handle);
	}
#endif
	return result;
}

static void
soup_init (void)
{
#ifdef G_OS_WIN32
	char *basedir = g_win32_get_package_installation_directory_of_module (soup_dll);
	char *localedir = g_build_filename (basedir, "share", "locale", NULL);
	bindtextdomain (GETTEXT_PACKAGE, localedir);
	g_free (localedir);
	g_free (basedir);
#else
	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
#endif
#ifdef HAVE_BIND_TEXTDOMAIN_CODESET
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
#endif

        if (soup2_is_loaded ())
                g_error ("libsoup2 symbols detected. Using libsoup2 and libsoup3 in the same process is not supported.");
}

#if defined (G_OS_WIN32)

BOOL WINAPI DllMain (HINSTANCE hinstDLL,
                     DWORD     fdwReason,
                     LPVOID    lpvReserved);

BOOL WINAPI
DllMain (HINSTANCE hinstDLL,
         DWORD     fdwReason,
         LPVOID    lpvReserved)
{
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		soup_dll = hinstDLL;

		soup_init ();
		break;

	case DLL_THREAD_DETACH:

	default:
		/* do nothing */
		;
	}

	return TRUE;
}

#elif defined (G_HAS_CONSTRUCTORS)

#ifdef G_DEFINE_CONSTRUCTOR_NEEDS_PRAGMA
#pragma G_DEFINE_CONSTRUCTOR_PRAGMA_ARGS(soup_init_ctor)
#endif
G_DEFINE_CONSTRUCTOR(soup_init_ctor)

static void
soup_init_ctor (void)
{
	soup_init ();
}

#else
# error Your platform/compiler is missing constructor support
#endif
