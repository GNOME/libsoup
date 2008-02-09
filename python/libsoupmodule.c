/* -*- Mode: C; c-basic-offset: 4 -*-
 *
 * libsoupmodule.c: module wrapping libsoup.
 *
 * based off atkmodule.c, Copyright (C) 1998-2003  James Henstridge
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* include this first, before NO_IMPORT_PYGOBJECT is defined */
#include <pygobject.h>

void pylibsoup_register_classes (PyObject *d);
void pylibsoup_add_constants(PyObject *module, const gchar *strip_prefix);
void _pylibsoup_register_boxed_types(void);	

extern PyMethodDef pylibsoup_functions[];

DL_EXPORT(void)
initsoup(void)
{
    PyObject *m, *d;

    init_pygobject ();
    g_thread_init (NULL);

    m = Py_InitModule ("soup", pylibsoup_functions);
    d = PyModule_GetDict (m);
    pylibsoup_register_classes (d);
    pylibsoup_add_constants(m, "SOUP_");
}
