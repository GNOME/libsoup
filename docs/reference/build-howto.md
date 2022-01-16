Title: Building with libsoup
Slug: build-howto

# Building with libsoup

## Buildsystem Integration

Like other GNOME libraries, libsoup uses
`pkg-config` to provide compiler options. The package
name is `libsoup-3.0`. For example if you use Autotools:

```
PKG_CHECK_MODULES(LIBSOUP, [libsoup-3.0])
AC_SUBST(LIBSOUP_CFLAGS)
AC_SUBST(LIBSOUP_LIBS)
```

If you use Meson: 

```
libsoup_dep = dependency('libsoup-3.0')
```
    
## API Availability and Deprecation Warnings

If you want to restrict your program to a particular libsoup version or range of
versions, you can define [const@VERSION_MIN_REQUIRED] and/or
`SOUP_VERSION_MAX_ALLOWED`. For example with Autotools:

```
LIBSOUP_CFLAGS="$LIBSOUP_CFLAGS -DSOUP_VERSION_MIN_REQUIRED=SOUP_VERSION_3_0"
LIBSOUP_CFLAGS="$LIBSOUP_CFLAGS -DSOUP_VERSION_MAX_ALLOWED=SOUP_VERSION_3_2"
```

Or with Meson:

```meson
add_project_arguments(
  '-DSOUP_VERSION_MIN_REQUIRED=SOUP_VERSION_2_99',
  '-DSOUP_VERSION_MAX_ALLOWED=SOUP_VERSION_3_0',
  language: 'c'
)
```
  
The [const@VERSION_MIN_REQUIRED] declaration states that the code is not
expected to compile on versions of libsoup older than the indicated version, and
so the compiler should print warnings if the code uses functions that were
deprecated as of that release.

The `SOUP_VERSION_MAX_ALLOWED` declaration states that the code *is* expected
to compile on versions of libsoup up to the indicated version, and so, when
compiling the program against a newer version than that, the compiler should
print warnings if the code uses functions that did not yet exist in the
max-allowed release.

You can use [func@CHECK_VERSION] to check the version of libsoup at compile
time, to compile different code for different libsoup versions. (If you are
setting [const@VERSION_MIN_REQUIRED] and `SOUP_VERSION_MAX_ALLOWED` to
different versions, as in the example above, then you almost certainly need to
be doing this.)
  
## Headers

Code using libsoup should include the header like so:

```c
#include <libsoup/soup.h>
```
