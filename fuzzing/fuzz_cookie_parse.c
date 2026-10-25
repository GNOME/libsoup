#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
    fuzz_set_logging_func ();

    char *str = g_strndup ((const char*)data, size);
    SoupCookie *cookie = soup_cookie_parse (str, NULL);

    g_clear_pointer (&cookie, soup_cookie_free);
    g_free (str);

    return 0;
}