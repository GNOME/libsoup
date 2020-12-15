#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
    // We only accept NUL terminated strings
    if (!size || data[size - 1] != '\0')
        return 0;

    fuzz_set_logging_func ();

    SoupCookie *cookie = soup_cookie_parse ((char*)data, NULL);

    g_clear_pointer (&cookie, soup_cookie_free);

    return 0;
}