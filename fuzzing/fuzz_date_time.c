#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
        fuzz_set_logging_func ();

        char *str = g_strndup ((const char*)data, size);
        GDateTime *dt = soup_date_time_new_from_http_string (str);

        g_clear_pointer (&dt, g_date_time_unref);
        g_free (str);

        return 0;
}