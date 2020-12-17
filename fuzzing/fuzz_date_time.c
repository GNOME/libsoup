#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
        // We only accept NUL terminated strings
        if (!size || data[size - 1] != '\0')
                return 0;

        fuzz_set_logging_func ();

        GDateTime *dt = soup_date_time_new_from_http_string ((const char*)data);

        g_clear_pointer (&dt, g_date_time_unref);

        return 0;
}