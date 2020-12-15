#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
    GBytes *bytes;
    char *data_uri;

    fuzz_set_logging_func ();

    data_uri = g_strdup_printf ("data:%.*s", (int)size, data);
    // g_print("%s", data_uri);
    bytes = soup_uri_decode_data_uri (data_uri, NULL);

    g_clear_pointer (&bytes, g_bytes_unref);
    g_free (data_uri);

    return 0;
}