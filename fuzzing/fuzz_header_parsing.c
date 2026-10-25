#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
        GHashTable *elements;
        char *str;

        fuzz_set_logging_func ();

        str = g_strndup ((const char*)data, size);
        elements = soup_header_parse_param_list(str);

        g_hash_table_unref(elements);
        g_free (str);

        return 0;
}