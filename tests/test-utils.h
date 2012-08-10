#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#define LIBSOUP_USE_UNSTABLE_REQUEST_API

#include "libsoup/soup.h"
#include "libsoup/soup-requester.h"
#include "libsoup/soup-request-data.h"
#include "libsoup/soup-request-file.h"
#include "libsoup/soup-request-http.h"

void test_init    (int argc, char **argv, GOptionEntry *entries);
void test_cleanup (void);

extern int debug_level, errors;
extern gboolean parallelize;
extern gboolean expect_warning, tls_available;
void debug_printf (int level, const char *format, ...) G_GNUC_PRINTF (2, 3);

#ifdef HAVE_APACHE
void apache_init    (void);
void apache_cleanup (void);
#endif

SoupSession *soup_test_session_new         (GType type, ...);
void         soup_test_session_abort_unref (SoupSession *session);

SoupServer  *soup_test_server_new        (gboolean in_own_thread);
SoupServer  *soup_test_server_new_ssl    (gboolean in_own_thread);
void         soup_test_server_quit_unref (SoupServer *server);

GInputStream *soup_test_request_send         (SoupRequest   *req,
					      GCancellable  *cancellable,
					      GError       **error);
gboolean      soup_test_request_close_stream (SoupRequest   *req,
					      GInputStream  *stream,
					      GCancellable  *cancellable,
					      GError       **error);
