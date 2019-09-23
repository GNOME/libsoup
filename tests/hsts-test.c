/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2018 Igalia S.L.
 * Copyright (C) 2018 Metrological Group B.V.
 */

#include "test-utils.h"

SoupURI *http_uri;
SoupURI *https_uri;

/* This server pseudo-implements the HSTS spec in order to allow us to
   test the Soup HSTS feature.
 */
static void
server_callback  (SoupServer *server, SoupMessage *msg,
		  const char *path, GHashTable *query,
		  SoupClientContext *context, gpointer data)
{
	const char *server_protocol = data;

	if (strcmp (server_protocol, "http") == 0) {
		if (strcmp (path, "/insecure") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=31536000");
			soup_message_set_status (msg, SOUP_STATUS_OK);
		} else {
			char *uri_string;
			SoupURI *uri = soup_uri_new ("https://localhost");
			soup_uri_set_path (uri, path);
			uri_string = soup_uri_to_string (uri, FALSE);
			soup_message_set_redirect (msg, SOUP_STATUS_MOVED_PERMANENTLY, uri_string);
			soup_uri_free (uri);
			g_free (uri_string);
		}
	} else if (strcmp (server_protocol, "https") == 0) {
		soup_message_set_status (msg, SOUP_STATUS_OK);
		if (strcmp (path, "/long-lasting") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=31536000");
		} else if (strcmp (path, "/two-seconds") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=2");
		} else if (strcmp (path, "/three-seconds") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=3");
		} else if (strcmp (path, "/delete") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=0");
		} else if (strcmp (path, "/subdomains") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=31536000; includeSubDomains");
		} else if (strcmp (path, "/no-sts-header") == 0) {
			/* Do not add anything */
		} else if (strcmp (path, "/multiple-headers") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=31536000; includeSubDomains");
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=1; includeSubDomains");
		} else if (strcmp (path, "/missing-values") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "");
		} else if (strcmp (path, "/invalid-values") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=foo");
		} else if (strcmp (path, "/extra-values-0") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=3600; foo");
		} else if (strcmp (path, "/extra-values-1") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     " max-age=3600; includeDomains; foo");
		} else if (strcmp (path, "/duplicated-directives") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=3600; includeDomains; includeDomains");
		} else if (strcmp (path, "/case-insensitive-header") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "STRICT-TRANSPORT-SECURITY",
						     "max-age=3600");
		} else if (strcmp (path, "/case-insensitive-directives") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "MAX-AGE=3600; includesubdomains");
		} else if (strcmp (path, "/optional-quotations") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=\"31536000\"");
		}
	}
}

static void
session_get_uri (SoupSession *session, const char *uri, SoupStatus expected_status)
{
	SoupMessage *msg;

	msg = soup_message_new ("GET", uri);
	soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, expected_status);
	g_object_unref (msg);
}

/* The HSTS specification does not handle custom ports, so we need to
 * rewrite the URI in the request and add the port where the server is
 * listening before it is sent, to be able to connect to the localhost
 * port where the server is actually running.
 */
static void
rewrite_message_uri (SoupMessage *msg)
{
	if (soup_uri_get_scheme (soup_message_get_uri (msg)) == SOUP_URI_SCHEME_HTTP)
		soup_uri_set_port (soup_message_get_uri (msg), soup_uri_get_port (http_uri));
	else if (soup_uri_get_scheme (soup_message_get_uri (msg)) == SOUP_URI_SCHEME_HTTPS)
		soup_uri_set_port (soup_message_get_uri (msg), soup_uri_get_port (https_uri));
	else
		g_assert_not_reached();
}

static void
on_message_restarted (SoupMessage *msg,
		     gpointer data)
{
	rewrite_message_uri (msg);
}

static void
on_request_queued (SoupSession *session,
		   SoupMessage *msg,
		   gpointer data)
{
	g_signal_connect (msg, "restarted", G_CALLBACK (on_message_restarted), NULL);

	rewrite_message_uri (msg);
}

static SoupSession *
hsts_session_new (SoupHSTSEnforcer *enforcer)
{
	SoupSession *session;

	if (enforcer)
		session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
						 SOUP_SESSION_ADD_FEATURE, enforcer,
						 NULL);
	else
		session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
						 SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_HSTS_ENFORCER,
						 NULL);

	g_signal_connect (session, "request-queued", G_CALLBACK (on_request_queued), NULL);

	return session;
}


static void
do_hsts_basic_test (void)
{
	SoupSession *session = hsts_session_new (NULL);

	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);
	session_get_uri (session, "https://localhost/long-lasting", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);

	/* The HSTS headers in the url above doesn't include
	   subdomains, so the request should ask for the unchanged
	   HTTP address below, to which the server will respond with a
	   moved permanently status. */
	session_get_uri (session, "http://subdomain.localhost", SOUP_STATUS_MOVED_PERMANENTLY);

	soup_test_session_abort_unref (session);
}

static void
do_hsts_expire_test (void)
{
	SoupSession *session = hsts_session_new (NULL);

	session_get_uri (session, "https://localhost/two-seconds", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	/* Wait for the policy to expire. */
	g_usleep (3 * G_USEC_PER_SEC);
	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);

	soup_test_session_abort_unref (session);
}

static void
do_hsts_delete_test (void)
{
	SoupSession *session = hsts_session_new (NULL);

	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);
	session_get_uri (session, "https://localhost/delete", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);

	soup_test_session_abort_unref (session);
}

static void
do_hsts_replace_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/long-lasting", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	session_get_uri (session, "https://localhost/two-seconds", SOUP_STATUS_OK);
	/* Wait for the policy to expire. */
	g_usleep (3 * G_USEC_PER_SEC);
	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);

	soup_test_session_abort_unref (session);
}

static void
do_hsts_update_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/three-seconds", SOUP_STATUS_OK);
	g_usleep (2 * G_USEC_PER_SEC);
	session_get_uri (session, "https://localhost/three-seconds", SOUP_STATUS_OK);
	g_usleep (2 * G_USEC_PER_SEC);

	/* At this point, 4 seconds have elapsed since setting the 3 seconds HSTS
	   rule for the first time, and it should have expired by now, but since it
	   was updated, it should still be valid. */
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_set_and_delete_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/long-lasting", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	session_get_uri (session, "https://localhost/delete", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);

	soup_test_session_abort_unref (session);
}

static void
do_hsts_no_hsts_header_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/long-lasting", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	session_get_uri (session, "https://localhost/no-sts-header", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);

	soup_test_session_abort_unref (session);
}

static void
do_hsts_persistency_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/long-lasting", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);

	session = hsts_session_new (NULL);
	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_subdomains_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/subdomains", SOUP_STATUS_OK);
	/* The enforcer should cause the request to ask for an HTTPS
	   uri, which will fail with an SSL error as there's no server
	   in subdomain.localhost. */
	session_get_uri (session, "http://subdomain.localhost", SOUP_STATUS_SSL_FAILED);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_superdomain_test (void)
{
	SoupHSTSEnforcer *enforcer = soup_hsts_enforcer_new ();
	SoupHSTSPolicy *policy;

	SoupSession *session = hsts_session_new (enforcer);
	/* This adds a long-lasting policy for localhost. */
	session_get_uri (session, "https://localhost/long-lasting", SOUP_STATUS_OK);

	/* We want to set a policy with age = 0 for a subdomain, to test that the
	   superdomain's policy is not removed. We cannot test this with a
	   server, so we just create one by hand and add it to the enforcer. */
	policy = soup_hsts_policy_new ("subdomain.localhost", 0, TRUE);
	soup_hsts_enforcer_set_policy (enforcer, policy);
	soup_hsts_policy_free (policy);

	/* This should work, as we have a long-lasting policy in place. If it fails,
	   the subdomain policy has modified the superdomain's policy, which is wrong. */
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	g_object_unref (enforcer);
}

static void
do_hsts_multiple_headers_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/multiple-headers", SOUP_STATUS_OK);
	g_usleep(2 * G_USEC_PER_SEC);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_insecure_sts_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "http://localhost/insecure", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_missing_values_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/missing-values", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_invalid_values_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/invalid-values", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_extra_values_test (void)
{
	int i;
	for (i = 0; i < 2; i++) {
		SoupSession *session = hsts_session_new (NULL);
		char *uri = g_strdup_printf ("https://localhost/extra-values-%i", i);
		session_get_uri (session, uri, SOUP_STATUS_OK);
		session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
		soup_test_session_abort_unref (session);
		g_free (uri);
	}
}

static void
do_hsts_duplicated_directives_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/duplicated-directives", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_case_insensitive_header_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/case-insensitive-header", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_case_insensitive_directives_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/case-insensitive-directives", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_optional_quotations_test (void)
{
	SoupSession *session = hsts_session_new (NULL);

	session_get_uri (session, "https://localhost/optional-quotations", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);

	soup_test_session_abort_unref (session);
}

static void
do_hsts_ip_address_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://127.0.0.1/basic", SOUP_STATUS_OK);
	session_get_uri (session, "http://127.0.0.1/", SOUP_STATUS_MOVED_PERMANENTLY);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_utf8_address_test (void)
{
	SoupSession *session = hsts_session_new (NULL);
	session_get_uri (session, "https://localhost/subdomains", SOUP_STATUS_OK);
	/* The enforcer should cause the request to ask for an HTTPS
	   uri, which will fail with an SSL error as there's no server
	   in 食狮.中国.localhost. */
	session_get_uri (session, "http://食狮.中国.localhost", SOUP_STATUS_SSL_FAILED);
	soup_test_session_abort_unref (session);
}

static void
do_hsts_session_policy_test (void)
{
	SoupHSTSEnforcer *enforcer = soup_hsts_enforcer_new ();
	SoupSession *session = hsts_session_new (enforcer);

	session_get_uri (session, "http://localhost", SOUP_STATUS_MOVED_PERMANENTLY);
	soup_hsts_enforcer_set_session_policy (enforcer, "localhost", FALSE);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);

	soup_test_session_abort_unref (session);
	g_object_unref (enforcer);
}

static void
on_idna_test_enforcer_changed (SoupHSTSEnforcer *enforcer, SoupHSTSPolicy *old, SoupHSTSPolicy *new, gpointer data)
{
	/* If NULL, then instead of replacing we're adding a new
	 * policy and somewhere we're failing to canonicalize a hostname. */
	g_assert_nonnull (old);
	g_assert_cmpstr (old->domain, ==, new->domain);
	/*  Domains should not have punycoded segments at this point. */
	g_assert_false (g_hostname_is_ascii_encoded (old->domain));
}

static void
do_hsts_idna_addresses_test (void)
{
	SoupHSTSEnforcer *enforcer = soup_hsts_enforcer_new ();

	soup_hsts_enforcer_set_session_policy (enforcer, "áéí.com", FALSE);
	soup_hsts_enforcer_set_session_policy (enforcer, "xn--6scagyk0fc4c.in", FALSE);

	g_assert_true (soup_hsts_enforcer_has_valid_policy (enforcer, "xn--1caqm.com"));

	g_signal_connect (enforcer, "changed", G_CALLBACK (on_idna_test_enforcer_changed), NULL);

	soup_hsts_enforcer_set_session_policy (enforcer, "xn--1caqm.com", TRUE);
	soup_hsts_enforcer_set_session_policy (enforcer, "ನೆನಪಿರಲಿ.in", TRUE);

	g_object_unref (enforcer);
}

static void
do_hsts_get_domains_test (void)
{
	SoupHSTSEnforcer *enforcer = soup_hsts_enforcer_new ();
	SoupHSTSPolicy *policy;
	GList* domains;

	g_assert_null (soup_hsts_enforcer_get_domains (enforcer, TRUE));
	g_assert_null (soup_hsts_enforcer_get_domains (enforcer, FALSE));

	policy = soup_hsts_policy_new ("gnome.org", 3600, FALSE);
	g_assert_nonnull (policy);
	soup_hsts_enforcer_set_policy (enforcer, policy);
	soup_hsts_policy_free (policy);

	policy = soup_hsts_policy_new_session_policy ("freedesktop.org", FALSE);
	g_assert_nonnull (policy);
	soup_hsts_enforcer_set_policy (enforcer, policy);
	soup_hsts_policy_free (policy);

	domains = soup_hsts_enforcer_get_domains (enforcer, TRUE);
	g_assert_nonnull (domains);
	g_assert_cmpint (g_list_length (domains), ==, 2);
	g_list_free_full (domains, (GDestroyNotify)g_free);

	domains = soup_hsts_enforcer_get_domains (enforcer, FALSE);
	g_assert_nonnull (domains);
	g_assert_cmpint (g_list_length (domains), ==, 1);
	g_assert_cmpstr ((char*)domains->data, ==, "gnome.org");
	g_list_free_full (domains, (GDestroyNotify)g_free);

	policy = soup_hsts_policy_new ("gnome.org", SOUP_HSTS_POLICY_MAX_AGE_PAST, FALSE);
	soup_hsts_enforcer_set_policy (enforcer, policy);
	soup_hsts_policy_free (policy);

	domains = soup_hsts_enforcer_get_domains (enforcer, TRUE);
	g_assert_cmpint (g_list_length (domains), ==, 1);
	g_assert_cmpstr ((char*)domains->data, ==, "freedesktop.org");
	g_list_free_full (domains, g_free);
	g_object_unref (enforcer);
}

static void
do_hsts_get_policies_test (void)
{
	SoupHSTSEnforcer *enforcer = soup_hsts_enforcer_new ();
	SoupHSTSPolicy *policy;
	GList* policies;

	g_assert_null (soup_hsts_enforcer_get_policies (enforcer, TRUE));
	g_assert_null (soup_hsts_enforcer_get_policies (enforcer, FALSE));

	policy = soup_hsts_policy_new ("gnome.org", 3600, FALSE);
	g_assert_nonnull (policy);
	soup_hsts_enforcer_set_policy (enforcer, policy);
	soup_hsts_policy_free (policy);

	policy = soup_hsts_policy_new_session_policy ("freedesktop.org", FALSE);
	g_assert_nonnull (policy);
	soup_hsts_enforcer_set_policy (enforcer, policy);
	soup_hsts_policy_free (policy);

	policies = soup_hsts_enforcer_get_policies (enforcer, TRUE);
	g_assert_nonnull (policies);
	g_assert_cmpint (g_list_length (policies), ==, 2);
	g_list_free_full (policies, (GDestroyNotify)soup_hsts_policy_free);

	policies = soup_hsts_enforcer_get_policies (enforcer, FALSE);
	g_assert_nonnull (policies);
	g_assert_cmpint (g_list_length (policies), ==, 1);
	policy = (SoupHSTSPolicy*)policies->data;
	g_assert_cmpstr (policy->domain, ==, "gnome.org");
	g_list_free_full (policies, (GDestroyNotify)soup_hsts_policy_free);

	policy = soup_hsts_policy_new ("gnome.org", SOUP_HSTS_POLICY_MAX_AGE_PAST, FALSE);
	soup_hsts_enforcer_set_policy (enforcer, policy);
	soup_hsts_policy_free (policy);

	policies = soup_hsts_enforcer_get_policies (enforcer, TRUE);
	g_assert_cmpint (g_list_length (policies), ==, 1);
	policy = (SoupHSTSPolicy*)policies->data;
	g_assert_cmpstr (policy->domain, ==, "freedesktop.org");
	g_list_free_full (policies, (GDestroyNotify)soup_hsts_policy_free);
	g_object_unref(enforcer);
}

int
main (int argc, char **argv)
{
	int ret;
	SoupServer *server;
	SoupServer *https_server = NULL;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, "http", NULL);
	http_uri = soup_test_server_get_uri (server, "http", NULL);

	if (tls_available) {
		https_server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
		soup_server_add_handler (https_server, NULL, server_callback, "https", NULL);
		https_uri = soup_test_server_get_uri (https_server, "https", NULL);
	}

	/* The case sensitivity test is run first because soup_message_headers_append()
	   interns the header name and further uses of the name use the interned version.
	   if we ran this test later, then the casing that this tests uses wouldn't be used. */
	g_test_add_func ("/hsts/case-insensitive-header", do_hsts_case_insensitive_header_test);
	g_test_add_func ("/hsts/basic", do_hsts_basic_test);
	g_test_add_func ("/hsts/expire", do_hsts_expire_test);
	g_test_add_func ("/hsts/delete", do_hsts_delete_test);
	g_test_add_func ("/hsts/replace", do_hsts_replace_test);
	g_test_add_func ("/hsts/update", do_hsts_update_test);
	g_test_add_func ("/hsts/set_and_delete", do_hsts_set_and_delete_test);
	g_test_add_func ("/hsts/no_hsts_header", do_hsts_no_hsts_header_test);
	g_test_add_func ("/hsts/persistency", do_hsts_persistency_test);
	g_test_add_func ("/hsts/subdomains", do_hsts_subdomains_test);
	g_test_add_func ("/hsts/superdomain", do_hsts_superdomain_test);
	g_test_add_func ("/hsts/multiple-headers", do_hsts_multiple_headers_test);
	g_test_add_func ("/hsts/insecure-sts", do_hsts_insecure_sts_test);
	g_test_add_func ("/hsts/missing-values", do_hsts_missing_values_test);
	g_test_add_func ("/hsts/invalid-values", do_hsts_invalid_values_test);
	g_test_add_func ("/hsts/extra-values", do_hsts_extra_values_test);
	g_test_add_func ("/hsts/duplicated-directives", do_hsts_duplicated_directives_test);
	g_test_add_func ("/hsts/case-insensitive-directives", do_hsts_case_insensitive_directives_test);
	g_test_add_func ("/hsts/optional-quotations", do_hsts_optional_quotations_test);
	g_test_add_func ("/hsts/ip-address", do_hsts_ip_address_test);
	g_test_add_func ("/hsts/utf8-address", do_hsts_utf8_address_test);
	g_test_add_func ("/hsts/session-policy", do_hsts_session_policy_test);
	g_test_add_func ("/hsts/idna-addresses", do_hsts_idna_addresses_test);
	g_test_add_func ("/hsts/get-domains", do_hsts_get_domains_test);
	g_test_add_func ("/hsts/get-policies", do_hsts_get_policies_test);

	ret = g_test_run ();

	soup_uri_free (http_uri);
	soup_test_server_quit_unref (server);

	if (tls_available) {
		soup_uri_free (https_uri);
		soup_test_server_quit_unref (https_server);
	}

	test_cleanup ();
	return ret;
}
