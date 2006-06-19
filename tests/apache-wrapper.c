#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_APACHE

#include "apache-wrapper.h"

static gboolean
apache_cmd (char *cmd)
{
	char *argv[8];
	char *cwd, *conf;
	int status;
	gboolean ok;

	cwd = g_get_current_dir ();
	conf = g_build_filename (cwd, "httpd.conf", NULL);

	argv[0] = APACHE_HTTPD;
	argv[1] = "-d";
	argv[2] = cwd;
	argv[3] = "-f";
	argv[4] = conf;
	argv[5] = "-k";
	argv[6] = cmd;
	argv[7] = NULL;

	ok = g_spawn_sync (cwd, argv, NULL, 0, NULL, NULL,
			   NULL, NULL, &status, NULL);
	if (ok)
		ok = (status == 0);

	g_free (cwd);
	g_free (conf);

	return ok;
}

gboolean
apache_init (void)
{
	return apache_cmd ("start");
}

void
apache_cleanup (void)
{
	apache_cmd ("graceful-stop");
}

#endif /* HAVE_APACHE */
