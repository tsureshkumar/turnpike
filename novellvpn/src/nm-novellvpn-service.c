/* nm-novellvpn-service - novellvpn integration with NetworkManager
 *
 * Authors:
 *          Bin Li <bili@novell.com>
 *          Sureshkumar T <tsureshkumar@novell.com>
 * 
 * Based on work by Dan Williams <dcbw@redhat.com>
 *                  Tim Niemueller <tim@niemueller.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * $Id: nm-novellvpn-service.c,v 1.3.2.17 2008/03/31 10:08:36 bili Exp $
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <glib/gprintf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>

#include <NetworkManager.h>
#include <NetworkManagerVPN.h>
#include <nm-setting-vpn.h>
#include "nm-novellvpn-service.h"
#include "nm-utils.h"

#define NO_CERTIFICATE_PASSWORD 1
#define NO_GROUP_PASSWORD	2
#define NO_USER_PASSWORD	4

static const char *dh_group_arg [] = {"dummy_dh", "1", "2" };
static const char *pfs_group_arg [] = {"0", "1", "2" };

#define NM_NOVELLVPN_HELPER_PATH		LIBEXECDIR"/nm-novellvpn-service-novellvpn-helper"

#define BUFF_SIZE        1024

G_DEFINE_TYPE (NMNovellvpnPlugin, nm_novellvpn_plugin, NM_TYPE_VPN_PLUGIN)

/* Add private data into NMNovellvpnPlugin */
#define NM_NOVELLVPN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NOVELLVPN_PLUGIN, NMNovellvpnPluginPrivate))

typedef struct _NmNovellVPN_IOData
{
	gint     child_stdin_fd;
	gint     child_stdout_fd;
	gint     child_stderr_fd;

	gchar    err_string [BUFF_SIZE];

} NmNovellVPN_IOData;

typedef struct _NMNovellvpnPlugin_Private
{
	GMainLoop *loop;
	NMVPNServiceState state;
	GPid pid;
	guint quit_timer;
	guint helper_timer;

	guint connect_timer;
	guint connect_count;

	gint connection_type;
	NmNovellVPN_IOData *io_data;

} NMNovellvpnPluginPrivate;

typedef struct {
	const char *name;
	GType type;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_NOVELLVPN_KEY_GWTYPE,          G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_GATEWAY,         G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_AUTHTYPE,        G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_USER_NAME,       G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_GROUP_NAME,      G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_CERTIFICATE,     G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_DHGROUP,         G_TYPE_INT },
	{ NM_NOVELLVPN_KEY_PFSGROUP,        G_TYPE_INT },
	{ NM_NOVELLVPN_KEY_NAME,            G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_NOSPLITTUNNEL,   G_TYPE_BOOLEAN },
	{ NULL,                             G_TYPE_NONE }
};

static ValidProperty valid_secrets[] = {
	{ NM_NOVELLVPN_KEY_USER_PWD,        G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_ENC_GRP_PWD,     G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_GRP_PWD,         G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_CERT_PWD,        G_TYPE_STRING },
	{ NM_NOVELLVPN_KEY_HOW_MANY_PWD,    G_TYPE_STRING },
	{ NULL,                             G_TYPE_NONE }
};

//static gboolean nm_novellvpn_dbus_handle_stop_vpn (NMNovellvpnPluginPrivate *data);
static void start_racoon (const char * action);

/*
 * Function: nm_novellvpn_helper_timer_cb
 * Description:
 *   If we haven't received the IP4 config info from the helper 
 * before the timeout occurs, we kill novellvpn
 */
static gboolean
nm_novellvpn_helper_timer_cb (NMNovellvpnPluginPrivate *data)
{
	data->helper_timer = 0;

	g_return_val_if_fail (data != NULL, FALSE);

	/* FIXME:
	 * is it NMNovellvpnPlugin ? */
	nm_vpn_plugin_failure (NM_VPN_PLUGIN (data), 
			NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);

	//nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);

	return FALSE;
}


/*
 * Function: nm_novellvpn_schedule_helper_timer
 * Description:
 *   Once novellvpn is running, we wait for the helper to return 
 * the IP4 configuration information to us. If we don't receive 
 * that information within 90 seconds, we kill novellvpn
 */
static void
nm_novellvpn_schedule_helper_timer (NMNovellvpnPluginPrivate *data)
{
	g_return_if_fail (data != NULL);

	if (data->helper_timer == 0) {
		data->helper_timer = g_timeout_add (90000, 
			(GSourceFunc) nm_novellvpn_helper_timer_cb, 
			data);
	}
}


/*
 * nm_novellvpn_cancel_helper_timer
 *
 * Cancel a helper timer that we've scheduled before.
 *
 */
/*static void
nm_novellvpn_cancel_helper_timer (NMNovellvpnPluginPrivate *data)
{
  g_return_if_fail (data != NULL);

  if (data->helper_timer > 0)
    g_source_remove (data->helper_timer);
}*/


/*
 * watch stderr of child proc and store in a buffer
 */
static gboolean
nm_nvpn_watch_stderr_cb (GIOChannel *channel, GIOCondition cond, gpointer user_data)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (user_data);
	NMNovellvpnPluginPrivate *priv = NM_NOVELLVPN_PLUGIN_GET_PRIVATE (plugin);

	g_debug ("Enter nm_nvpn_watch_stderr_cb...");

	if ( (cond & (G_IO_IN | G_IO_PRI))) { // something to read
		NmNovellVPN_IOData *iodata = priv->io_data;
		GIOStatus ret;
		gchar * temp;
		gsize count;
		gint filled_so_far = 0;

		do {
			ret = g_io_channel_read_chars (channel, 
					iodata->err_string + filled_so_far,
					BUFF_SIZE - 1 - filled_so_far, 
					&count, NULL);
			if (count <=0 || ret != G_IO_STATUS_NORMAL)
				break; // no more to read
			iodata->err_string [count] = 0;
			filled_so_far += count;
			temp = g_strrstr (iodata->err_string, "VPNCLIENT-UI");

			// error starts at somewhere in middle
			if (temp != iodata->err_string)
			{
				gchar *p = iodata->err_string, *q = temp;
				// re-arrange string
				filled_so_far = strlen (temp);
				while (*q)
					*p++ = *q++;
			}
		} while (filled_so_far < BUFF_SIZE -1);

		iodata->err_string [filled_so_far] = '\0';
	}

	if ( (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))) // error
		return FALSE;

	return TRUE;
}


/*
 * Function: novellvpn_watch_cb
 * Description:
 *   Watch our child novellvpn process and get notified of events from it.
 */
static void
novellvpn_watch_cb (GPid pid, gint status, gpointer user_data)
{
	guint error = -1;
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (user_data);
	NMNovellvpnPluginPrivate *data = NM_NOVELLVPN_PLUGIN_GET_PRIVATE (plugin);

	g_debug ("Enter novellvpn_watch_cb...");

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			g_warning ("novellvpn exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		g_warning ("novellvpn stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		g_warning ("novellvpn died with signal %d", WTERMSIG (status));
	else
		g_warning ("novellvpn died from an unknown cause");

	/* Reap child if needed. */
	waitpid (data->pid, NULL, WNOHANG);
	data->pid = 0;

	/* Must be after data->state is set since signals use data->state */
	/* This is still code from vpnc, novellvpn does not supply useful exit codes :-/ */
	switch (error)
	{
		case EXIT_FAILURE:	/* Other error (couldn't bind to address, etc) */
			if (data->io_data->err_string [0] != '\0') {
				// FIXME : parse the error to set the right signal
				//nm_novellvpn_dbus_signal_failure_with_msg (data, 
				//		NM_DBUS_VPN_SIGNAL_CONNECT_FAILED,
				//		data->io_data->err_string);
				g_warning ("novellvpn exited with error: %s",
						data->io_data->err_string);
				nm_vpn_plugin_failure (plugin,
					   	NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
			} else {
				nm_vpn_plugin_failure (plugin,
						NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
			}
			break;

		default:
			break;
	}

	g_free (data->io_data);
	data->io_data = NULL;

	nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
}


static const char*
get_connection_type (NMSettingVPN *s_vpn)
{
	const char* ctype = NULL;

	ctype = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_AUTHTYPE);
	if (NULL != ctype) {
		g_debug ("g_value_get_string %s=%s",
				NM_NOVELLVPN_KEY_AUTHTYPE, ctype);

		if (!strcmp (ctype, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)
				|| !strcmp (ctype, NM_NOVELLVPN_CONTYPE_X509_STRING))
			return ctype;
		else
			g_warning ("This connection type not found!");
	} else {
		g_warning ("g_value_get_string %s failed", NM_NOVELLVPN_KEY_AUTHTYPE);
	}

	return NULL;
}

static const char *
nm_find_novellvpn (void)
{   
	static const char *novellvpn_binary_paths[] =
	{
		"/opt/novell/bin/nvpn",
		"/usr/bin/nvpn", 
		NULL
	};

	const char **novellvpn_binary = novellvpn_binary_paths;

	while (*novellvpn_binary != NULL) {
		if (g_file_test (*novellvpn_binary, G_FILE_TEST_EXISTS))
			break;
		novellvpn_binary++;
	}

	return *novellvpn_binary;
}

static void
free_novellvpn_args (GPtrArray *args)
{   
	g_ptr_array_free (args, TRUE);
}

#define NVPN_DEBUG
/*
 * write_config_option
 *
 * Helper that writes a formatted string to an fd
 *
 */
static inline void write_config_option (int fd, const char *format, ...)
{
  char * 	string;
  va_list	args;
  int		x;

  va_start (args, format);
  string = g_strdup_vprintf (format, args);
  x = write (fd, string, strlen (string));
#ifdef NVPN_DEBUG
  fprintf (stdout, string);
#endif
  g_free (string);
  va_end (args);
}


void nm_novellvpn_write_gauth_config (NmNovellVPN_IOData *io_data,
		const char * gateway_type,
		const char * remote,
		const char * user_name,
		const char * user_pwd,
		const char * group_name,
		const char * group_pwd,
		gboolean is_grp_pwd_encrypted)
{
	write_config_option (io_data->child_stdin_fd, 
			"IPSec gateway %s\n", remote);
	write_config_option (io_data->child_stdin_fd, 
			"IPSec gateway type %s\n",  gateway_type);
	write_config_option (io_data->child_stdin_fd, 
			"Authentication type XAUTH\n");
	write_config_option (io_data->child_stdin_fd, 
			"XAuth User %s\n",  user_name );
	write_config_option (io_data->child_stdin_fd, 
			"XAuth Password %s\n",  user_pwd );
	write_config_option (io_data->child_stdin_fd, 
			"IPSec ID %s\n",  group_name );
	write_config_option (io_data->child_stdin_fd, 
			"IPSec Password %s\n",  group_pwd );
	write_config_option (io_data->child_stdin_fd, 
			"IPSec Password EncFlag %d\n\n",
			is_grp_pwd_encrypted ? 1 : 0 );
}


/*
 * nm_novellvpn_groupauth_writeparams
 *
 * write group auth params to fd
 */

static
void nm_novellvpn_write_cert_config (NmNovellVPN_IOData *io_data,
				     const char * gateway_type,
				     const char * remote,
				     const char * certificate,
				     const char * certificate_pwd)


{
  write_config_option (io_data->child_stdin_fd, "IPSec gateway %s\n", remote);
  write_config_option (io_data->child_stdin_fd, "IPSec gateway type %s\n",  gateway_type );
  write_config_option (io_data->child_stdin_fd, "Authentication type X509\n");
  write_config_option (io_data->child_stdin_fd, "Certificate Name %s\n",  certificate );
  write_config_option (io_data->child_stdin_fd, "Certificate Password %s\n",  certificate_pwd );
}


/*
 * add an fd to watch list of main loop
 */
static void
nm_nvpn_watch_fd (int fd, GIOCondition cond, GIOFunc func, gpointer data)
{
	GIOChannel * channel;
	channel = g_io_channel_unix_new (fd);

	// i want binary data
	g_io_channel_set_encoding (channel, NULL, NULL);
	g_io_channel_set_buffered (channel, FALSE);
	g_io_channel_set_flags(channel,     
			g_io_channel_get_flags(channel) | G_IO_FLAG_NONBLOCK,
		   	NULL);

	g_io_add_watch (channel, cond, func, data);

	g_io_channel_unref (channel); // g_io_add_watch has the reference now.

}


/*
 * Function: nm_novellvpn_start_vpn_binary
 * Description:
 *   Start the novellvpn binary with a set of arguments and 
 * a config file.
 */
static gboolean
nm_novellvpn_start_novellvpn_binary (NMNovellvpnPlugin *plugin,
		NMSettingVPN *s_vpn,
		GError **error)
{
	NMNovellvpnPluginPrivate *priv = NM_NOVELLVPN_PLUGIN_GET_PRIVATE(plugin);
	NmNovellVPN_IOData *io_data = priv->io_data;
	GPid pid;
	const char *novellvpn_binary = NULL;
	GPtrArray *novellvpn_argv = NULL;

	gint stdin_fd = -1;
	gint stdout_fd = -1;
	gint stderr_fd = -1;

	const char *user_name = NULL;
	const char *auth_type = NULL;
	const char *gateway_type = NULL;
	const char *group_name = NULL;
	const char *certificate = NULL;
	const char *remote = NULL;
	char *user_pwd = NULL;
	char *group_pwd = NULL;
	char *certificate_pwd = NULL;
	const char *how_many_passwords_str = NULL;

	gint how_many_passwords = 0;
	gboolean is_grp_pwd_encrypted = TRUE;
	const char *dh_group = dh_group_arg [1]; // the default value is 1
	const char *pfs_group = pfs_group_arg [0]; // the default value is 0
	const char *tmp = NULL;
	gboolean no_split_tunnel = FALSE;

	g_return_val_if_fail (plugin != NULL, -1);

	g_debug ("Enter nm_novellvpn_start_novellvpn_binary...");

	priv->pid = 0;

	/* Find novellvpn */
	novellvpn_binary = nm_find_novellvpn ();
	if (NULL == novellvpn_binary) {
		g_set_error (error,
				NM_VPN_PLUGIN_ERROR,
				NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				"%s",
				"Could not find the novellvpn binary.");

		return FALSE;
	} else {
		g_debug ("novellvpn's path is %s", novellvpn_binary);
	}

	/* First check in which mode we are operating.
	 * Get value from hashtable one by one.
	 */
	priv->connection_type = NM_NOVELLVPN_CONTYPE_INVALID;

	/* get gateway-type */
	gateway_type = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_GWTYPE);
	if (!gateway_type || !strlen (gateway_type)) {
		nm_vpn_set_missing_arg_error (error, NM_NOVELLVPN_KEY_GWTYPE);
		return FALSE;
	}

	g_debug("%s = %s!", NM_NOVELLVPN_KEY_GWTYPE, gateway_type);

	/* get gateway's address */
	remote = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_GATEWAY);
	if (!remote || !strlen (remote)) {
		nm_vpn_set_missing_arg_error (error, NM_NOVELLVPN_KEY_GATEWAY);
		return FALSE;
	}

	/* get auth-type */
	auth_type = get_connection_type (s_vpn);
	if (!auth_type || !strlen (auth_type)) {
		nm_vpn_set_missing_arg_error (error, NM_NOVELLVPN_KEY_AUTHTYPE);
		return FALSE;
	}

	if ( !strcmp (auth_type, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)) {
		priv->connection_type = NM_NOVELLVPN_CONTYPE_GROUPAUTH;

		/* get username */
		user_name = nm_setting_vpn_get_data_item (s_vpn,
							  NM_NOVELLVPN_KEY_USER_NAME);
		if ( !user_name || !strlen (user_name)) {
			nm_vpn_set_missing_arg_error (error, NM_NOVELLVPN_KEY_USER_NAME);
			return FALSE;
		}
		/*{
			// FIXME:
			// Need the try the default user_name
			user_name = s_vpn->user_name;

			if ( !user_name || !strlen (user_name)) {
				nm_vpn_set_missing_arg_error (error, NM_NOVELLVPN_KEY_USER_NAME);
				return FALSE;
			}
		}*/

		/* get group-name, it can set to null */
		group_name = nm_setting_vpn_get_data_item (s_vpn,
				NM_NOVELLVPN_KEY_GROUP_NAME);
		if (!group_name || !strlen (group_name)) {
			nm_vpn_set_missing_arg_error (error, NM_NOVELLVPN_KEY_GROUP_NAME);
			return FALSE;
		}

	} else if ( !strcmp (auth_type, NM_NOVELLVPN_CONTYPE_X509_STRING)) {
		priv->connection_type = NM_NOVELLVPN_CONTYPE_X509;

		certificate = nm_setting_vpn_get_data_item (s_vpn,
				NM_NOVELLVPN_KEY_CERTIFICATE);
		if (!certificate || !strlen (certificate)) {
			nm_vpn_set_missing_arg_error (error, NM_NOVELLVPN_KEY_CERTIFICATE);
			return FALSE;
		}
	} else {
		nm_vpn_set_invalid_arg_error (error, NM_NOVELLVPN_KEY_AUTHTYPE, auth_type);
		return FALSE;
	}

	// every gateway has the dhgroup
	// when user don't set the dhgroup, use the default value
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_DHGROUP);
	if (tmp && strlen (tmp)) {
		gint dhgroup = DHGROUP_INVALID;

		dhgroup = (gint) strtol (tmp, NULL, 10);
		if ((dhgroup > DHGROUP_INVALID) && (dhgroup <= DHGROUP_DH2))
			dh_group = dh_group_arg[dhgroup + 1];
		else {
			nm_vpn_set_invalid_arg_error (error, NM_NOVELLVPN_KEY_DHGROUP, tmp);
			return FALSE;
		}
	}

	// every gateway has the pfsgroup
	// when user don't set the pfsgroup, use the default value
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_PFSGROUP);
	if (tmp && strlen (tmp)) {
		gint pfsgroup = PFSGROUP_INVALID;

		pfsgroup = (gint) strtol (tmp, NULL, 10);
		if ((pfsgroup > PFSGROUP_INVALID) && (pfsgroup <= PFSGROUP_PFS2)) {
			pfs_group = pfs_group_arg [pfsgroup];
		} else {
			nm_vpn_set_invalid_arg_error (error, NM_NOVELLVPN_KEY_PFSGROUP, tmp);
			return FALSE;
		}
	} 

	// when user don't set the split_tunnle, use the default value
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_NOSPLITTUNNEL);
	if (tmp && strlen (tmp)) {
		g_debug("%s = %s!", NM_NOVELLVPN_KEY_NOSPLITTUNNEL, tmp);
		if (!strcmp (tmp, "yes")) {
			no_split_tunnel = TRUE;
		} else {
			no_split_tunnel = FALSE;
		}
	}

	if ( priv->connection_type != NM_NOVELLVPN_CONTYPE_INVALID ) {

		novellvpn_argv = g_ptr_array_new ();
		g_return_val_if_fail (NULL != novellvpn_argv, -1);

		/* add vpn program's fullpath and name */
		g_ptr_array_add (novellvpn_argv, (gpointer) (novellvpn_binary));

		/* add the connect parameter */
		g_ptr_array_add (novellvpn_argv, (gpointer) "-c"); 

		/* read input from stdin */
		g_ptr_array_add (novellvpn_argv, (gpointer) "-");

		/* Add global arguments */

		/* Up script, called when connection has been established or
		 * has been restarted */
		g_ptr_array_add (novellvpn_argv, (gpointer) "--up");
		g_ptr_array_add (novellvpn_argv, (gpointer) NM_NOVELLVPN_HELPER_PATH);

		g_ptr_array_add (novellvpn_argv, (gpointer) "-g");
		g_ptr_array_add (novellvpn_argv, (gpointer) dh_group);

		g_ptr_array_add (novellvpn_argv, (gpointer) "-s");
		g_ptr_array_add (novellvpn_argv, (gpointer) pfs_group);

		// disable the split tunnel
		if (no_split_tunnel)
			g_ptr_array_add (novellvpn_argv, (gpointer) "-t");
		//g_ptr_array_add (novellvpn_argv, (gpointer) "-r");

		/* FIXME:
		 * do not let novellvpn setup routes, NM will handle it?
		 */
		/*{
		  char *str = NULL;
		  GString *routes_string = g_string_new ("");
		  g_slist_foreach (routes, getroute_cb, routes_string);

		  str = g_string_free (routes_string, FALSE);

		//routes_string = g_strjoinv (" ", routes);
		g_ptr_array_add (novellvpn_argv, (gpointer) str);
		}*/

		g_ptr_array_add (novellvpn_argv, NULL);

#ifdef NVPN_DEBUG1
		for (i = 0; g_ptr_array_index (novellvpn_argv, i) != NULL; i++)
			printf ("%d %s\n", i, 
					(char *) g_ptr_array_index (novellvpn_argv , i));
#endif // NVPN_DEBUG

		if (!g_spawn_async_with_pipes (
					NULL,                           /* working_directory */
					(char **) novellvpn_argv->pdata, /* argv */
					NULL,                           /* envp */
					G_SPAWN_DO_NOT_REAP_CHILD,      /* flags */
					NULL,                           /* child_setup */
					NULL,                           /* user_data */
					&pid,                           /* child_pid */
					&stdin_fd,                      /* standard_input */
					NULL,                           /* standard_output */
					&stderr_fd,                     /* standard_error */
					error))
		{
			free_novellvpn_args (novellvpn_argv);
			g_warning ("novellvpn failed to start failed! '%s'",
					(*error)->message);

			return FALSE;
		}

		free_novellvpn_args (novellvpn_argv);

		g_message ("novellvpn started with pid %d", pid);

		priv->pid = pid;

		io_data                  = g_new0 (NmNovellVPN_IOData, 1);
		io_data->child_stdin_fd  = stdin_fd;
		io_data->child_stdout_fd = stdout_fd;
		io_data->child_stderr_fd = stderr_fd;
		io_data->err_string [0] = '\0';

		if (priv->io_data)
			g_free (priv->io_data);
		priv->io_data = io_data;

		/* add a watcb cb for stderr so that we can print them */
		nm_nvpn_watch_fd (stderr_fd, 
				G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP | G_IO_NVAL, 
				nm_nvpn_watch_stderr_cb, 
				plugin);

		g_child_watch_add (pid, 
				(GChildWatchFunc) novellvpn_watch_cb, 
				plugin);

		/* dump some other config options to stdin of launched process
		 * GROUPAUTH: Will require username and password and 
		 * group_name & group_password
		 * X.509: Will require username and password and
		 * maybe certificate password
		 */
		if ( (priv->connection_type == NM_NOVELLVPN_CONTYPE_GROUPAUTH) 
				|| (priv->connection_type == NM_NOVELLVPN_CONTYPE_X509)) {
			// setup passwords

			how_many_passwords_str = nm_setting_vpn_get_secret (s_vpn,
					NM_NOVELLVPN_KEY_HOW_MANY_PWD);
			if (how_many_passwords_str && strlen (how_many_passwords_str)) {
				how_many_passwords = atoi(how_many_passwords_str);
			}

			tmp = nm_setting_vpn_get_secret (s_vpn, NM_NOVELLVPN_KEY_USER_PWD);
			if (NULL != tmp) {
				if( (how_many_passwords & NO_USER_PASSWORD) != 0) 
					user_pwd = g_strdup ("");
				else {
					user_pwd = g_strdup (tmp);
				}
			}

			tmp = nm_setting_vpn_get_secret (s_vpn,
					NM_NOVELLVPN_KEY_CERT_PWD);
			if (NULL != tmp) {
				if( (how_many_passwords & NO_CERTIFICATE_PASSWORD) != 0 )
					certificate_pwd = g_strdup("");
				else {
					certificate_pwd = g_strdup (tmp);
				}
			}

			tmp = nm_setting_vpn_get_secret (s_vpn,
					NM_NOVELLVPN_KEY_ENC_GRP_PWD);
			if (NULL != tmp) {
				if( (how_many_passwords & NO_GROUP_PASSWORD) != 0)
					group_pwd = g_strdup("");
				else
					group_pwd = g_strdup (tmp);
				is_grp_pwd_encrypted = TRUE;
			}

			tmp = nm_setting_vpn_get_secret (s_vpn,
					NM_NOVELLVPN_KEY_GRP_PWD);
			if (NULL != tmp) {
				if( (how_many_passwords & NO_GROUP_PASSWORD) != 0)
					group_pwd = g_strdup("");
				else
					group_pwd = g_strdup (tmp);
				is_grp_pwd_encrypted = FALSE;
			}

			switch (priv->connection_type) {
				case NM_NOVELLVPN_CONTYPE_GROUPAUTH:
					nm_novellvpn_write_gauth_config (io_data,
							gateway_type,
							remote,
							user_name,
							user_pwd,
							group_name,
							group_pwd,
							is_grp_pwd_encrypted);
					break;
				case NM_NOVELLVPN_CONTYPE_X509:
					nm_novellvpn_write_cert_config (io_data,
							gateway_type,
							remote,
							certificate,
							certificate_pwd);
					break;
				default:
					g_assert_not_reached();
			}
		}

		nm_novellvpn_schedule_helper_timer (priv);

	} else {
		g_warning("%s is null! Can't connect vpn!",
				NM_NOVELLVPN_KEY_AUTHTYPE);

		return FALSE;
	}
	return TRUE;
}


typedef enum OptType
{
	OPT_TYPE_UNKNOWN = 0,
	OPT_TYPE_ADDRESS,
	OPT_TYPE_ASCII,
	OPT_TYPE_INTEGER,
	OPT_TYPE_NONE
} OptType;

typedef struct Option
{
	const char *name;
	OptType type;
} Option;


NMNovellvpnPluginPrivate *vpn_data = NULL;

/*
 * start racoon daemon if not already started
 */
static void
start_racoon (const char *action)
{
#define RACOON_LAUNCHER_SCRIPT LIBEXECDIR"/nm_novellvpn_racoon_launcher.sh"
	char * cmd = g_strdup_printf ("%s %s", RACOON_LAUNCHER_SCRIPT, action);
	int ret;

	g_message ("launching %s", cmd);
	ret = system (cmd);
	if (ret == -1)
		g_warning ("launching command failed '%s'", cmd);
	g_free (cmd);
}

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *val, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;
	long int tmp = 0;

	if (*info->error) {
		g_warning ("Already failed, return now!");
		return;
	}

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp ( key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];

		if (strcmp (prop.name, key))
			continue;	

		g_debug ("found it, name=%s, val=%s", prop.name, val);

		switch (prop.type) {
			case G_TYPE_STRING:
				if (strlen (val) > 0) {
					/* Property is ok */
					return;
				}
				break;
			case G_TYPE_INT:
				errno = 0; // NOTE: maybe some value infuence errno
				tmp = strtol (val, NULL, 10);
				if (errno == 0 && tmp >= 0) {
					/* Property is ok */
					return;
				}
				g_debug ("property '%s' wrong value, %s", prop.name, strerror (errno));
				break;
			case G_TYPE_BOOLEAN:
				if (!strcmp (val, "yes") || !strcmp (val, "no"))
					return; /* valid */

				g_set_error (info->error,
						NM_VPN_PLUGIN_ERROR,
						NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
						"invalid boolean property '%s' (not yes or no)",
						key);
				break;

			default:
				g_set_error (info->error,
						NM_VPN_PLUGIN_ERROR,
						NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
						"unhandled property '%s' type %s",
						key, g_type_name (prop.type));
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
				NM_VPN_PLUGIN_ERROR,
				NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				"property '%s' invalid or not supported",
				key);
	}
}


static gboolean
nm_novellvpn_properties_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN configuration options.");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}


static gboolean
nm_novellvpn_secrets_validate (NMSettingVPN *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN secrets!");
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}


static gboolean
real_connect (NMVPNPlugin *plugin,
		NMConnection *connection,
		GError **error)
{
	NMSettingVPN *s_vpn = NULL;
	gboolean success = FALSE;

	g_debug ("Enter real_connect...");

	s_vpn = NM_SETTING_VPN (
			nm_connection_get_setting (
				connection, NM_TYPE_SETTING_VPN));
	if (NULL == s_vpn) {
		g_set_error (error,
				NM_VPN_PLUGIN_ERROR,
				NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				"%s",
				"get NMSettingVPN failed!");

		g_warning ("get NMSettingVPN failed!");
		goto out;
	}

	if (!nm_novellvpn_properties_validate (s_vpn, error)) {
		goto out;
	}

	if (!nm_novellvpn_secrets_validate (s_vpn, error)) {
		goto out;
	}

	start_racoon ("up");

	// wait for the racoon finish to start, one second should be enough
	// Bug #308739, novel-vpn fails to start the first time
	// cause the racoon not start yet when nvpn connect racoon.
	sleep(1);

	if (!nm_novellvpn_start_novellvpn_binary (NM_NOVELLVPN_PLUGIN (plugin), s_vpn, error)) {

		g_warning ("Could not start novellvpn binary!");
		goto out;
	}

	success = TRUE;

out:
	/* FIXME: It never did that but I guess it should? */
	/*  close (fd); */

	return success;
}


static gboolean
real_need_secrets (NMVPNPlugin *plugin,
		NMConnection *connection,
		char **setting_name,
		GError **error)
{
	NMSettingVPN *s_vpn = NULL;
	const char* connection_type = NULL;
	gboolean need_secrets = FALSE;

	g_debug("Enter real_need_secrets...");

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (
				connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
				NM_VPN_PLUGIN_ERROR,
				NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
				"%s",
				"Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	connection_type = get_connection_type (s_vpn);
	if (connection_type == NULL) {
		nm_vpn_set_missing_arg_error (error, NM_NOVELLVPN_KEY_AUTHTYPE);
		return FALSE;
	}
	if (!strcmp (connection_type, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)) {
		/* Will require username and password and 
		 * group_name and group_password */
		if (!nm_setting_vpn_get_secret (s_vpn,
					NM_NOVELLVPN_KEY_USER_PWD)) {
			need_secrets = TRUE;
			g_warning ("need secrets!");
		} else  {
			/* Fall through */
			g_warning ("already have %s!", NM_NOVELLVPN_KEY_USER_PWD);
		}
	} else if (!strcmp (connection_type, NM_NOVELLVPN_CONTYPE_X509_STRING)) {
		/* May require certificate password */
		need_secrets = TRUE;
		g_debug ("X509 also need password!");
	}

	if (need_secrets)
		*setting_name = NM_SETTING_VPN_SETTING_NAME;

	return need_secrets;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}


static gboolean
real_disconnect (NMVPNPlugin *plugin, GError **err)
{
	NMNovellvpnPluginPrivate *priv = NM_NOVELLVPN_PLUGIN_GET_PRIVATE (plugin);

	g_debug("Enter real_disconnect...");

	if (priv->pid) {
		//nm_novellvpn_set_state (data, NM_VPN_STATE_STOPPING);

		//kill (priv->pid, SIGINT);
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		g_message ("Terminated novellvpn daemon with PID %d.", priv->pid);
		priv->pid = 0;

		start_racoon ("down");
		//nm_novellvpn_set_state (data, NM_VPN_STATE_STOPPED);
		//nm_novellvpn_schedule_quit_timer (data, 10000);
	}

	return TRUE;
}


static void
nm_novellvpn_plugin_init (NMNovellvpnPlugin *plugin)
{
	g_debug("Enter nm_novellvpn_plugin_init...");
}

static void
nm_novellvpn_plugin_class_init (NMNovellvpnPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (plugin_class);

	g_debug("Enter nm_novellvpn_plugin_class_init...");

	g_type_class_add_private (object_class, sizeof (NMNovellvpnPluginPrivate));

	/* virtual methods */
	parent_class->connect      = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect   = real_disconnect;
}

NMNovellvpnPlugin *
nm_novellvpn_plugin_new (void)
{
	g_debug("Enter nm_novellvpn_plugin_new...");

	return (NMNovellvpnPlugin *) g_object_new (NM_TYPE_NOVELLVPN_PLUGIN,
			NM_VPN_PLUGIN_DBUS_SERVICE_NAME,
			NM_DBUS_SERVICE_NOVELLVPN,
			NULL);
}

static void
quit_mainloop (NMVPNPlugin *plugin, gpointer user_data)
{   
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main( int argc, char *argv[] )
{
	NMNovellvpnPlugin *plugin = NULL;
	GMainLoop *main_loop = NULL;

	g_type_init ();

	plugin = nm_novellvpn_plugin_new ();
	if (NULL == plugin) {
		g_warning("Create new novellvpn_plugin failed!");
		exit (EXIT_FAILURE);
	}

	main_loop = g_main_loop_new (NULL, FALSE);

	g_signal_connect (plugin, "quit",
			G_CALLBACK (quit_mainloop),
			main_loop);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);

	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}
