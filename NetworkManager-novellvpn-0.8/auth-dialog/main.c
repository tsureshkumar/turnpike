/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Authors:
 *          R Vinay <rvinay@novell.com>
 *
 * Based on work by
 *        Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <libgnomeui/libgnomeui.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <gconf/gconf-client.h>

#include "gnome-two-password-dialog.h"
#include "profile.h"

#include "src/nm-novellvpn-service.h"
#include "common-gnome/keyring-helpers.h"

#define NO_CERTIFICATE_PASSWORD 1
#define NO_GROUP_PASSWORD	2
#define NO_USER_PASSWORD	4

#define KEYRING_IS_SESSION  1
#define KEYRING_IS_FOREVER  2

#define GCONF_PATH_NM_CONNECTIONS "/system/networking/connections"

// password related 
typedef struct {
	char *vpn_uuid;
	char *vpn_name;

	gboolean need_password;
	char *user_password;
	char *group_password;
	gboolean enc_group_password;  // When it's TRUE, the group password was encrypt

	gboolean need_cert_password;
	char *cert_password;

} PasswordsInfo;

static void
clear_secrets (PasswordsInfo *info)
{
	if (info->user_password) {
		memset (info->user_password, 0, strlen (info->user_password));
		g_free (info->user_password);
	}
	if (info->group_password) {
		memset (info->group_password, 0, strlen (info->group_password));
		g_free (info->group_password);
	}
}

static gboolean
get_passwords (PasswordsInfo *info, gboolean retry)
{
	char *prompt = NULL;
	GtkWidget *dialog = NULL;
	gboolean is_session = FALSE;
	gboolean result = FALSE; 
	gboolean need_secret = FALSE;

	g_return_val_if_fail (info != NULL, FALSE);
	g_return_val_if_fail (info->vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (info->vpn_name != NULL, FALSE);

	if (info->need_password) {
		info->user_password = keyring_helpers_lookup_secret (
				info->vpn_uuid,
			   	NM_NOVELLVPN_KEY_USER_PWD,
			   	&is_session);

		// get unencrypt group password first
		info->group_password = keyring_helpers_lookup_secret (
				info->vpn_uuid,
			   	NM_NOVELLVPN_KEY_GRP_PWD,
			   	&is_session);

		if (NULL == info->group_password) {
			// get the group encrypt password
			// after get unencryp group password failed.
			info->group_password = keyring_helpers_lookup_secret (
					info->vpn_uuid,
					NM_NOVELLVPN_KEY_ENC_GRP_PWD,
					&is_session);
			if (NULL == info->group_password) {
				// get the group password from user's profile
				// after getting group password failed.
				const char *grppassword = NULL;

				grppassword = check_for_group_password_in_profile(info->vpn_uuid);
				if (grppassword) {
					info->group_password = g_strdup_printf ("%s", grppassword);
					info->enc_group_password = TRUE;
				}
			} else {
				info->enc_group_password = TRUE;
			}
		}

		if ((NULL == info->user_password)
				|| (NULL == info->group_password))
			need_secret = TRUE;
	} else if (info->need_cert_password) {
		info->cert_password = keyring_helpers_lookup_secret (
				info->vpn_uuid,
				NM_NOVELLVPN_KEY_CERT_PWD,
				&is_session);
		if (NULL == info->cert_password)
			need_secret = TRUE;
	}

	/* Have all passwords and we're not supposed to ask the user again */
	if (!need_secret && !retry)
		return TRUE;

	prompt = g_strdup_printf (_("You need to authenticate to access the Novell's  Virtual Private Network '%s'."),
		   	info->vpn_name);
	dialog = gnome_two_password_dialog_new (_("Authenticate Novell VPN"), 
			prompt, NULL, NULL, FALSE);
	g_free (prompt);

	/* If nothing was found in the keyring, default to not remembering any secrets */
	if (info->user_password || info->cert_password 
			|| ((!info->enc_group_password) && info->group_password) ) {
		/* Otherwise set default remember based on which keyring the secrets were found in */
		if (is_session)
			gnome_two_password_dialog_set_remember (
					GNOME_TWO_PASSWORD_DIALOG (dialog),
				   	GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION);
		else
			gnome_two_password_dialog_set_remember (
					GNOME_TWO_PASSWORD_DIALOG (dialog),
				   	GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER);
	} else {
		gnome_two_password_dialog_set_remember (
				GNOME_TWO_PASSWORD_DIALOG (dialog),
				GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING);
	}

	gnome_two_password_dialog_set_show_username (
			GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (
			GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
	gnome_two_password_dialog_set_show_domain (
			GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
	gnome_two_password_dialog_set_show_remember (
			GNOME_TWO_PASSWORD_DIALOG (dialog), TRUE);

	if (info->need_password) {
		gnome_two_password_dialog_set_password_secondary_label (
				GNOME_TWO_PASSWORD_DIALOG (dialog), _("_Group Password:"));
		if (NULL != info->group_password) {
			gnome_two_password_dialog_set_password_secondary (
					GNOME_TWO_PASSWORD_DIALOG (dialog), 
					info->group_password);
			// don't allow user view and change group password
			if (info->enc_group_password) {
				gnome_two_password_dialog_set_password_secondary_editable(
						GNOME_TWO_PASSWORD_DIALOG (dialog), 
						FALSE);
			}
		}
		/* if retrying, put in the passwords from the keyring */
		if (NULL != info->user_password) {
			gnome_two_password_dialog_set_password (
					GNOME_TWO_PASSWORD_DIALOG (dialog), info->user_password);
		}
	} else if (info->need_cert_password) {
		gnome_two_password_dialog_set_show_password_secondary (
				GNOME_TWO_PASSWORD_DIALOG (dialog), FALSE);
		gnome_two_password_dialog_set_password_primary_label (
				GNOME_TWO_PASSWORD_DIALOG (dialog), _("_Cert Password:"));
		if (NULL != info->cert_password) {
			gnome_two_password_dialog_set_password (
					GNOME_TWO_PASSWORD_DIALOG (dialog),
					info->cert_password);
		}
	}

	clear_secrets (info);

	gtk_widget_show (dialog);

	if (gnome_two_password_dialog_run_and_block (GNOME_TWO_PASSWORD_DIALOG (dialog)))
	{
		const char *keyring = NULL;
		gboolean save = FALSE;

		if (info->need_password) {
			info->user_password = g_strdup (gnome_two_password_dialog_get_password (
						GNOME_TWO_PASSWORD_DIALOG (dialog)));
			info->group_password = g_strdup (gnome_two_password_dialog_get_password_secondary (
						GNOME_TWO_PASSWORD_DIALOG (dialog)));
		} else if (info->need_cert_password) {
			info->cert_password = g_strdup (gnome_two_password_dialog_get_password (
						GNOME_TWO_PASSWORD_DIALOG (dialog)));
		}

		switch (gnome_two_password_dialog_get_remember (GNOME_TWO_PASSWORD_DIALOG (dialog)))
		{
			case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION:
				keyring = "session";
				/* Fall through */
			case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
				save = TRUE;
				break;
			default:
				break;
		}

		if (save) {
			if (info->user_password) {
				keyring_helpers_save_secret (info->vpn_uuid, info->vpn_name,
						keyring, NM_NOVELLVPN_KEY_USER_PWD, info->user_password);
			}
			if (info->group_password) {
				if (info->enc_group_password) {
					keyring_helpers_save_secret (info->vpn_uuid, info->vpn_name,
							keyring, NM_NOVELLVPN_KEY_ENC_GRP_PWD, info->group_password);
				} else {
					keyring_helpers_save_secret (info->vpn_uuid, info->vpn_name,
							keyring, NM_NOVELLVPN_KEY_GRP_PWD, info->group_password);
				}
			}
			if (info->cert_password) {
				keyring_helpers_save_secret (info->vpn_uuid, info->vpn_name,
						keyring, NM_NOVELLVPN_KEY_CERT_PWD, info->cert_password);
			}
		}

		result = TRUE;
	}

	gtk_widget_destroy (dialog);

	return result;
}

static gboolean
get_password_types (PasswordsInfo *info)
{
	GConfClient *gconf_client = NULL;
	GSList *conf_list = NULL;
	GSList *iter = NULL;
	char *key = NULL;
	char *val = NULL;
	char *connection_path = NULL;

	gconf_client = gconf_client_get_default();

	/* FIXME: This whole thing sucks: we should not go around poking gconf
	 *        directly, but there's nothing that does it for us right now */

	/* Lists the subdirectories in GCONF_PATH_NM_CONNECTIONS,
	 * The returned list contains allocated strings, so need to free */
	conf_list = gconf_client_all_dirs (gconf_client,
			GCONF_PATH_NM_CONNECTIONS, NULL);
	if (NULL == conf_list) {
		return FALSE;
	}

	/* found the vpn connection dir, 'type' should be vpn, and 
	 * also 'id' should be the VPN_Name */
	for ( iter = conf_list; iter ; iter = iter->next) {
		const char *path = (const char *) iter->data;

		key = g_strdup_printf ("%s/%s/%s", path,
				NM_SETTING_CONNECTION_SETTING_NAME,
				NM_SETTING_CONNECTION_TYPE);
		val = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (NULL == val || 0 != strcmp (val, "vpn")) {
			g_free (val);
			continue;
		}
		/* need free? */
		g_free (val);

		key = g_strdup_printf ("%s/%s/%s", path,
				NM_SETTING_CONNECTION_SETTING_NAME,
				NM_SETTING_CONNECTION_UUID);
		val = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (NULL == val || 0 != strcmp (val, info->vpn_uuid)) {
			g_free (val);
			continue;
		}
		/* need free? */
		g_free (val);

		/* Woo, found the connection */
		connection_path = g_strdup ((char *) iter->data);
		break;
	}

	/* g_free() each string in the list, then g_slist_free() the list itself */
	g_slist_foreach (conf_list, (GFunc) g_free, NULL);
	g_slist_free (conf_list);

	if (NULL != connection_path) {
		key = g_strdup_printf ("%s/%s/%s",
				connection_path,
				NM_SETTING_VPN_SETTING_NAME,
				NM_NOVELLVPN_KEY_AUTHTYPE);
		val = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (NULL != val) {
			if (0 == strcmp (val, NM_NOVELLVPN_CONTYPE_X509_STRING)) {
				info->need_cert_password = TRUE;
			} else if (0 == strcmp (val, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)) {
				info->need_password = TRUE;
			} 
		}
		g_free (val);
		
		g_free (connection_path);
	} else {
		g_object_unref (gconf_client);
		return FALSE;
	}

	g_object_unref (gconf_client);

	return TRUE;
}

int 
main (int argc, char *argv[])
{
	static gboolean retry = FALSE;
	static gchar *vpn_name = NULL;
	static gchar *vpn_uuid = NULL;
	static gchar *vpn_service = NULL;
	GOptionContext *context = NULL;
	GnomeProgram *program = NULL;
	int how_many_passwords = 0;
	PasswordsInfo info;
	gboolean result = FALSE;
	int exit_status = 1;

	static GOptionEntry entries[] = 
	{
		{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
		{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
		{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
		{ "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
		{ NULL }
	};
	char buf[1];

	bindtextdomain (GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	context = g_option_context_new ("- nvpn auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

	program = gnome_program_init ("nm-novellvpn-auth-dialog",
		   	VERSION, LIBGNOMEUI_MODULE,
			argc, argv, 
			GNOME_PARAM_GOPTION_CONTEXT, context,
			GNOME_PARAM_NONE);

	if (vpn_uuid == NULL || vpn_name == NULL || vpn_service == NULL) {
		fprintf (stderr, "Have to supply UUID, name and service\n");
		goto out;
	}

	if (strcmp (vpn_service, NM_DBUS_SERVICE_NOVELLVPN) != 0) {
		fprintf (stderr,
			   	"This dialog only works with the '%s' service\n",
			   	NM_DBUS_SERVICE_NOVELLVPN);
		goto out;
	}

	memset (&info, 0, sizeof (PasswordsInfo));
	info.vpn_uuid = vpn_uuid;
	info.vpn_name = vpn_name;

	if (!get_password_types (&info)) {
		fprintf (stderr, "Invalid connection");
		goto out;
	}

	result = get_passwords (&info, retry);
	if (!result) {
		/* when user click the cancel button, set the return value non zero */
		goto out;
	}

	exit_status = 0;

	/* Detect how many passwords are there */
	if (info.need_cert_password) {
		/* is it the cert password same as the user password */
		if (info.cert_password != NULL) {
			if (strcmp(info.cert_password, "") == 0)
				how_many_passwords = how_many_passwords | NO_CERTIFICATE_PASSWORD;

			/* unenc-cert-password */
			printf("%s\n", NM_NOVELLVPN_KEY_CERT_PWD);
			printf ("%s\n", info.cert_password);
		}

	} else if (info.need_password) {
		if (info.user_password != NULL) {
			if (strcmp(info.user_password, "") == 0) {
				how_many_passwords = how_many_passwords | NO_USER_PASSWORD;
			}
			/* unenc-user-password */
			printf("%s\n", NM_NOVELLVPN_KEY_USER_PWD);
			printf ("%s\n", info.user_password);
		}

		if(info.group_password != NULL) {
			if (strcmp(info.group_password, "") == 0) {
				how_many_passwords = how_many_passwords | NO_GROUP_PASSWORD;
			}

			if (info.enc_group_password) {
				/* enc-group-password */
				printf ("%s\n", NM_NOVELLVPN_KEY_ENC_GRP_PWD);
			} else
				/* unenc-group-password */
				printf ("%s\n", NM_NOVELLVPN_KEY_GRP_PWD);

			printf ("%s\n", info.group_password);
		}
	}

	printf("%s\n", NM_NOVELLVPN_KEY_HOW_MANY_PWD);
	printf("%d\n", how_many_passwords);

	printf ("\n\n");

	clear_secrets (&info);

	/* for good measure, flush stdout since Kansas is going Bye-Bye */
	fflush (stdout);


	/* wait for data on stdin  */
	fread (buf, sizeof (char), sizeof (buf), stdin);

out:
	if (program)
		g_object_unref (program);

	// FIXME:
	// Why crash when free context?
	//if (context)
	//	g_option_context_free (context);

	return exit_status;
}
