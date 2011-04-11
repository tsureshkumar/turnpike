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
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>

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
	GnomeTwoPasswordDialog *dialog = NULL;
	char *prompt = NULL;
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
	dialog = GNOME_TWO_PASSWORD_DIALOG (gnome_two_password_dialog_new (_("Authenticate Novell VPN"), 
			prompt, NULL, NULL, FALSE));
	g_free (prompt);

	/* If nothing was found in the keyring, default to not remembering any secrets */
	if (info->user_password || info->cert_password 
			|| ((!info->enc_group_password) && info->group_password) ) {
		/* Otherwise set default remember based on which keyring the secrets were found in */
		if (is_session)
			gnome_two_password_dialog_set_remember (
					dialog,
				   	GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION);
		else
			gnome_two_password_dialog_set_remember (
					dialog,
				   	GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER);
	} else {
		gnome_two_password_dialog_set_remember (
				dialog,
				GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING);
	}

	gnome_two_password_dialog_set_show_username (
			dialog, FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (
			dialog, FALSE);
	gnome_two_password_dialog_set_show_domain (
			dialog, FALSE);
	gnome_two_password_dialog_set_show_remember (
			dialog, TRUE);

	if (info->need_password) {
		gnome_two_password_dialog_set_password_secondary_label (
				dialog, _("_Group Password:"));
		if (NULL != info->group_password) {
			gnome_two_password_dialog_set_password_secondary (
					dialog, 
					info->group_password);
			// don't allow user view and change group password
			if (info->enc_group_password) {
				gnome_two_password_dialog_set_password_secondary_editable(
						dialog, 
						FALSE);
			}
		}
		/* if retrying, put in the passwords from the keyring */
		if (NULL != info->user_password) {
			gnome_two_password_dialog_set_password (
					dialog, info->user_password);
		}
	} else if (info->need_cert_password) {
		gnome_two_password_dialog_set_show_password_secondary (
				dialog, FALSE);
		gnome_two_password_dialog_set_password_primary_label (
				dialog, _("_Cert Password:"));
		if (NULL != info->cert_password) {
			gnome_two_password_dialog_set_password (
					dialog,
					info->cert_password);
		}
	}

	clear_secrets (info);

	gtk_widget_show (GTK_WIDGET (dialog));

	if (gnome_two_password_dialog_run_and_block (dialog))
	{
		const char *keyring = NULL;
		gboolean save = FALSE;

		if (info->need_password) {
			info->user_password = g_strdup (gnome_two_password_dialog_get_password (
						dialog));
			info->group_password = g_strdup (gnome_two_password_dialog_get_password_secondary (
						dialog));
		} else if (info->need_cert_password) {
			info->cert_password = g_strdup (gnome_two_password_dialog_get_password (
						dialog));
		}

		switch (gnome_two_password_dialog_get_remember (dialog))
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

	gtk_widget_destroy (GTK_WIDGET (dialog));

	return result;
}

static void
get_password_types (GHashTable *data, PasswordsInfo *info)
{
	const char *ctype, *val;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	ctype = g_hash_table_lookup (data, NM_NOVELLVPN_KEY_AUTHTYPE);
	g_return_if_fail (ctype != NULL);

	if (!strcmp (ctype, NM_NOVELLVPN_CONTYPE_X509_STRING)) {
		info->need_cert_password = TRUE;
		/* FIXME: Need Cert password for X509 */
		nm_vpn_plugin_utils_get_secret_flags (data, NM_NOVELLVPN_KEY_CERT_PWD, &flags);
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			info->need_cert_password = TRUE;

	} else if (!strcmp (ctype, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)) {
		info->need_password = TRUE;
		/* Need user password for XAUTH */
		nm_vpn_plugin_utils_get_secret_flags (data, NM_NOVELLVPN_KEY_USER_PWD, &flags);
		if (!(flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED))
			info->need_password = TRUE;
	} else {
		g_warning ("Failed to get the auth type!");
	}
}

int 
main (int argc, char *argv[])
{
	gboolean retry = FALSE;
	gchar *vpn_name = NULL;
	gchar *vpn_uuid = NULL;
	gchar *vpn_service = NULL;
	GHashTable *data = NULL, *secrets = NULL;
	GOptionContext *context = NULL;
	int how_many_passwords = 0;
	PasswordsInfo info;
	gboolean result = FALSE;
	int exit_status = 1;

	GOptionEntry entries[] = 
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

	gtk_init (&argc, &argv);

	context = g_option_context_new ("- nvpn auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

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

	if (!nm_vpn_plugin_utils_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n",
				vpn_name, vpn_uuid);
		return 1;
	}

	memset (&info, 0, sizeof (PasswordsInfo));
	info.vpn_uuid = vpn_uuid;
	info.vpn_name = vpn_name;

	get_password_types (data, &info);
	if (!info.need_password && !info.need_cert_password) {
		//printf ("%s\n%s\n\n\n", NM_OPENVPN_KEY_NOSECRET, "true");
		return 0;
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

	// FIXME:
	// Why crash when free context?
	//if (context)
	//	g_option_context_free (context);

	return exit_status;
}
