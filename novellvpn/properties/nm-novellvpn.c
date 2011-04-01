/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * CVSID: $Id: nm-novellvpn.c 3834 2008-07-19 18:02:46Z dcbw $
 *
 * nm-novellvpn.c : GNOME UI dialogs for configuring novellvpn VPN connections
 *
 * Copyright (C) 2008 Bin Li, <bili@novell.com>
 * Copyright (C) 2005 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Based on work by David Zeuthen, <davidz@redhat.com>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <glib/gi18n-lib.h>
#include <string.h>
#include <gtk/gtk.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "src/nm-novellvpn-service.h"
#include "nm-novellvpn.h"
#include "nm-utils.h"
#include "common-gnome/keyring-helpers.h"
#include "import-export.h"

#define NOVELLVPN_PLUGIN_NAME    _("NovellVPN Client")
#define NOVELLVPN_PLUGIN_DESC    _("Compatible with the Nortel's ipsec-based server.")
#define NOVELLVPN_PLUGIN_SERVICE NM_DBUS_SERVICE_NOVELLVPN 

typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

/************** plugin class **************/

static void novellvpn_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NovellvpnPluginUi, novellvpn_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   novellvpn_plugin_ui_interface_init))

/************** UI widget class **************/

static void novellvpn_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NovellvpnPluginUiWidget, novellvpn_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   novellvpn_plugin_ui_widget_interface_init))

#define NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NOVELLVPN_TYPE_PLUGIN_UI_WIDGET, NovellvpnPluginUiWidgetPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;           // Grouping widgets so they request same size
	GtkWindowGroup *window_group;
	gboolean window_added;
	GHashTable *advanced;
} NovellvpnPluginUiWidgetPrivate;


#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

GQuark
novellvpn_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("novellvpn-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
novellvpn_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NOVELLVPN_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The connection was missing invalid. */
			ENUM_ENTRY (NOVELLVPN_PLUGIN_UI_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NOVELLVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NOVELLVPN_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The file to import could not be read. */
			ENUM_ENTRY (NOVELLVPN_PLUGIN_UI_ERROR_FILE_NOT_READABLE, "FileNotReadable"),
			/* The file to import could was not an NovellVPN client file. */
			ENUM_ENTRY (NOVELLVPN_PLUGIN_UI_ERROR_FILE_NOT_NOVELLVPN, "FileNotNovellVPN"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NovellvpnPluginUiError", values);
	}
	return etype;
}

static gboolean
validate_file_chooser (GtkBuilder *builder, const char *name)
{
	GtkWidget *widget = NULL;
	char *str = NULL;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, name));
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!str || !strlen (str))
		return FALSE;

	return TRUE;
}

gboolean
auth_widget_check_validity (GtkBuilder *builder, const char *contype, GError **error)
{
	GtkWidget *widget = NULL;
	const char *str = NULL;

	if (!strcmp (contype, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)) {
		// check the username and groupname when XAUTH
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "username_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
					NOVELLVPN_PLUGIN_UI_ERROR,
					NOVELLVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
					NM_NOVELLVPN_KEY_USER_NAME);
			return FALSE;
		}
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "groupname_entry"));
		str = gtk_entry_get_text (GTK_ENTRY (widget));
		if (!str || !strlen (str)) {
			g_set_error (error,
					NOVELLVPN_PLUGIN_UI_ERROR,
					NOVELLVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
					NM_NOVELLVPN_KEY_GROUP_NAME);
			return FALSE;
		}
	} else if (!strcmp (contype, NM_NOVELLVPN_CONTYPE_X509_STRING)) {
		// check certificated file name when X509
		if (!validate_file_chooser (builder, "certificate_file_chooser")) {
			g_set_error (error,
					NOVELLVPN_PLUGIN_UI_ERROR,
					NOVELLVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
					NM_NOVELLVPN_KEY_CERTIFICATE);
			return FALSE;
		}
	} else {
		// connection type is wrong
		g_assert_not_reached();
	}

	return TRUE;
}

static const char *
get_auth_type (GtkBuilder *glade_builder)
{
	GtkComboBox *combo = NULL;
	GtkTreeModel *model = NULL;
	GtkTreeIter iter;
	const char *auth_type = NULL;

	combo = GTK_COMBO_BOX (GTK_WIDGET (gtk_builder_get_object (glade_builder, "authtype_combo")));
	g_assert (combo);

	model = gtk_combo_box_get_model (combo);
	g_assert (model);

	if (gtk_combo_box_get_active_iter (combo, &iter))
		gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &auth_type, -1);

	return auth_type;
}

static gboolean
check_validity (NovellvpnPluginUiWidget *self, GError **error)
{
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget = NULL;
	const char *str = NULL;
	const char *auth_type = NULL;

	g_debug ("Enter check_validity...");

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
				NOVELLVPN_PLUGIN_UI_ERROR,
				NOVELLVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
				NM_NOVELLVPN_KEY_GATEWAY);
		return FALSE;
	}

	auth_type = get_auth_type (priv->builder);
	if (auth_type) {
		if (!auth_widget_check_validity (priv->builder, auth_type, error))
			return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	// Emitted when the value of a UI widget changes.  May trigger a validity
    // check via update_connection() to write values to the connection 
	g_signal_emit_by_name (NOVELLVPN_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void
gateway_type_changed (GtkWidget *combo, gpointer user_data)
{
	NovellvpnPluginUiWidget *self = (NovellvpnPluginUiWidget *) user_data;
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	gint sel = gtk_combo_box_get_active (GTK_COMBO_BOX (combo));
	GtkWidget *widget = NULL;

	g_debug("Enter gateway_type_changed(%d)...", sel);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "authtype_combo"));
	switch (sel)
	{
		case NM_NOVELLVPN_GWTYPE_NORTEL:
			{
				gtk_widget_set_sensitive (
						GTK_WIDGET (widget),
						TRUE);
				gtk_combo_box_set_active (
						GTK_COMBO_BOX (widget),
						NM_NOVELLVPN_CONTYPE_GROUPAUTH);
				break;
			}
		case NM_NOVELLVPN_GWTYPE_STDGW:
			{
				gtk_widget_set_sensitive (
						GTK_WIDGET (widget),
						TRUE);
				gtk_combo_box_set_active (
						GTK_COMBO_BOX (widget),
						NM_NOVELLVPN_CONTYPE_X509);
				gtk_widget_set_sensitive (
						GTK_WIDGET (widget),
						FALSE);
				break;
			}
	}
}


static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	NovellvpnPluginUiWidget *self = NOVELLVPN_PLUGIN_UI_WIDGET (user_data);
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *auth_notebook = NULL;
	GtkTreeModel *model = NULL;
	GtkTreeIter iter;
	gint new_page = 0;

	auth_notebook = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_notebook"));
	g_assert (auth_notebook);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	g_assert (model);
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter));

	gtk_tree_model_get (model, &iter, COL_AUTH_PAGE, &new_page, -1);
	gtk_notebook_set_current_page (GTK_NOTEBOOK (auth_notebook), new_page);

	stuff_changed_cb (combo, self);
}

/*
 * check the certificate file, when the file is illegal, it's not
 * be seen in the file chooser dialog.
 * if the function return TRUE, the file will be display.
 */
static gboolean
cert_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	char *ext = NULL, *p = NULL;
	struct stat statbuf;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (!p)
		return FALSE;

	// check file extention name
	ext = g_ascii_strdown (p, -1);
	if (!ext)
		return FALSE;
	if (strcmp (ext, ".pem") && strcmp (ext, ".crt") && strcmp (ext, ".key")) {
		g_free (ext);
		return FALSE;
	}
	g_free (ext);

	// Ignore files that are really large(>500K) or null
	if (!stat (filter_info->filename, &statbuf)) {
		if (statbuf.st_size > 500000)
			return FALSE;
		if (statbuf.st_size == 0)
			return FALSE;
	}

	return TRUE;
}

GtkFileFilter *
cert_file_chooser_filter_new (void)
{
	GtkFileFilter *filter = NULL;

	filter = gtk_file_filter_new ();
	gtk_file_filter_add_custom (filter, 
			GTK_FILE_FILTER_FILENAME, 
			cert_default_filter, 
			NULL,
			NULL);
	gtk_file_filter_set_name (filter, 
			_("certificates file(*.pem, *.crt, *.key)"));

	return filter;
}


void
x509_init_auth_widget(GtkBuilder *builder,
		GtkSizeGroup *group,
		NMSettingVPN *s_vpn,
		ChangedCallback changed_cb,
		gpointer user_data)
{
	GtkWidget *widget = NULL;
	GtkFileFilter *filter = NULL;
	const char *value = NULL;

	g_debug ("Enter x509_init_auth_widget...");

	g_return_if_fail (builder != NULL);
	g_return_if_fail (group != NULL);
	g_return_if_fail (changed_cb != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "certificate_file_chooser"));
	g_return_if_fail (widget != NULL);

	gtk_size_group_add_widget(group, widget);

	filter = cert_file_chooser_filter_new ();
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
	// set only the files in the local operating system can be selected.
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
			_("Choose a Certificate file..."));
	g_signal_connect (G_OBJECT (widget),
			"selection-changed", 
			G_CALLBACK (changed_cb),
			user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn,
				NM_NOVELLVPN_KEY_CERTIFICATE);
		if (value && strlen (value))
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}
}

void
xauth_init_auth_widget(GtkBuilder *builder,
		GtkSizeGroup *group,
		NMSettingVPN *s_vpn,
		ChangedCallback changed_cb,
		gpointer user_data)
{
	GtkWidget *widget = NULL;
	const char *value = NULL;

	g_debug ("Enter xauth_init_auth_widget...");

	g_return_if_fail (builder != NULL);
	g_return_if_fail (group != NULL);
	g_return_if_fail (changed_cb != NULL);

	// 1. init username entry
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "username_entry"));
	g_return_if_fail (widget != NULL);

	gtk_size_group_add_widget(group, widget);

	// set text for username
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn,
				NM_NOVELLVPN_KEY_USER_NAME);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}

	g_signal_connect (G_OBJECT (widget), "changed", 
			G_CALLBACK (changed_cb), user_data);

	// 2. init groupname entry
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "groupname_entry"));
	g_return_if_fail (widget != NULL);

	gtk_size_group_add_widget(group, widget);

	// set text for groupname
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn,
				NM_NOVELLVPN_KEY_GROUP_NAME);
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}

	g_signal_connect (G_OBJECT (widget), "changed", 
			G_CALLBACK (changed_cb), user_data);
}

static void
show_toggled_cb (GtkCheckButton *button, NovellvpnPluginUiWidget *self)
{
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget = NULL;
	gboolean visible = FALSE;

	visible = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "userpassword_entry"));
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "grouppassword_entry"));
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "certpassword_entry"));
	g_assert (widget);
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

/*
 * Set the value of each item in the new advanced dialog
 */
static GtkWidget *
advanced_dialog_new (GHashTable *hash)
{
	GtkBuilder *builder = NULL;
	GtkWidget *dialog = NULL;
	char *ui_file = NULL;
	GtkWidget *widget = NULL;
	const char *value = NULL;
	GError *error = NULL;

	g_return_val_if_fail (hash != NULL, NULL);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-novellvpn-dialog.ui");
	builder = gtk_builder_new ();

    if (!gtk_builder_add_from_file (builder, ui_file, &error)) {
        g_warning ("Couldn't load builder file: %s", error->message);
        g_error_free (error);
        g_object_unref (G_OBJECT (builder));
        goto out;
    }

	gtk_builder_set_translation_domain (builder, GETTEXT_PACKAGE);

	dialog = GTK_WIDGET (gtk_builder_get_object (builder, "novellvpn-advanced-dialog"));
	if (!dialog) {
		g_debug ("Couldn't found novellvpn-advanced-dialog!");
		g_object_unref (G_OBJECT (builder));
		goto out;
	}

	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_object_set_data_full (G_OBJECT (dialog), "builder",
			builder, (GDestroyNotify) g_object_unref);

	// get DH Group type ComboBox
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "dhgroup_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);

	// set dhgroup
	value = g_hash_table_lookup (hash, NM_NOVELLVPN_KEY_DHGROUP); // "dhgroup"
	g_debug ("Prepare set the dhgroup type...");
	if (value && strlen (value)) {
		long int temp = 0;

		temp = strtol (value, NULL, 10);
		gtk_combo_box_set_active(GTK_COMBO_BOX (widget), (gint) temp);
	} else {
		// init the dhgroup combo box value
		gtk_combo_box_set_active(GTK_COMBO_BOX (widget), 
				DHGROUP_DH1);
	}

	// get PFS Group type ComboBox
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "pfsgroup_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);

	// set pfsgroup
	value = g_hash_table_lookup (hash, NM_NOVELLVPN_KEY_PFSGROUP);
	if (value && strlen (value)) {
		long int temp = 0;

		temp = strtol (value, NULL, 10);
		gtk_combo_box_set_active(GTK_COMBO_BOX (widget), (gint) temp);
	} else {
		// init the pfsgroup combo box value
		gtk_combo_box_set_active(GTK_COMBO_BOX (widget), 
				PFSGROUP_OFF);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "no_split_tunnel_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);

	// set nosplittunnel
	value = g_hash_table_lookup (hash, NM_NOVELLVPN_KEY_NOSPLITTUNNEL);
	if (value && strlen (value) && !strcmp (value, "yes")) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), TRUE);
	} else {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (widget), FALSE);
	}

out:
	g_free (ui_file);

	return dialog;
}

/*
 * Get the every item in the advanced dialog, then add it into hash table.
 */
GHashTable *
advanced_dialog_new_hash_from_dialog (GtkWidget *dialog, GError **error)
{
	GHashTable *hash = NULL;
	GtkWidget *widget = NULL;
	GtkBuilder *builder = NULL;

	g_return_val_if_fail (dialog != NULL, NULL);
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	builder = g_object_get_data (G_OBJECT (dialog), "builder");
	g_return_val_if_fail (builder != NULL, NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "dhgroup_combo"));
	if (widget != NULL) {
		gint dhgroup = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
		g_debug ("dhgroup is %d", dhgroup);
		if ((dhgroup > DHGROUP_INVALID)
				&& (dhgroup <= DHGROUP_DH2)) {

			g_hash_table_insert (hash,
					g_strdup (NM_NOVELLVPN_KEY_DHGROUP),
					g_strdup_printf ("%d", dhgroup));
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "pfsgroup_combo"));
	if (widget != NULL) {
		gint pfsgroup = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
		g_debug ("pfsgroup is %d", pfsgroup);
		if ((pfsgroup > PFSGROUP_INVALID)
				&& (pfsgroup <= PFSGROUP_PFS2)) {

			g_hash_table_insert (hash,
					g_strdup (NM_NOVELLVPN_KEY_PFSGROUP),
					g_strdup_printf ("%d", pfsgroup));
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "no_split_tunnel_checkbutton"));
	if (widget != NULL) {
		gboolean nosplittunnel =
		   	gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (widget));
		g_debug ("nosplittunnel is %d", nosplittunnel);
		if (nosplittunnel) {
			g_hash_table_insert (hash,
				   	g_strdup (NM_NOVELLVPN_KEY_NOSPLITTUNNEL),
				   	g_strdup ("yes"));
		} else {
			g_hash_table_insert (hash,
				   	g_strdup (NM_NOVELLVPN_KEY_NOSPLITTUNNEL),
				   	g_strdup ("no"));
		}
	}
	return hash;
}

static void
advanced_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	gtk_widget_hide (dialog);
	/* gtk_widget_destroy() will remove the window from the window group */
	gtk_widget_destroy (dialog);
}

/*
 * When user click "Ok" or "Cancel" in the advanced dialog, invoke this func.
 */
static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{   
	NovellvpnPluginUiWidget *self = NOVELLVPN_PLUGIN_UI_WIDGET (user_data);
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GError *error = NULL;

	if (response != GTK_RESPONSE_OK) {// "-5"
		advanced_dialog_close_cb (dialog, self);
		return;
	}

	if (priv->advanced)
		g_hash_table_destroy (priv->advanced);

	// retrieve the new value in the advanced dialog, add into hash table.
	priv->advanced = advanced_dialog_new_hash_from_dialog (dialog, &error);
	if (!priv->advanced) {
		g_message ("%s: error reading advanced settings: %s", __func__, error->message);
		g_error_free (error);
	}

	advanced_dialog_close_cb (dialog, self);

	stuff_changed_cb (NULL, self);
}

/*
 * When user click "Advanced..." button, invoke this function
 */
static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	NovellvpnPluginUiWidget *self = NOVELLVPN_PLUGIN_UI_WIDGET (user_data);
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *dialog, *toplevel;

	toplevel = gtk_widget_get_toplevel (priv->widget);
	g_return_if_fail (GTK_WIDGET_TOPLEVEL (toplevel));

	dialog = advanced_dialog_new (priv->advanced);
	if (!dialog) {
		g_warning ("%s: failed to create the Advanced dialog!", __func__);
		return;
	}

	gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
	if (!priv->window_added) {
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (toplevel));
		priv->window_added = TRUE;
	}

	gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (toplevel));

	g_signal_connect (G_OBJECT (dialog), "response",
		   	G_CALLBACK (advanced_dialog_response_cb),
		   	self);
	g_signal_connect (G_OBJECT (dialog), "close",
		   	G_CALLBACK (advanced_dialog_close_cb),
		   	self);

	gtk_widget_show_all (dialog);
}

static GtkWidget *
fill_password (GtkBuilder *builder,
		const char *widget_name,
		NMConnection *connection,
		const char *password_type)
{
	NMSettingVPN *s_vpn = NULL;
	GtkWidget *widget = NULL;
	gchar *keyring_pw = NULL;
	gboolean unused;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));
	g_assert (widget);

	if (!connection)
		return widget;

	/* Grab from the connection first */
	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (s_vpn) {
		const gchar *tmp = NULL;

		tmp = nm_setting_vpn_get_secret (s_vpn, password_type);
		if (tmp) {
			gtk_entry_set_text (GTK_ENTRY (widget), tmp);
			return widget;
		}
	}

	/* If not the connection then from the keyring */
	keyring_pw = keyring_helpers_lookup_secret (nm_connection_get_uuid (connection),
			password_type,
			&unused);
	if (keyring_pw) {
		gtk_entry_set_text (GTK_ENTRY (widget), keyring_pw);
		gnome_keyring_memory_free (keyring_pw);
	}

	return widget;
}

void
fill_vpn_passwords (GtkBuilder *builder,
		GtkSizeGroup *group,
		NMConnection *connection,
		const char *contype,
		ChangedCallback changed_cb,
		gpointer user_data)
{
	GtkWidget *w = NULL;

	g_debug ("enter fill_vpn_passwords(%s)", contype);

	if (!strcmp (contype, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)) {
		GtkWidget *w2 = NULL;

		w = fill_password (builder, "userpassword_entry", connection, NM_NOVELLVPN_KEY_USER_PWD);

		w2 = fill_password (builder, "grouppassword_entry", connection, NM_NOVELLVPN_KEY_GRP_PWD);
		if (w2) {
			gtk_size_group_add_widget (group, w2);
			g_signal_connect (w2, "changed", G_CALLBACK (changed_cb), user_data);
		}
	}
	else if (!strcmp (contype, NM_NOVELLVPN_CONTYPE_X509_STRING))
		w = fill_password (builder, "certpassword_entry", connection, NM_NOVELLVPN_KEY_CERT_PWD);

	if (w) {
		gtk_size_group_add_widget (group, w);
		g_signal_connect (w, "changed", G_CALLBACK (changed_cb), user_data);
	}
}

static gboolean
init_plugin_ui (NovellvpnPluginUiWidget *self, 
		NMConnection *connection, 
		GError **error)
{
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn = NULL;
	GtkWidget *widget = NULL;
	GtkListStore *store = NULL;
	GtkTreeIter iter;
	int active = -1;
	const char *value = NULL;
	const char *contype = NULL;

	g_debug ("Enter init_plugin_ui...");

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	g_return_val_if_fail (s_vpn != NULL, FALSE);
	g_return_val_if_fail (priv != NULL, FALSE);

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);
	g_return_val_if_fail (priv->group != NULL, FALSE);

	// make Gateway entry could resize
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);

	gtk_size_group_add_widget (priv->group, widget);

	if (s_vpn) {
		// set text for Gateway entry 
		value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_GATEWAY); // "remote"
		if (value && strlen (value))
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	// make Gateway type ComboBox could resize
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_type_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);

	gtk_size_group_add_widget (priv->group, widget);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_GWTYPE); // "gateway-type"
		if (value && strlen (value)) {
			long int temp = 0;

			/* Convert -> int and back to string for security's sake since
			 * strtol() ignores some leading and trailing characters.
			 */
			temp = strtol (value, NULL, 10);
			gtk_combo_box_set_active(GTK_COMBO_BOX (widget), (gint) temp);
		} else {
			// set default value
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), NM_NOVELLVPN_GWTYPE_NORTEL);
		}
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (gateway_type_changed), self);

	// make authentication type ComboBox could resize
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "authtype_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);

	gtk_size_group_add_widget (priv->group, widget);

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);
	g_return_val_if_fail (store != NULL, FALSE);

	if (s_vpn) {
		contype = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_AUTHTYPE);
		if (contype && strlen (contype)) {
			if (strcmp (contype, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)
					&& strcmp (contype, NM_NOVELLVPN_CONTYPE_X509_STRING)) {
				contype = NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING;
			}
		} else {
			contype = NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING;
		}
	}

	// XAUTH widget
	xauth_init_auth_widget (priv->builder, priv->group, s_vpn,
			stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
			COL_AUTH_NAME, _("XAUTH"),
			COL_AUTH_PAGE, 0,
			COL_AUTH_TYPE, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING,
			-1);

	// X.509 auth widget */
	x509_init_auth_widget (priv->builder, priv->group, s_vpn,
			stuff_changed_cb, self);

	// just call one time
	fill_vpn_passwords (priv->builder, priv->group, connection,
			contype, stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
			COL_AUTH_NAME, _("X.509"),
			COL_AUTH_PAGE, 1,
			COL_AUTH_TYPE, NM_NOVELLVPN_CONTYPE_X509_STRING,
			-1);
	if ((active < 0) && !strcmp (contype, NM_NOVELLVPN_CONTYPE_X509_STRING))
		active = 1;

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);

	g_signal_connect (widget, "changed", G_CALLBACK (auth_combo_changed_cb), self);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "show_passwords_checkbutton"));
	g_return_val_if_fail (widget != NULL, FALSE);
	g_signal_connect (G_OBJECT (widget), "toggled",
			G_CALLBACK (show_toggled_cb),
			self);

	// connect the advanced button to the advanced dialog
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
	g_return_val_if_fail (widget != NULL, FALSE);

	g_signal_connect (G_OBJECT (widget),
		   	"clicked",
		   	G_CALLBACK (advanced_button_clicked_cb),
		   	self);

	return TRUE;
}

static const char *advanced_keys[] = {
	NM_NOVELLVPN_KEY_DHGROUP,
	NM_NOVELLVPN_KEY_PFSGROUP,
	NM_NOVELLVPN_KEY_NOSPLITTUNNEL,
	NULL
};

static void
copy_values (const char *key, const char *value, gpointer user_data)
{   
	GHashTable *hash = (GHashTable *) user_data;
	const char **i;

	for (i = &advanced_keys[0]; *i; i++) {
		if (strcmp (key, *i))
			continue;

		g_hash_table_insert (hash, g_strdup (key), g_strdup (value));
	}
}

static GHashTable *
advanced_dialog_new_hash_from_connection (
		NMConnection *connection,
		GError **error)
{
	GHashTable *hash = NULL;
	NMSettingVPN *s_vpn = NULL;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
	if (s_vpn == NULL) {
		g_debug ("Get vpn setting failed from connection.");
	}

	// copy each vpn properties from connections into advanced hash
	nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);

	return hash;
}

/*
 * Return the GtkWidget for the VPN's UI
 */
static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	NovellvpnPluginUiWidget *self = NOVELLVPN_PLUGIN_UI_WIDGET (iface);
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	g_debug ("Enter get_widget...");

	return G_OBJECT (priv->widget);
}

static void
update_entry (GtkBuilder *builder,
		const char *key,
		const char *widget_name,
	   	NMSettingVPN *s_vpn)
{
	GtkWidget *widget = NULL;
	const char *str = NULL;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));

	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		nm_setting_vpn_add_data_item (s_vpn, key, str);
	}
}

static void
update_from_filechooser (GtkBuilder *builder,
		const char *key,
		const char *widget_name,
		NMSettingVPN *s_vpn)
{
	GtkWidget *widget = NULL;
	char *filename = NULL;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (key != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));

	filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!filename)
		return;

	if (strlen (filename))
		nm_setting_vpn_add_data_item (s_vpn, key, filename);

	g_free (filename);
}

void
auth_widget_update_connection (GtkBuilder *builder,
		const char *contype,
		NMSettingVPN *s_vpn)
{
	g_return_if_fail (builder != NULL);
	g_return_if_fail (contype != NULL);
	g_return_if_fail (s_vpn != NULL);

	if (!strcmp (contype, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)) {

		nm_setting_vpn_add_data_item (s_vpn, NM_NOVELLVPN_KEY_AUTHTYPE,
				NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING);

		update_entry (builder, NM_NOVELLVPN_KEY_USER_NAME,
				"username_entry", s_vpn);
		update_entry (builder, NM_NOVELLVPN_KEY_GROUP_NAME,
				"groupname_entry", s_vpn);
	} else if (!strcmp (contype, NM_NOVELLVPN_CONTYPE_X509_STRING)) {

		nm_setting_vpn_add_data_item (s_vpn, NM_NOVELLVPN_KEY_AUTHTYPE,
				NM_NOVELLVPN_CONTYPE_X509_STRING);

		update_from_filechooser (builder, NM_NOVELLVPN_KEY_CERTIFICATE,
				"certificate_file_chooser", s_vpn);
	} else {
		g_warning ("Wrong auth-type(%s)!", contype);
		g_assert_not_reached ();
	}
}

static void
hash_copy_advanced (gpointer key, gpointer data, gpointer user_data)
{
	NMSettingVPN *s_vpn = NM_SETTING_VPN (user_data);
	const char *value = (const char *) data;

	nm_setting_vpn_add_data_item (s_vpn, (const char *) key, value);
}

/*
 * Called to save the user-entered options to the connection object.  Should
 * return FALSE and set 'error' if the current options are invalid.  'error'
 * should contain enough information for the plugin to determine which UI
 * widget is invalid at a later point in time.  For example, creating unique
 * error codes for what error occurred and populating the message field
 * of 'error' with the name of the invalid property.
 */
static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	NovellvpnPluginUiWidget *self = NOVELLVPN_PLUGIN_UI_WIDGET (iface);
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn = NULL;
	GtkWidget *widget = NULL;
	char *str = NULL;
	gboolean valid = FALSE;
	const char *auth_type = NULL;
	int gateway_type = NM_NOVELLVPN_GWTYPE_INVALID;

	g_debug ("Enter update_connection...");

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_NOVELLVPN, NULL);

	// Get Gateway
	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str)) {
		nm_setting_vpn_add_data_item (s_vpn, 
				NM_NOVELLVPN_KEY_GATEWAY,
				str);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_type_combo"));
	gateway_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	g_debug ("gateway_type is %d", gateway_type);
	if ((gateway_type > NM_NOVELLVPN_GWTYPE_INVALID)
			&& (gateway_type <= NM_NOVELLVPN_GWTYPE_STDGW)) {

		char *gwtype = NULL;

		switch (gateway_type) {
			case NM_NOVELLVPN_GWTYPE_NORTEL: // 0
				gwtype = NM_NOVELLVPN_GWTYPE_NORTEL_STRING;
				break;
			case NM_NOVELLVPN_GWTYPE_STDGW: // 1
				gwtype = NM_NOVELLVPN_GWTYPE_STDGW_STRING;
				break;
			default:
				g_warning("Wrong gateway-type(%d)!", gateway_type);
		}
		nm_setting_vpn_add_data_item (s_vpn,
				NM_NOVELLVPN_KEY_GWTYPE,
				gwtype);
	}

	auth_type = get_auth_type (priv->builder);
	if (auth_type) {
		auth_widget_update_connection (priv->builder, auth_type, s_vpn);
	}

	// add each vpn properties into connections from advanced hash table
	if (priv->advanced)
		g_hash_table_foreach (priv->advanced, hash_copy_advanced, s_vpn);

	if (!strcmp (auth_type, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)) {
		// User password
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "userpassword_entry"));
		str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_secret (s_vpn, NM_NOVELLVPN_KEY_USER_PWD, str);

		// Group password
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "grouppassword_entry"));
		str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_secret (s_vpn, NM_NOVELLVPN_KEY_GRP_PWD, str);

	} else if (!strcmp (auth_type, NM_NOVELLVPN_CONTYPE_X509_STRING)) {
		// Certificate password
		widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "certpassword_entry"));
		str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
		if (str && strlen (str))
			nm_setting_vpn_add_secret (s_vpn, NM_NOVELLVPN_KEY_CERT_PWD, str);
	} else
		g_assert_not_reached ();

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

static gboolean
save_secret (GtkBuilder *builder,
		const char *widget_name,
		const char *vpn_uuid,
		const char *vpn_name,
		const char *secret_name)
{
	GtkWidget *w = NULL;
	const char *secret = NULL;
	GnomeKeyringResult result;
	gboolean ret = FALSE;

	g_debug ("save_secret(%s, %s, %s, %s)", widget_name,
			vpn_uuid, vpn_name, secret_name);
	w = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));
	g_assert (w);
	secret = gtk_entry_get_text (GTK_ENTRY (w));
	if (secret && strlen (secret)) {
		result = keyring_helpers_save_secret (vpn_uuid, vpn_name, NULL, secret_name, secret);
		// FIXME:
		// why not return by function
		ret = result == GNOME_KEYRING_RESULT_OK;
		if (!ret)
			g_warning ("%s: failed to save user password to keyring.", __func__);
	} else
		ret = keyring_helpers_delete_secret (vpn_uuid, secret_name);

	return ret;
}

gboolean
auth_widget_save_secrets (GtkBuilder *builder,
		const char *contype,
		const char *uuid,
		const char *name)
{   
	gboolean ret = FALSE;

	if (!strcmp (contype, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)) {
		ret = save_secret (builder, "userpassword_entry", uuid, name, NM_NOVELLVPN_KEY_USER_PWD);
		ret = save_secret (builder, "grouppassword_entry", uuid, name, NM_NOVELLVPN_KEY_GRP_PWD);

	} else if (!strcmp (contype, NM_NOVELLVPN_CONTYPE_X509_STRING))
		ret = save_secret (builder, "certpassword_entry", uuid, name, NM_NOVELLVPN_KEY_CERT_PWD);
	else
		g_assert_not_reached ();

	return ret;
}

static gboolean
save_secrets (NMVpnPluginUiWidgetInterface *iface,
              NMConnection *connection,
              GError **error)
{
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (iface);
	NMSettingConnection *s_con = NULL;
	const char *auth_type = NULL;
	gboolean ret = FALSE;

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection,
			NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
				NOVELLVPN_PLUGIN_UI_ERROR,
				NOVELLVPN_PLUGIN_UI_ERROR_INVALID_CONNECTION,
				"%s", "missing 'connection' setting");
		return FALSE;
	}

	auth_type = get_auth_type (priv->builder);
	if (auth_type)
		ret = auth_widget_save_secrets (priv->builder, auth_type,
				nm_setting_connection_get_uuid (s_con),
				nm_setting_connection_get_id (s_con));

	if (!ret)
		g_set_error (error, NOVELLVPN_PLUGIN_UI_ERROR,
				NOVELLVPN_PLUGIN_UI_ERROR_UNKNOWN,
				"%s", "Saving secrets to gnome keyring failed.");
	return ret;
}

/*
 * Return a GObject that implements NMVpnPluginUiWidgetInterface
 */
static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object = NULL;
	NovellvpnPluginUiWidgetPrivate *priv = NULL;
	char *ui_file = NULL;

	g_debug ("Enter nm_vpn_plugin_ui_widget_interface_new...");

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (NOVELLVPN_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, NOVELLVPN_PLUGIN_UI_ERROR, 0, "could not create novellvpn object");
		return NULL;
	}

	priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	ui_file = g_strdup_printf ("%s/%s", UIDIR, "nm-novellvpn-dialog.ui");
	priv->builder = gtk_builder_new ();
	if (!gtk_builder_add_from_file (priv->builder, ui_file, error)) {
		g_warning ("Couldn't load builder file: %s",
				error && *error ? (*error)->message : "(unknown)");
		g_clear_error (error);
		g_set_error (error, NOVELLVPN_PLUGIN_UI_ERROR, 0,
				"could not load required resources from %s", ui_file);
		g_free (ui_file);
		g_object_unref (object);
		return NULL;
	}

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	g_free (ui_file);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "novellvpn-vbox"));
	if (!priv->widget) {
		g_set_error (error, NOVELLVPN_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	if (!init_plugin_ui (NOVELLVPN_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	// get the advanced dialog's variable from connection.
	priv->advanced = advanced_dialog_new_hash_from_connection (connection, error);
	if (!priv->advanced) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	NovellvpnPluginUiWidget *plugin = NOVELLVPN_PLUGIN_UI_WIDGET (object);
	NovellvpnPluginUiWidgetPrivate *priv = NOVELLVPN_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	g_debug ("Enter dispose...");

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->builder)
		g_object_unref (priv->builder);

	if (priv->advanced)
		g_hash_table_destroy (priv->advanced);

	G_OBJECT_CLASS (novellvpn_plugin_ui_widget_parent_class)->dispose (object);
}

static void
novellvpn_plugin_ui_widget_class_init (NovellvpnPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_debug ("Enter novellvpn_plugin_ui_widget_class_init...");

	g_type_class_add_private (req_class, sizeof (NovellvpnPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
novellvpn_plugin_ui_widget_init (NovellvpnPluginUiWidget *plugin)
{
	g_debug ("Enter novellvpn_plugin_ui_widget_init...");
}

static void
novellvpn_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	g_debug ("Enter novellvpn_plugin_ui_widget_interface_init...");
	// interface implementation
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;

	// save VPN-specific connection secrets in a way that the auth-dialog can read them
	iface_class->save_secrets = save_secrets;
}

static gboolean
delete_connection (NMVpnPluginUiInterface *iface,
	   	NMConnection *connection,
	   	GError **error)
{
	NMSettingConnection *s_con = NULL;
	const char *uuid;

	/* Remove any secrets in the keyring associated with this connection's UUID */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection,
			NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
				NOVELLVPN_PLUGIN_UI_ERROR,
				NOVELLVPN_PLUGIN_UI_ERROR_INVALID_CONNECTION,
				"missing 'connection' setting");
		return FALSE;
	}

	uuid = nm_setting_connection_get_uuid (s_con);

	keyring_helpers_delete_secret (uuid, NM_NOVELLVPN_KEY_USER_PWD);
	keyring_helpers_delete_secret (uuid, NM_NOVELLVPN_KEY_GRP_PWD);

	return TRUE;
}

/* 
 * Try to import a connection from the specified path.  On success, return a
 * partial NMConnection object.  On error, return NULL and set 'error' with
 * additional information.  Note that 'error' can be NULL, in which case no
 * additional error information should be provided.
 */
static NMConnection *
import (NMVpnPluginUiInterface *iface, const char *path, GError **error)
{
	NMConnection *connection = NULL;
	char *ext = NULL;

	ext = strrchr (path, '.');
	if (!ext) {
		g_set_error (error,
				NOVELLVPN_PLUGIN_UI_ERROR,
				NOVELLVPN_PLUGIN_UI_ERROR_FILE_NOT_NOVELLVPN,
				"unknown NovellVPN file extension");
		goto out;
	}

	if (strcmp (ext, ".prf")) {
		g_set_error (error,
				NOVELLVPN_PLUGIN_UI_ERROR,
				NOVELLVPN_PLUGIN_UI_ERROR_FILE_NOT_NOVELLVPN,
				"unknown NovellVPN file extension");
		goto out;
	}

	connection = do_import (path, error);

out:
	return connection;
}

/* 
 * Export the given connection to the specified path.  Return TRUE on success.
 * On error, return FALSE and set 'error' with additional error information.
 * Note that 'error' can be NULL, in which case no additional error information
 * should be provided.
 */
static gboolean
export (NMVpnPluginUiInterface *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	return do_export (path, connection, error);
}

/*
 * For a given connection, return a suggested file name.  Returned value should
 * be NULL or a suggested file name allocated via g_malloc/g_new/etc to be freed
 * by the caller.
 */
static char *
get_suggested_name (NMVpnPluginUiInterface *iface, NMConnection *connection)
{
	NMSettingConnection *s_con = NULL;
	const char *id;

	g_debug ("Enter get_suggested_name...");

	g_return_val_if_fail (connection != NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, NULL);

	id = nm_setting_connection_get_id (s_con);
	g_return_val_if_fail (id != NULL, NULL);

	return g_strdup_printf ("profile_%s.prf", id);
}

/* 
 * Plugin's capabiltity function that returns a bitmask of capabilities
 * described by NM_VPN_PLUGIN_UI_CAPABILITY_* defines.
 */
static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	g_debug ("Enter get_capabilities...");

	return (NM_VPN_PLUGIN_UI_CAPABILITY_IMPORT | NM_VPN_PLUGIN_UI_CAPABILITY_EXPORT);
}

/* 
 * Plugin's factory function that returns a GObject that implements
 * NMVpnPluginUiWidgetInterface, pre-filled with values from 'connection'
 * if non-NULL.
 */
static NMVpnPluginUiWidgetInterface *
ui_factory (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error)
{
	g_debug ("Enter ui_factory...");
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	g_debug ("Enter get_property(%d)...", prop_id);

	switch (prop_id) {
		case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME: // 4096
			g_value_set_string (value, NOVELLVPN_PLUGIN_NAME);
			break;
		case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC: // 4097
			g_value_set_string (value, NOVELLVPN_PLUGIN_DESC);
			break;
		case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE: // 4098
			g_value_set_string (value, NOVELLVPN_PLUGIN_SERVICE);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
novellvpn_plugin_ui_class_init (NovellvpnPluginUiClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_debug ("Enter novellvpn_plugin_ui_class_init...");

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
			NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
			NM_VPN_PLUGIN_UI_INTERFACE_NAME);

	g_object_class_override_property (object_class,
			NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
			NM_VPN_PLUGIN_UI_INTERFACE_DESC);

	g_object_class_override_property (object_class,
			NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
			NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void
novellvpn_plugin_ui_init (NovellvpnPluginUi *plugin)
{
	g_debug ("Enter novellvpn_plugin_ui_init...");
}

static void
novellvpn_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
{
	g_debug ("Enter novellvpn_plugin_ui_interface_init...");
	/* interface implementation */
   	// the ui_factory callback return a GObject that implements 
	// NMVpnPluginUiWidgetInterface
	iface_class->ui_factory = ui_factory;
	// the get_capabilities callback return a bitmask of capabilities
	iface_class->get_capabilities = get_capabilities;
	// import callback try to import a connection from the specified path
	iface_class->import_from_file = import;
	// export callback try to export a connection to the specified path
	iface_class->export_to_file = export;
	// get_suggested_name callback return a suggested file name
	// for exporting a given connection
	iface_class->get_suggested_name = get_suggested_name;

	// clear out any VPN-specific secrets or data related to the connection
	iface_class->delete_connection = delete_connection;
}

/*
 * The shared library of NetworkManager's plugin
 * must export the "nm_vpn_plugin_ui_factory" method
 * see also /usr/include/libnm-glib/nm-vpn-plugin-ui-interface.h
 */
G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	g_debug ("Enter nm_vpn_plugin_ui_factory...");
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (NOVELLVPN_TYPE_PLUGIN_UI, NULL));
}
