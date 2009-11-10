/* nm-novellvpn-vpnui-impl.c : Factory Implementations for configuring 
 *                             NovellVPN connections
 *
 * Copyright (C) 2006 Sureshkumar T <tsureshkumar@novell.com>
 * Based on work by Tim Niemueller <tim@niemueller.de>
 *                  David Zeuthen, <davidz@redhat.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include <string.h>
#include <stdlib.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-ui-interface.h>
#include <nm-setting-connection.h>
#include <nm-setting-vpn.h>
#include <nm-setting-vpn-properties.h>

#include "nm-novellvpn-propertiesui.h"
#include "../src/nm-novellvpn-service.h"
#include "nm-utils.h"

typedef struct _NetworkManagerVpnUIImpl NetworkManagerVpnUIImpl;

struct _NetworkManagerVpnUIImpl {
	NetworkManagerVpnUI parent;

	NovellVPNPropertiesUI *novell_vpn_ui;

	NetworkManagerVpnUIDialogValidityCallback callback;
	gpointer callback_user_data;
	gchar    *last_fc_dir;
};

static gboolean
impl_is_valid (NetworkManagerVpnUI *self)
{
	NetworkManagerVpnUIImpl *impl = NULL;

	g_return_val_if_fail (NULL != self, FALSE);
	
	impl = (NetworkManagerVpnUIImpl *) self->data;
	g_return_val_if_fail (NULL != impl, FALSE);

	return novellvpnui_validate (impl->novell_vpn_ui);
}

static void
open_button_clicked (GtkButton *button, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *)user_data;
	GtkWidget *dialog;
	const char *msg;
	GtkEntry *entry;
	gchar *dir;
	char fileName[200];

	nm_debug("Enter open_button_clicked...");

	if ( button == impl->novell_vpn_ui->w_button_cert ) {
		msg = _("Select certificate to use");
		entry = impl->novell_vpn_ui->w_cert;
	} else {
		return;
	}

	dialog = gtk_file_chooser_dialog_new (msg,
			NULL,
			GTK_FILE_CHOOSER_ACTION_OPEN,
			GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
			GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
			NULL);

	//	if ( impl->last_fc_dir != NULL ) 
	//	{
	//		gtk_file_chooser_set_current_folder (GTK_FILE_CHOOSER (dialog), impl->last_fc_dir);   
	sprintf(fileName, "%s/%s/%s", getenv("HOME"), ".turnpike", "usercerts");	
	gtk_file_chooser_set_current_folder (GTK_FILE_CHOOSER (dialog), fileName);   
	//	}

	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) 
	{
		char * file_name = gtk_file_chooser_get_filename (
				GTK_FILE_CHOOSER (dialog));
		int cert_file_name_length = 0;

		if (NULL != file_name) {
			cert_file_name_length = strlen(file_name);
		}

		dir = gtk_file_chooser_get_current_folder (
				GTK_FILE_CHOOSER (dialog));
		g_free( impl->last_fc_dir );
		impl->last_fc_dir = dir;

		if(( file_name[cert_file_name_length - 1] == 'x')
				&& (file_name[cert_file_name_length - 2] == 'f')
				&& ( file_name[cert_file_name_length - 3] == 'p')
				&& (file_name[cert_file_name_length - 4] == '.'))	 
		{
			gtk_entry_set_text (entry, file_name);
			gtk_widget_destroy (dialog);
		}
		else
		{ 
			GtkWidget*  confirm_dialog;
			gtk_widget_destroy (dialog);
			confirm_dialog = gtk_message_dialog_new (NULL,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_MESSAGE_WARNING,
					GTK_BUTTONS_CLOSE,
					_("Wrong certificate file format"));
			gtk_message_dialog_format_secondary_text (
					GTK_MESSAGE_DIALOG (confirm_dialog),
					"Only .pfx format is supported");
			gtk_dialog_run (GTK_DIALOG (confirm_dialog));
			gtk_widget_destroy (confirm_dialog);
			gtk_entry_set_text (entry, "");
		}
		return;
	}
	gtk_widget_destroy (dialog);
}

static void
gateway_type_changed (GtkComboBox *box, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;
	gint sel = gtk_combo_box_get_active( box );

	nm_debug("Enter gateway_type_changed(%d)...", sel);

	switch ( sel )
   	{
		case NM_NOVELLVPN_GWTYPE_NORTEL:
		{
			gtk_widget_set_sensitive (
				GTK_WIDGET (impl->novell_vpn_ui->w_authtype),
				TRUE); 
			gtk_widget_set_sensitive (
				GTK_WIDGET ( impl->novell_vpn_ui->w_use_routes),
				FALSE); 
			break;
		}
		case NM_NOVELLVPN_GWTYPE_STDGW:		
		{
			gtk_widget_set_sensitive (
				GTK_WIDGET (impl->novell_vpn_ui->w_authtype),
				TRUE); 
			gtk_combo_box_set_active (
				GTK_COMBO_BOX (impl->novell_vpn_ui->w_authtype),
				NM_NOVELLVPN_CONTYPE_X509);
			gtk_widget_set_sensitive (
				GTK_WIDGET (impl->novell_vpn_ui->w_authtype),
				FALSE); 
			gtk_widget_set_sensitive (
				GTK_WIDGET (impl->novell_vpn_ui->w_use_routes),
				TRUE); 
			break;
		}
	}
}

void
auth_type_changed (GtkComboBox *box, gpointer user_data)
{
	int i;
	GtkWidget *tab;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;
	gint sel = gtk_combo_box_get_active( box );

	nm_debug("Enter auth_type_changed(%d)...", sel);

	switch ( sel )
   	{
		case NM_NOVELLVPN_CONTYPE_GROUPAUTH:
		{
			i = 0;
			gtk_notebook_set_current_page(
				   	impl->novell_vpn_ui->w_settings_notebook,
				   	sel );
			tab = GTK_WIDGET (
				   	gtk_notebook_get_nth_page( GTK_NOTEBOOK (
						impl->novell_vpn_ui->w_settings_notebook),
					   	i));
			gtk_widget_set_sensitive( tab, (i == sel));
			gtk_widget_set_sensitive(
			 	GTK_WIDGET ( gtk_notebook_get_tab_label(
				  	GTK_NOTEBOOK (impl->novell_vpn_ui->w_settings_notebook), tab) ),
				(i == sel));
			tab = GTK_WIDGET ( gtk_notebook_get_nth_page(
				   	GTK_NOTEBOOK (impl->novell_vpn_ui->w_settings_notebook), 1));
				gtk_widget_set_sensitive( tab, FALSE);
		}
		break;
		case NM_NOVELLVPN_CONTYPE_X509:
		{
			i = 1;
			gtk_notebook_set_current_page(
				   	impl->novell_vpn_ui->w_settings_notebook, sel );
			tab = GTK_WIDGET ( gtk_notebook_get_nth_page(
				 	GTK_NOTEBOOK (impl->novell_vpn_ui->w_settings_notebook), i));
			gtk_widget_set_sensitive( tab, (i == sel));
			gtk_widget_set_sensitive(
			 	GTK_WIDGET ( gtk_notebook_get_tab_label(
			   	GTK_NOTEBOOK (impl->novell_vpn_ui->w_settings_notebook),
			   	tab) ),
				(i == sel));
			tab = GTK_WIDGET ( gtk_notebook_get_nth_page(
			   	GTK_NOTEBOOK (impl->novell_vpn_ui->w_settings_notebook), 0));
			gtk_widget_set_sensitive( tab, FALSE);
		}
		break;
	}
}

static void
advanced_button_clicked(GtkButton *button, gpointer user_data)
{
	NovellVPNPropertiesUI *self = (NovellVPNPropertiesUI *) user_data;

	nm_debug("Enter advanced_button_clicked...");

	g_assert(self->w_advanced_dialog);

	gtk_dialog_run (self->w_advanced_dialog);
	gtk_widget_hide (GTK_WIDGET(self->w_advanced_dialog));
}

static void
use_routes_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;
	
	nm_debug("Enter use_routes_toggled...");

	gtk_widget_set_sensitive (
			GTK_WIDGET (impl->novell_vpn_ui->w_routes),
			gtk_toggle_button_get_active (togglebutton));
	if (impl->callback != NULL) 
	{
		gboolean is_valid;
		is_valid = impl_is_valid (&(impl->parent));
		impl->callback (&(impl->parent),
			   	is_valid,
			   	impl->callback_user_data);
	}
}


static void 
editable_changed (GtkEditable *editable, gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) user_data;

	//nm_debug("Enter editable_changed...");

	if (impl->callback != NULL)
   	{
		gboolean is_valid;

		is_valid = impl_is_valid (&(impl->parent));
		impl->callback (&(impl->parent),
			   	is_valid,
			   	impl->callback_user_data);
	}
}

static const char *
impl_get_display_name (NetworkManagerVpnUI *self)
{
	nm_debug("Enter impl_get_display_name...");
	return _("NovellVPN Client");
}

static const char *
impl_get_service_name (NetworkManagerVpnUI *self)
{
	nm_debug("Enter impl_get_service_name...");
	return "org.freedesktop.NetworkManager.novellvpn";
}

static GSList *
get_routes (NetworkManagerVpnUIImpl *impl)
{
	GSList *routes = NULL;
	const char *routes_entry = NULL;
	gboolean use_routes;
	char **substrs;
	unsigned int i = 0;

	nm_debug("Enter get_routes...");

	routes_entry = gtk_entry_get_text (impl->novell_vpn_ui->w_routes);
	use_routes = gtk_toggle_button_get_active (
			GTK_TOGGLE_BUTTON (impl->novell_vpn_ui->w_use_routes));

	if (!use_routes)
		goto out;

	substrs = g_strsplit (routes_entry, " ", 0);
	for (i = 0; substrs[i] != NULL; i++) 
	{
		char *route = NULL;

		route = substrs[i];
		if ((NULL != route) && (strlen (route) > 0))
			routes = g_slist_append (routes, g_strdup (route));
	}

	g_strfreev (substrs);

out:
	return routes;
}

static void
impl_fill_connection (NetworkManagerVpnUI *self, NMConnection *connection)
{
	NetworkManagerVpnUIImpl *impl = NULL;
	NMSettingConnection *s_con = NULL;
	NMSettingVPN *s_vpn = NULL;
	NMSettingVPNProperties *s_vpn_props = NULL;
	const char *connection_id = NULL;

	nm_debug("Enter impl_fill_connection...");

	g_return_if_fail (self != NULL);

	impl = (NetworkManagerVpnUIImpl *) self->data;
	g_return_if_fail (impl != NULL);

	s_con = NM_SETTING_CONNECTION (
			nm_connection_get_setting (
				connection, NM_TYPE_SETTING_CONNECTION));
	g_return_if_fail (s_con != NULL);

	s_vpn = NM_SETTING_VPN (
			nm_connection_get_setting (
				connection, NM_TYPE_SETTING_VPN));
	g_return_if_fail (s_vpn != NULL);

	s_vpn_props = NM_SETTING_VPN_PROPERTIES (
			nm_connection_get_setting (
				connection, NM_TYPE_SETTING_VPN_PROPERTIES));
	g_return_if_fail (s_vpn_props != NULL);

	/* Connection name */
	connection_id = gtk_entry_get_text (
			impl->novell_vpn_ui->w_connection_name);
	g_assert (connection_id);
	nm_debug("connection name is %s", connection_id);

	s_con->id = g_strdup (connection_id);

	/* Populate routes */
	if (s_vpn->routes != NULL) {
		/* the s_vpn->routes already exist */
		g_slist_foreach (s_vpn->routes, (GFunc) g_free, NULL);
		g_slist_free (s_vpn->routes);
	}

	s_vpn->routes = get_routes (impl);

	novellvpnui_get_properties(impl->novell_vpn_ui,
			&(s_vpn_props->data));
}

static GtkWidget *
impl_get_widget (NetworkManagerVpnUI *self, NMConnection *connection)
{
	NMSettingConnection *s_con = NULL;
	NMSettingVPN *s_vpn = NULL;
	NMSettingVPNProperties *s_vpn_props = NULL;

	NetworkManagerVpnUIImpl *impl = NULL;
	NovellVPNPropertiesUI *novell_vpn_ui = NULL;
	
	g_return_val_if_fail (NULL != self, NULL);

	impl = (NetworkManagerVpnUIImpl *) self->data;
	g_return_val_if_fail (NULL != impl, NULL);

	novell_vpn_ui = impl->novell_vpn_ui;
	g_return_val_if_fail (NULL != novell_vpn_ui, NULL);

	novellvpnui_clear_widget(novell_vpn_ui);

	if (NULL != connection)
	{
		/* Populate UI bits from the NMConnection */
		s_con = NM_SETTING_CONNECTION (
				nm_connection_get_setting (connection, 
					NM_TYPE_SETTING_CONNECTION));

		g_assert (s_con);
		g_assert (s_con->id);

		novellvpnui_set_connection_name(novell_vpn_ui, s_con->id);

		s_vpn = NM_SETTING_VPN (
				nm_connection_get_setting (connection,
					NM_TYPE_SETTING_VPN));
		g_assert (s_vpn);

		s_vpn_props = NM_SETTING_VPN_PROPERTIES (
				nm_connection_get_setting (connection,
					NM_TYPE_SETTING_VPN_PROPERTIES));
		g_assert (s_vpn_props);
		g_assert (s_vpn_props->data);

		novellvpnui_set_properties(novell_vpn_ui,
				s_vpn->routes,
				s_vpn_props->data);

		gtk_container_resize_children (GTK_CONTAINER (novell_vpn_ui->widget));
	}
	else
	{
		nm_debug ("NMConnection's buffer is null!");
	}

	return novell_vpn_ui->widget;
}

static void 
impl_set_validity_changed_callback (
		NetworkManagerVpnUI *self, 
		NetworkManagerVpnUIDialogValidityCallback callback,
		gpointer user_data)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

	nm_debug("Enter impl_set_validity_changed_callback...");

	impl->callback = callback;
	impl->callback_user_data = user_data;
}

static void
impl_get_confirmation_details (
		NetworkManagerVpnUI *self,
	   	gchar **retval)
{
	GString *buf = NULL;
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;
	NovellVPNPropertiesUI *novell_vpn_ui = impl->novell_vpn_ui;

	nm_debug("Enter impl_get_confirmation_details...");

	// This is risky, should be variable length depending on actual data!
	buf = g_string_sized_new (512);

	g_string_append (buf, _("The following NovellVPN connection will be created:"));
	g_string_append (buf, "\n\n\t");
	g_string_append_printf (buf, _("Name:  %s"), novellvpnui_get_connection_name (novell_vpn_ui));
	g_string_append (buf, "\n\n\t");
	g_string_append (buf, "\n\n");
	g_string_append (buf, _("The connection details can be changed using the \"Edit\" button."));
	g_string_append (buf, "\n");

	*retval = g_string_free (buf, FALSE);

	nm_debug("Exit impl_get_confirmation_details\n%s", *retval);
}


/*static GSList *
impl_get_routes (NetworkManagerVpnUI *self)
{
	NetworkManagerVpnUIImpl *impl = (NetworkManagerVpnUIImpl *) self->data;

	return get_routes (impl);
}*/

static gboolean 
impl_import_file (NetworkManagerVpnUI *self,
		const char *path,
		NMConnection *connection)
{
	nm_debug("Enter impl_import_file...");
	return TRUE;
}

static gboolean 
impl_can_export (NetworkManagerVpnUI *self)
{
	nm_debug("Enter impl_can_export...");
	return FALSE;
}

static gboolean 
impl_export (NetworkManagerVpnUI *self,
		NMConnection *connection)
{
	nm_debug("Enter impl_export...");
	return TRUE;
}

static NetworkManagerVpnUI* 
impl_create_object (void)
{
	NetworkManagerVpnUIImpl *impl = NULL;

	nm_debug ("Enter impl_create_object...");

	impl = g_new0 (NetworkManagerVpnUIImpl, 1);
	g_assert(impl);

	impl->novell_vpn_ui = g_new0 (NovellVPNPropertiesUI, 1);
	g_assert(impl->novell_vpn_ui);

	impl->novell_vpn_ui->editable_changed = editable_changed;
	impl->novell_vpn_ui->editable_changed_user_data = impl;
	impl->novell_vpn_ui->use_routes_toggled = use_routes_toggled;
	impl->novell_vpn_ui->open_button_clicked = open_button_clicked; 
	impl->novell_vpn_ui->gateway_type_changed = gateway_type_changed;
	impl->novell_vpn_ui->auth_type_changed = auth_type_changed;
	impl->novell_vpn_ui->advanced_button_clicked = advanced_button_clicked;

	if (! novellvpnui_init (impl->novell_vpn_ui))
   	{
		g_free (impl->novell_vpn_ui);
		g_free (impl);

		return NULL;
	}

	impl->callback = NULL;
	impl->last_fc_dir = NULL;

	/* override methods, see also
	 * /usr/include/NetworkManager/nm-vpn-ui-interface.h */
	impl->parent.get_display_name = impl_get_display_name;
	impl->parent.get_service_name = impl_get_service_name;
	impl->parent.fill_connection = impl_fill_connection;
	impl->parent.get_widget = impl_get_widget;
	impl->parent.set_validity_changed_callback
	   	= impl_set_validity_changed_callback;
	impl->parent.is_valid = impl_is_valid;
	impl->parent.get_confirmation_details 
		= impl_get_confirmation_details;
	impl->parent.can_export = impl_can_export;
	impl->parent.import_file = impl_import_file;
	impl->parent.export = impl_export;
	impl->parent.data  = impl;

	return &(impl->parent);
}


NetworkManagerVpnUI* 
nm_vpn_properties_factory (void)
{
	nm_debug ("Enter nm_vpn_properties_factory...");

	return impl_create_object();
}
