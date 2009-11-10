/* nm-novellvpn-propertiesui.c : GNOME UI dialogs for configuring NovellVPN connections
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
#include <sys/stat.h>
#include "nm-novellvpn-propertiesui.h"

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <NetworkManager/nm-vpn-ui-interface.h>
#include "../src/nm-novellvpn-service.h"
#include "nm-utils.h"

/* 
   Do not change numbers, only add if needed!
   See properties/nm-novellvpn.c:connection_type_changed() for details
 */

#define DHGROUP1 "dh1"
#define DHGROUP2 "dh2"


static GValue *
str_to_gvalue (const char *str)
{
	GValue *value;

	value = g_slice_new0 (GValue);
	g_value_init (value, G_TYPE_STRING);
	g_value_set_string (value, str);

	return value;
}

static void
load_widgets_and_handlers (NovellVPNPropertiesUI *self,
		const gchar *glade_file ) 
{
	g_assert (self->editable_changed != NULL);
	nm_debug ("Enter load_widgets_and_handlers...");

	/* advanced setting from advanced dialog */
	self->xml = glade_xml_new (glade_file,
			"nm-novellvpn-advanced-dialog",
			GETTEXT_PACKAGE);
	if (self->xml != NULL) {

		self->w_advanced_dialog = GTK_DIALOG (
			glade_xml_get_widget(self->xml,
				"nm-novellvpn-advanced-dialog"));
		g_return_if_fail (self->w_advanced_dialog != NULL);

		self->w_dhgroup = GTK_COMBO_BOX (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-dhgroup"));
		g_return_if_fail (self->w_dhgroup != NULL);

		self->w_pfsgroup = GTK_COMBO_BOX (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-pfsgroup"));
		g_return_if_fail (self->w_pfsgroup != NULL);

		self->w_routes = GTK_ENTRY (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-routes"));
		g_return_if_fail (self->w_routes != NULL);

		self->w_use_routes = GTK_CHECK_BUTTON (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-use-routes"));
		g_return_if_fail (self->w_use_routes != NULL);

		gtk_signal_connect (GTK_OBJECT (self->w_use_routes),
				"toggled",
			   	GTK_SIGNAL_FUNC (self->use_routes_toggled),
			   	self->editable_changed_user_data);
		gtk_signal_connect (GTK_OBJECT (self->w_routes),
				"changed",
			   	GTK_SIGNAL_FUNC (self->editable_changed),
			   	self->editable_changed_user_data);
	}

	/* normal setting */
	self->xml = glade_xml_new (glade_file,
		   	"nm-novellvpn-widget",
		   	GETTEXT_PACKAGE);
	if (self->xml != NULL) {

		self->widget = glade_xml_get_widget(self->xml,
		   	"nm-novellvpn-widget");
		g_return_if_fail (self->widget != NULL);
		g_object_ref_sink (self->widget);

		self->w_connection_name = GTK_ENTRY (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-connection-name"));
		g_return_if_fail (self->w_connection_name != NULL);

		self->w_gatewaytype = GTK_COMBO_BOX (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-gatewaytype"));
		g_return_if_fail (self->w_gatewaytype != NULL );

		self->w_authtype = GTK_COMBO_BOX (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-authtype"));
		g_return_if_fail (self->w_authtype != NULL );

		self->w_gateway = GTK_ENTRY (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-gateway"));
		g_return_if_fail (self->w_gateway != NULL );

		self->w_settings_notebook = GTK_NOTEBOOK (
				glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-settings"));
		g_return_if_fail (self->w_settings_notebook != NULL);

		self->w_username = GTK_ENTRY (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-username"));
		g_return_if_fail (self->w_username != NULL );

		self->w_groupname = GTK_ENTRY (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-groupname"));
		g_return_if_fail (self->w_groupname != NULL );

		self->w_cert = GTK_ENTRY (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-certificate"));
		g_return_if_fail (self->w_cert != NULL );

		self->w_button_cert = GTK_BUTTON (
			glade_xml_get_widget (self->xml,
				"nm-novellvpn-but-cert"));
		g_return_if_fail (self->w_button_cert != NULL );

		self->w_advanced_button = GTK_BUTTON (
			glade_xml_get_widget (self->xml,
			   	"nm-novellvpn-advanced-button"));
		g_return_if_fail (self->w_advanced_button != NULL );

		gtk_signal_connect (GTK_OBJECT (self->w_connection_name), 
				"changed",
				GTK_SIGNAL_FUNC (*(self->editable_changed)),
				self->editable_changed_user_data);
		gtk_signal_connect (GTK_OBJECT (self->w_gatewaytype),
				"changed",
			   	GTK_SIGNAL_FUNC (self->gateway_type_changed),
			   	self->editable_changed_user_data);
		gtk_signal_connect (GTK_OBJECT (self->w_authtype),
				"changed",
			   	GTK_SIGNAL_FUNC (self->auth_type_changed),
			   	self->editable_changed_user_data);
		gtk_signal_connect (GTK_OBJECT (self->w_gateway), 
				"changed",
				GTK_SIGNAL_FUNC (self->editable_changed),
				self->editable_changed_user_data);

		gtk_signal_connect (GTK_OBJECT (self->w_username), 
				"changed",
			   	GTK_SIGNAL_FUNC (self->editable_changed),
			   	self->editable_changed_user_data);
		gtk_signal_connect (GTK_OBJECT (self->w_groupname), 
				"changed",
			   	GTK_SIGNAL_FUNC (self->editable_changed),
			   	self->editable_changed_user_data);

		gtk_signal_connect (GTK_OBJECT (self->w_cert),
				"changed",
			   	GTK_SIGNAL_FUNC (self->editable_changed),
			   	self->editable_changed_user_data);
		gtk_signal_connect (GTK_OBJECT (self->w_button_cert),
				"clicked",
			   	GTK_SIGNAL_FUNC (self->open_button_clicked),
			   	self->editable_changed_user_data);

		gtk_signal_connect (GTK_OBJECT (self->w_advanced_button),
				"clicked", 
				GTK_SIGNAL_FUNC (self->advanced_button_clicked),
			   	self);

		/* make the widget reusable */
		gtk_signal_connect (GTK_OBJECT (self->widget),
			   	"delete-event", 
				GTK_SIGNAL_FUNC (gtk_widget_hide_on_delete),
			   	NULL);
		gtk_signal_connect (GTK_OBJECT (self->w_advanced_dialog),
			   	"delete-event",
				GTK_SIGNAL_FUNC (gtk_widget_hide_on_delete),
			   	NULL);

		{
			GtkWidget *tab = NULL;

			/* set tab to disabled */
			tab = GTK_WIDGET ( gtk_notebook_get_nth_page(
					GTK_NOTEBOOK (
						self->w_settings_notebook), 0));
			gtk_widget_set_sensitive( tab, FALSE);

			tab = GTK_WIDGET ( gtk_notebook_get_nth_page(
					GTK_NOTEBOOK (
						self->w_settings_notebook), 1));
			gtk_widget_set_sensitive( tab, FALSE);
		}
	}
}

void 
novellvpnui_clear_widget (NovellVPNPropertiesUI *self)
{
	nm_debug ("Enter novellvpnui_clear_widget...");

	g_return_if_fail (NULL != self);

	gtk_entry_set_text (self->w_connection_name, "");
	gtk_entry_set_text (self->w_gateway, "");
	gtk_entry_set_text (self->w_username, "");
	gtk_entry_set_text (self->w_groupname, "");
	gtk_entry_set_text (self->w_cert, "");

	gtk_toggle_button_set_active (
			GTK_TOGGLE_BUTTON (self->w_use_routes), FALSE);
	gtk_entry_set_text (self->w_routes, "");
	gtk_widget_set_sensitive (GTK_WIDGET (self->w_routes), FALSE);

	gtk_combo_box_set_active (
			GTK_COMBO_BOX (self->w_gatewaytype),
		   	NM_NOVELLVPN_GWTYPE_NORTEL);

	gtk_combo_box_set_active (
			GTK_COMBO_BOX (self->w_authtype),
		   	NM_NOVELLVPN_CONTYPE_GROUPAUTH);

	gtk_combo_box_set_active (
			GTK_COMBO_BOX (self->w_dhgroup), 0);

	gtk_combo_box_set_active (
			GTK_COMBO_BOX (self->w_pfsgroup), 0);
}

gchar *
novellvpnui_get_connection_name (NovellVPNPropertiesUI *self)
{
	const char *name =  gtk_entry_get_text (self->w_connection_name);

	nm_debug ("Enter novellvpnui_get_connection_name, name=%s",
			name);

	if (name != NULL)
		return g_strdup (name);
	else
		return NULL;
}

void
novellvpnui_set_connection_name (NovellVPNPropertiesUI *self,
		const gchar *name)
{
	nm_debug ("Enter novellvpnui_set_connection_name, name=%s",
			name);

	if (name != NULL)
		gtk_entry_set_text (self->w_connection_name, name);
	else
		gtk_entry_set_text (self->w_connection_name, "");
}

/*
 * Function: novellvpnui_get_properties
 * Description: 
 *   Get properties from Properties UI and insert it to 
 * NMSettingVPNProperties' g_hash_table.
 *   It used for connecting the vpn server when called
 * nm_novellvpn_start_novellvpn_binary.
 */
void
novellvpnui_get_properties (NovellVPNPropertiesUI *self,
		GHashTable **properties)
{
	const char *conn_name = NULL;
	const char *gwtype = NULL;
	const char *authtype = NULL;
	const char *gw = NULL;
	const char *username = NULL;
	const char *groupname = NULL;
	const char *certificate = NULL;
	const char *dhgroup = NULL;
	const char *pfsgroup = NULL;
	int sw = 0;

	nm_debug ("Enter novellvpnui_get_properties...");

	g_return_if_fail (self != NULL);

	/* the hashtable shouldn't be null */
	g_return_if_fail (properties != NULL);
	g_return_if_fail (*properties != NULL);

	gw  = gtk_entry_get_text (self->w_gateway);
	username = gtk_entry_get_text (self->w_username);
	groupname = gtk_entry_get_text (self->w_groupname);
	certificate = gtk_entry_get_text (self->w_cert); 

	sw = gtk_combo_box_get_active (GTK_COMBO_BOX (self->w_dhgroup));
	switch (sw) 
	{
		case 1:
			dhgroup = g_strdup (DHGROUP2);
			break;
		case 0:
		default:
			dhgroup = g_strdup (DHGROUP1);
	}

	sw = gtk_combo_box_get_active (GTK_COMBO_BOX (self->w_pfsgroup));
	switch (sw) 
	{
		case 2:
			pfsgroup = strdup("2");
		case 1:
			pfsgroup = strdup("1");
			break;
		case 0:
		default:
			pfsgroup = strdup("0");
	}

	sw = gtk_combo_box_get_active (GTK_COMBO_BOX (self->w_gatewaytype));
	switch (sw) 
	{
		case NM_NOVELLVPN_GWTYPE_NORTEL: /* 0 */
			{	
				gwtype = NM_NOVELLVPN_GWTYPE_NORTEL_STRING;

				/* insert gateway-type key and value */
				g_hash_table_insert (*properties,
						g_strdup (NM_NOVELLVPN_KEY_GWTYPE),
						str_to_gvalue(gwtype));

				/* insert remote(gateway address) key and value */
				g_hash_table_insert (*properties,
						g_strdup (NM_NOVELLVPN_KEY_GATEWAY),
						str_to_gvalue(gw));

				sw = gtk_combo_box_get_active (
						GTK_COMBO_BOX (self->w_authtype));
				switch (sw)
				{
					case NM_NOVELLVPN_CONTYPE_GROUPAUTH: /* 0 */
						{
							authtype = NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING;

							/* insert auth-type key and value */
							g_hash_table_insert (*properties,
									g_strdup (NM_NOVELLVPN_KEY_AUTHTYPE),
									str_to_gvalue(authtype));

							/* insert username key and value */
							g_hash_table_insert (*properties,
									g_strdup (NM_NOVELLVPN_KEY_USER_NAME),
									str_to_gvalue(username));

							/* insert group-name key and value */
							g_hash_table_insert (*properties,
									g_strdup (NM_NOVELLVPN_KEY_GROUP_NAME),
									str_to_gvalue(groupname));
							break;
						}
					case NM_NOVELLVPN_CONTYPE_X509: /* 1 */
						{
							authtype = NM_NOVELLVPN_CONTYPE_X509_STRING;

							/* insert auth-type key and value */
							g_hash_table_insert (*properties,
									g_strdup (NM_NOVELLVPN_KEY_AUTHTYPE),
									str_to_gvalue(authtype));

							/* insert certificate key and value */
							g_hash_table_insert (*properties,
									g_strdup (NM_NOVELLVPN_KEY_CERTIFICATE),
									str_to_gvalue(certificate));
							break;
						}
				}
				break;
			}
		case NM_NOVELLVPN_GWTYPE_STDGW: /* 1 */
			{
				gwtype = NM_NOVELLVPN_GWTYPE_STDGW_STRING;

				/* insert gateway-type key and value */
				g_hash_table_insert (*properties,
						g_strdup (NM_NOVELLVPN_KEY_GWTYPE),
						str_to_gvalue(gwtype));

				/* insert remote(gateway address) key and value */
				g_hash_table_insert (*properties,
						g_strdup (NM_NOVELLVPN_KEY_GATEWAY),
						str_to_gvalue(gw));

				authtype = NM_NOVELLVPN_CONTYPE_X509_STRING;

				/* insert auth-type key and value */
				g_hash_table_insert (*properties,
						g_strdup (NM_NOVELLVPN_KEY_AUTHTYPE),
						str_to_gvalue(authtype));

				/* insert certificate key and value */
				g_hash_table_insert (*properties,
						g_strdup (NM_NOVELLVPN_KEY_CERTIFICATE),
						str_to_gvalue(certificate));

				break;
			}
		default:
			nm_warning("Wrong gateway-type(%d)!", sw);
	}

	/* insert dhgroup key and value */
	g_hash_table_insert (*properties,
			g_strdup (NM_NOVELLVPN_KEY_DHGROUP),
			str_to_gvalue(dhgroup));

	/* insert pfsgroup key and value */
	g_hash_table_insert (*properties,
			g_strdup (NM_NOVELLVPN_KEY_PFSGROUP),
			str_to_gvalue(pfsgroup));
}

/*
 * Function: set_property
 * Description: 
 *   The g_hash_table's callback, compare the hashtable's
 * key, and set the value to Properties UI.
 */
static void
set_property (gpointer key, gpointer val, gpointer user_data)
{
	NovellVPNPropertiesUI *self = (NovellVPNPropertiesUI *) user_data;
	const char *name = (const char *) key;
	char *value = (char *)g_value_get_string((GValue *)val);

	nm_debug ("Enter set_property, key=%s, val=%s", name, value);

	/* Found "gateway-type", and set to combo_box */
	if (strcmp (name, NM_NOVELLVPN_KEY_GWTYPE) == 0)
	{
		if ( strcmp (value, NM_NOVELLVPN_GWTYPE_NORTEL_STRING) == 0 ) 
		{
			gtk_combo_box_set_active (
					GTK_COMBO_BOX (self->w_gatewaytype),
					NM_NOVELLVPN_GWTYPE_NORTEL);
		}
		else if ( strcmp ( value, NM_NOVELLVPN_GWTYPE_STDGW_STRING) == 0 )
		{
			gtk_combo_box_set_active (
					GTK_COMBO_BOX (self->w_gatewaytype),
					NM_NOVELLVPN_GWTYPE_STDGW);
		}
	}

	/* Found "auth-type", and set to combo_box */
	if (strcmp (name, NM_NOVELLVPN_KEY_AUTHTYPE) == 0) 
	{
		gint type_cbox_sel = 0;

		/* auth-type is XAUTH */
		if ( strcmp (value, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING) == 0 ) 
		{
			GtkWidget *tab;

			gtk_notebook_set_current_page( self->w_settings_notebook, 0 );
			tab = GTK_WIDGET ( gtk_notebook_get_nth_page( 
						GTK_NOTEBOOK (self->w_settings_notebook), 0));
			gtk_widget_set_sensitive( tab, TRUE);
			gtk_widget_set_sensitive(
			   	GTK_WIDGET (
				   	gtk_notebook_get_tab_label(
						GTK_NOTEBOOK (self->w_settings_notebook),
					   	tab)),
			   	TRUE);
			tab = GTK_WIDGET ( gtk_notebook_get_nth_page(
					   	GTK_NOTEBOOK (self->w_settings_notebook), 1));
			gtk_widget_set_sensitive( tab, FALSE);
			gtk_notebook_set_current_page( self->w_settings_notebook, 0 );
			type_cbox_sel = NM_NOVELLVPN_CONTYPE_GROUPAUTH ;
		}
		/* auth-type is X.509 */
		else if ( strcmp ( value, NM_NOVELLVPN_CONTYPE_X509_STRING) == 0 )
		{
			GtkWidget *tab;
			gtk_notebook_set_current_page( self->w_settings_notebook, 1 );
			tab = GTK_WIDGET ( gtk_notebook_get_nth_page(
					   	GTK_NOTEBOOK (self->w_settings_notebook), 1));
			gtk_widget_set_sensitive( tab, TRUE);
			gtk_widget_set_sensitive(
				   	GTK_WIDGET ( gtk_notebook_get_tab_label( 
						GTK_NOTEBOOK (self->w_settings_notebook), tab) ),
				   	TRUE);
			tab = GTK_WIDGET ( gtk_notebook_get_nth_page(
					   	GTK_NOTEBOOK (self->w_settings_notebook), 0));
			gtk_widget_set_sensitive( tab, FALSE);
			gtk_notebook_set_current_page( self->w_settings_notebook, 1 );
			type_cbox_sel = NM_NOVELLVPN_CONTYPE_X509 ;
		}
		gtk_combo_box_set_active (
				GTK_COMBO_BOX (self->w_authtype),
			   	type_cbox_sel);
	}
	/* Found "remote", and set to text entry*/
	else if (strcmp (key, NM_NOVELLVPN_KEY_GATEWAY) == 0) 
	{
		gtk_entry_set_text (self->w_gateway, value);
	} 
	/* Found "user name", and set to text entry*/
	else if (strcmp (key, NM_NOVELLVPN_KEY_USER_NAME) == 0) 
	{
		gtk_entry_set_text (self->w_username, value);
	} 
	/* Found "group name", and set to text entry*/
	else if (strcmp (key, NM_NOVELLVPN_KEY_GROUP_NAME) == 0) 
	{
		gtk_entry_set_text (self->w_groupname, value);
	} 
	/* Found "certificate", and set to text entry*/
	else if (strcmp (key, NM_NOVELLVPN_KEY_CERTIFICATE) == 0)
	{
		gtk_entry_set_text (self->w_cert, value);
	}
	/* Found "dhgroup", and set to text entry*/
	else if (strcmp (key, NM_NOVELLVPN_KEY_DHGROUP) == 0) 
	{
		DHGroup dh_group = strcmp (value, "dh2") == 0 ? DH2 : DH1;

		gtk_combo_box_set_active (GTK_COMBO_BOX (self->w_dhgroup),
			   	dh_group - 1);
	}
	/* Found "psfgroup", and set to text entry*/
	else if (strcmp (key, NM_NOVELLVPN_KEY_PFSGROUP) == 0) 
	{
		PFSGroup pfs_group = PFS0;

		if (strcmp (value, "2") == 0)
			pfs_group = PFS2;
		if (strcmp (value, "1") == 0)
			pfs_group = PFS1;
		if (strcmp (value, "0") == 0)
			pfs_group = PFS0;

		gtk_combo_box_set_active (GTK_COMBO_BOX (self->w_pfsgroup),
			   	pfs_group);
	}
}

void
novellvpnui_set_properties (NovellVPNPropertiesUI *self,
	   	GSList* routes,
	   	GHashTable *properties)
{
	GSList *i = NULL;

	nm_debug ("Enter novellvpnui_set_properties...");

	if (properties != NULL)
	{
		g_hash_table_foreach (properties, set_property, self);
	}

	if(routes != NULL)
	{
		char* routes_entry = (char*) malloc (200);
		GSList* i;

		strcpy(routes_entry, "");
		for (i = routes; i != NULL ; i = g_slist_next (i)) 
		{
			const char *value;
			value = (i)->data;
			strcat(routes_entry, value);
			strcat(routes_entry, " ");
		}
		gtk_entry_set_text (self->w_routes, routes_entry);
		gtk_toggle_button_set_active (
				GTK_TOGGLE_BUTTON (self->w_use_routes), TRUE);  
	}
}

int isFileExist(const char *string)
{
	struct stat buf;

	if(lstat(string,&buf)<0) 
	{
		return -1;
	}
	else if(!S_ISREG(buf.st_mode) || (buf.st_size==0)) 
	{
		return -1;
	}
	return 0;
}

gboolean
novellvpnui_validate (NovellVPNPropertiesUI *self)
{
	gboolean is_valid = FALSE;
	const char *connectionname = NULL;
	const char *remote = NULL;
	const char *groupname = NULL;

	//nm_debug ("Enter novellvpnui_validate...");

	g_return_val_if_fail (NULL != self, FALSE);

	connectionname = gtk_entry_get_text (self->w_connection_name);
	remote = gtk_entry_get_text (self->w_gateway);

	if ( ((connectionname != NULL) && (strlen (connectionname) == 0)) ||
			((remote != NULL) &&
			 ((strlen (remote) == 0) ||
			  (strstr (remote, " ") != NULL)  ||
			  (strstr (remote, "\t") != NULL))) ) {

		is_valid = FALSE;

	} else {
		const char *username = NULL;
		const char *certificate = NULL;

		username    = gtk_entry_get_text (self->w_username);
		groupname   = gtk_entry_get_text (self->w_groupname);
		certificate = gtk_entry_get_text (self->w_cert);
		//if ( (strlen (groupname) > 0 && (strlen (username) > 0)))
		// GroupName could be set to null
		if ((NULL != username) && (strlen (username) > 0))
		{
			is_valid = TRUE;
		}
		else if ( (NULL != certificate) && (strlen(certificate) > 0 ))
		{
			int cert_file_length = strlen(certificate);

			if (isFileExist(certificate) < 0)
				is_valid = FALSE;
			else
			{	
				if( (certificate[cert_file_length - 1] == 'x')
					   	&& (certificate[cert_file_length - 2] == 'f')
					   	&& (certificate[cert_file_length - 3] == 'p')
					   	&& (certificate[cert_file_length - 4] == '.'))
				{
					is_valid = TRUE;
				}
				else
					is_valid = FALSE;
			}
		}
	} 

	//nm_debug ("Exit novellvpnui_validate, is_valid = %d", is_valid);
	
	return is_valid;
}

gboolean
novellvpnui_init (NovellVPNPropertiesUI *self) 
{
	gchar *glade_file = g_strdup_printf ("%s/%s",
		   	GLADEDIR, "nm-novellvpn-dialog.glade");

	load_widgets_and_handlers (self, (const gchar *) glade_file);

	g_free( glade_file );

	if (self->xml == NULL)
		return FALSE;

	novellvpnui_clear_widget (self);

	return TRUE;
}
