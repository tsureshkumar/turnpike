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

#ifndef __H_NM_NOVELLVPN_PROPERTIESUI__
#define __H_NM_NOVELLVPN_PROPERTIESUI__ 1

#include <gtk/gtk.h>
#include <glade/glade.h>

#define NM_NOVELLVPN_GWTYPE_NORTEL                 0
#define NM_NOVELLVPN_GWTYPE_STDGW                  1

typedef struct _NovellVPNPropertiesUI NovellVPNPropertiesUI;

struct _NovellVPNPropertiesUI {
	GladeXML *xml;

	GtkWidget *widget;

	GtkEntry       *w_connection_name;
	GtkComboBox    *w_gatewaytype;
	GtkComboBox    *w_authtype;
	GtkEntry       *w_gateway;
	GtkEntry       *w_username;
	GtkEntry       *w_groupname;
	GtkComboBox    *w_dhgroup;
	GtkComboBox    *w_pfsgroup;
	
	//GtkExpander    *w_opt_info_expander;
	GtkButton      *w_advanced_button;
	GtkDialog      *w_advanced_dialog;
	GtkEntry       *w_remote;
	GtkEntry       *w_ca;
	GtkEntry       *w_cert;
	GtkEntry       *w_routes;
	GtkCheckButton *w_use_routes;
	GtkButton      *w_button_ca;
	GtkButton      *w_button_cert;
	GtkComboBox    *w_connection_type;
	GtkNotebook    *w_settings_notebook;

	void (*editable_changed) (GtkEditable *editable, gpointer user_data);
	void (*use_routes_toggled) (GtkToggleButton *togglebutton, gpointer user_data);
	void (*open_button_clicked) (GtkButton *button, gpointer user_data);
	void (*gateway_type_changed) (GtkComboBox *box, gpointer user_data);
	void (*auth_type_changed) (GtkComboBox *box, gpointer user_data);
	void (*cert_file_changed) (GtkEntry *cert, gpointer user_data);
	gpointer editable_changed_user_data;

	void (*advanced_button_clicked) (GtkButton *button, gpointer user_data);

};

void 
novellvpnui_clear_widget (NovellVPNPropertiesUI *self);
gchar * 
novellvpnui_get_connection_name (NovellVPNPropertiesUI *self);
void 
novellvpnui_set_connection_name (NovellVPNPropertiesUI *self, const gchar *name);

void
novellvpnui_get_properties (NovellVPNPropertiesUI *self,
		GHashTable **properties);
void 
novellvpnui_set_properties (NovellVPNPropertiesUI *self,
	   	GSList *routes, 
	   	GHashTable *properties);

gboolean
novellvpnui_validate (NovellVPNPropertiesUI *self);

gboolean
novellvpnui_init (NovellVPNPropertiesUI *self); 

#endif // __H_NM_NOVELLVPN_PROPERTIESUI__
