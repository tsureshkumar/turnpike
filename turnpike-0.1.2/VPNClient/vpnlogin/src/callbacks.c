
/************************************************************************************
*   Copyright (c) 2005, Novell Inc.,                                                * 
*   All rights reserved.                                                            *
*                                                                                   *
*   Redistribution and use in source and binary forms, with or without              *
*   modification, are permitted provided that the following conditions              *
*   are met:                                                                        *
*   1.  Redistributions of source code must retain the above copyright              *
*       notice, this list of conditions and the following disclaimer.               *
*   2.  Redistributions in binary form must reproduce the above copyright           *
*       notice, this list of conditions and the following disclaimer in the         *
*       documentation and/or other materials provided with the distribution.        *
*   3.  Neither the name of the Novell nor the names of its contributors            *
*       may be used to endorse or promote products derived from this software       *
*       without specific prior written permission.                                  *
*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND *
*   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE           *
*   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE      *
*   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE *
*   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL      *
*   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS         *
*   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)           *
*   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT      *
*   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY       *
*   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF          *
*   SUCH DAMAGE.                                                                    *
*************************************************************************************/

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include <string.h>

/* GTK Headers */
#include <gtk/gtk.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

/* GUI Headers */
#include "callbacks.h"
#include "interface.h"
#include "support.h"
#include "profile.h"
#include "externs.h"
#include "CommonUI.h"

#include "tpike-types.h"
#include "ui-helpers.h"

/* Racoon Headers */
#include "racoon/admin.h"
extern Inf_t Inf;
extern char* errString(int, char*);
extern int updateProfileList(int loadProfile);
extern void cleanup_resources();
extern int unloadmodule();
extern int confirm_profile_delete(void);
extern int updatePmProfileList(void);
extern void fillup_ike_ph2_params(xmlNode *policy_node);
extern void restoreGatewayPanel(void);
extern void setConnStatus(int state);
extern int load_plugin();
extern int setCertificatesOnpmCombo(char *profileCert);
extern int loadmodule(const char *file_name);
extern int setph1ModeCombo(char *buffer);
extern int setph1HashCombo(char *buffer);
extern int setph1DhCombo(char *buffer);

void
on_vpnlogin_show (GtkWidget *widget, gpointer user_data)
{
	if(widget) {
		//setupLogFile();
		//setUserEnv();
		/* Commenting this inorder for icon not to be visible for Novell innerforge build */

#if 0
		vpnlogin_icon_pixbuf1 = create_pixbuf ("vpnlogin.gif");
		if (vpnlogin_icon_pixbuf1)
		{
			gtk_window_set_icon (GTK_WINDOW (widget), vpnlogin_icon_pixbuf1);
			gdk_pixbuf_unref (vpnlogin_icon_pixbuf1);
		}
#endif                
		if (getWidgetPointers(widget))
			printf("Failed to get widget pointers ..");

		set_missing_mnemonics();
		setInitialSensitivities();
		loadLastSuccessfulProfile(&Inf);
		gtk_combo_box_set_active((GtkComboBox *)gwtypeCombo,0);
		gtk_combo_box_set_active((GtkComboBox *)authenticateCombo,0);
		//gtk_button_set_label(GTK_BUTTON(mainConnectBtn), "Connect");
		gtk_widget_set_sensitive(mainConnectBtn, FALSE);
		updateProfileList(1);

		if(!g_module_supported())	
			show_dialog_message(errString(GMODULE_SUPPORT_ERROR, Inf.errStr));
	}
	else
		printf("main widget is NULL\n");
}


void
on_vpnlogin_destroy (GtkObject *object, gpointer user_data)
{
	if(Inf.connInProgress) {
		Inf.connInProgress = FALSE;
		disconnectServer(&Inf, 1);
	}

	cleanup_resources();
	gtk_main_quit();
	exit(0);
}


void
on_profileCombo_changed (GtkComboBox *combobox, gpointer user_data)
{
	char *comboString = NULL;
	char prfname[MAX_STRING_LEN];
	int index;

	comboString = get_active_text_from_combobox(combobox);

	if (!comboString)
		return;

	if ((index = gtk_combo_box_get_active ( (GtkComboBox *)combobox)) == 1) {
		if(Inf.plugin) {
			unloadmodule();
		}
		setInitialSensitivities();
		return;
	}

	if(strcmp(comboString, "Choose profile") == 0) {
		setInitialSensitivities();
	} else if(strcmp(comboString, "Profile manager") == 0) {
		if(Inf.plugin) {
			unloadmodule();
		}
		gtk_widget_set_sensitive((GtkWidget *)gwMaintable, FALSE);
		gtk_widget_show(profileManagerVbox);
		gtk_widget_set_sensitive(profileManagerVbox, TRUE);
		gtk_widget_hide(mainWindowHbox);
		do_profile_manager();
	} else {
		strcpy(prfname, "profile_");
		strcat(prfname, comboString);
		strcat(prfname, ".prf");
		loadProfile(prfname);
	}

	if(comboString) {
		free(comboString);
		comboString = NULL;
	}
}


void
on_pmCancelBtn_clicked (GtkButton *button, gpointer user_data)
{
	if (profileManagerActive) {
		if (!Inf.mainWindowActive) {
			gtk_widget_set_sensitive((GtkWidget *)gwMaintable, TRUE);
			gtk_widget_show(mainWindowHbox);
			gtk_widget_hide(profileManagerVbox);
			gtk_notebook_set_current_page((GtkNotebook *)mainNotebook, 0);
			setInitialSensitivities();
			updateProfileList(0);
			on_profileCombo_changed((GtkComboBox *)profileCombo, NULL);
		}
	}
}


void
on_pmRembtn_clicked (GtkButton *button, gpointer user_data)
{
	if(!confirm_profile_delete())
		return;

	setpmsensitivities(PM_REM_BTN_CLICKED);
	removeCurrentProfile();
	setpmsensitivities(PM_REM_BTN_FINISHED);
}

void
on_pmSavBtn_clicked (GtkButton *button, gpointer user_data)
{
	setpmsensitivities(PM_SAVE_BTN_CLICKED);
	if (writeCurrentProfileToFile()) {
		setpmsensitivities(PM_SAVE_BTN_FAILED); //None at this time
		return;
	}
	setpmsensitivities(PM_SAVE_BTN_FINISHED);
	updatePmProfileList();
	gtk_combo_box_set_active((GtkComboBox *)pmprofileCombo,0);
	on_pmprofileCombo_changed((GtkComboBox *)pmprofileCombo, NULL);
	//on_pmprofileCombo_changed(pmprofileCombo, NULL);
}

void
on_pmAddBtn_clicked (GtkButton *button, gpointer user_data)
{
	setpmsensitivities(PM_ADD_BTN_CLICKED);
	
	//setCertificatesOnpmCombo(NULL);
	gtk_widget_show(pmNotebook);
	fillup_ike_ph2_params(NULL);
}

void
on_mainHelpBtn_clicked (GtkButton *button, gpointer user_data)
{
	/* Commenting this inorder for help not to be visible for Novell innerforge build */
            
#if 0
	char helpstr[MAX_STRING_LEN];
	
	if(isFileExist(HELP_FILE)!=0){
		show_dialog_message(errString(HELP_FILE_NOT_LOCATED, errStr));
		return;
	}
	sprintf(helpstr, "yelp %s &", HELP_FILE);
	
	system(helpstr);
#endif        
}


void
on_mainCancelBtn_clicked (GtkButton *button, gpointer user_data)
{
	if (!Inf.connInProgress)
		on_vpnlogin_destroy(NULL, NULL);
	else
		restoreGatewayPanel();
}


void
on_button4_clicked                     (GtkButton       *button,
                                        gpointer         user_data)
{

}


void
on_auth1Combo_changed (GtkComboBox *combobox, gpointer user_data)
{
}

void
on_pmauthCombo_changed (GtkComboBox *combobox, gpointer user_data)
{
	if(gtk_combo_box_get_active(combobox)) {
		gtk_widget_set_sensitive(pmSavBtn, TRUE);
	} else
		gtk_widget_set_sensitive(pmSavBtn, FALSE);
}

void
on_mainConnectBtn_clicked (GtkButton *button, gpointer user_data)
{
	if (Inf.plugin == 1) {
		if(Inf.authentication_type == CERTIFICATE) {
			if(getAndValidateFields_for_Connect())
				return;
		} else if(Inf.authentication_type == XAUTH) {
			if(getAndValidateField_for_Plugin_Connect())
				return;
		}

		if(Inf.plugin_connect) {
			if(Inf.authentication_type == CERTIFICATE)
				strcpy(Inf.pluginBuf, "CERTIFICATE");
			Inf.pluginBufLen = Inf.plugin_connect((Inf.pluginBuf));
		}
	} else {
		if (getAndValidateFields_for_Connect())
			return;
	}

	if (connectToServer(&Inf, 1)) {
		return;
	}
	else
		setConnStatus(IKE_CONN_IN_PROGRESS);

	startEventPoll(&Inf, 1);
}

void
on_mainDisconnectBtn_clicked (GtkButton *button, gpointer user_data)
{
	disconnectServer(&Inf, 1);
	return;
}

void
on_ph1expander_activate (GtkExpander *expander, gpointer user_data)
{
	GtkWidget *ph1Table;
	GtkWidget *ph1Label1;

	if(gtk_expander_get_expanded(expander))
	{

	}
	else
	{
		ph1Table = gtk_table_new (3, 3, FALSE);
		gtk_widget_show (ph1Table);
		GTK_WIDGET_SET_FLAGS (ph1Table, GTK_CAN_FOCUS);

		ph1Label1 = gtk_label_new_with_mnemonic (_("IKE Mode:"));
		gtk_widget_show (ph1Label1);
		//gtk_table_attach (GTK_TABLE (ph1Table), ph1Label1, 0, 1, 0, 1,
		//  	(GtkAttachOptions) (GTK_FILL),
		//	(GtkAttachOptions) (0), 0, 0);
		gtk_container_add (GTK_CONTAINER (expander), ph1Label1);
	}
}


void
on_ph2expander_activate (GtkExpander *expander, gpointer user_data)
{
	if(gtk_expander_get_expanded(expander))
		show_dialog_message("ph2 expanded !");
	else
		show_dialog_message("ph2 shrunk !");
}


gboolean
on_ikenotebook_select_page (
		GtkNotebook *notebook,
		gboolean move_focus,
		gpointer user_data)
{
	show_dialog_message("notebook page selected");
	return FALSE;
}


void
on_ikenotebook_switch_page (
		GtkNotebook *notebook,
		GtkNotebookPage *page,
		guint page_num,
		gpointer user_data)
{
	if (page_num == 1) {
		fillup_ike_ph2_params(NULL);
	}
}


void
on_gwtypeCombo_changed (GtkComboBox *combobox, gpointer user_data)
{
	char *comboString = NULL;

	comboString = get_active_text_from_combobox(combobox);
	if (strcmp(comboString, "Standard IPsec gateway")== 0) //||(strcmp(comboString, "Choose gateway type") == 0))
	{
		if(module) {
			unloadmodule();
		}
	}

	if(comboString)
		free(comboString);	
}


void
on_pmgwtypeCombo_changed (GtkComboBox *combobox, gpointer user_data)
{
	char *comboString = NULL;
	//int saved_position = 0;
	comboString = get_active_text_from_combobox (combobox);

	if (strcmp (comboString, "Standard IPsec gateway") == 0) {
		gtk_widget_show (pmAuthframe);
		if (pmPluginActive) {
			unloadmodule ();
			pmPluginActive = 0;
		}
		gtk_widget_set_sensitive (pmauthtypeCombo, TRUE);
		gtk_combo_box_set_active ((GtkComboBox *)pmauthtypeCombo, 1);
		gtk_widget_set_sensitive (pmauthtypeCombo, FALSE);

	} else if (strcmp(comboString, "nortel") == 0) {
		gtk_widget_set_sensitive (pmauthtypeCombo, TRUE);
		gtk_signal_emit_by_name ((GtkObject*)pmauthtypeCombo,
			   	"changed",
			   	NULL);
		//saved_position = gtk_combo_box_get_active((GtkComboBox *)pmauthtypeCombo);
		//gtk_combo_box_set_active((GtkComboBox *)pmauthtypeCombo, 1 - saved_position);
		//gtk_combo_box_set_active((GtkComboBox *)pmauthtypeCombo, saved_position);
	}

	if (comboString)
		free(comboString);
}

void
on_pmauthtypeCombo_changed (GtkComboBox *combobox, gpointer user_data)
{
	enum tpike_auth_type auth_method = ui_helper_get_authmethod ();
	const gchar *gateway_type = ui_helper_get_gateway_type_text ();

	if (auth_method == TPIKE_AUTH_TYPE_NONE
			|| ui_helper_get_gateway_type () == TPIKE_GATEWAY_TYPE_NONE)
		return;

	if (auth_method == TPIKE_AUTH_TYPE_XAUTH) {
		char Plugin [MAX_STRING_LEN] = { '\0' };
		char vendorfile[MAX_STRING_LEN] = {'\0'};

		pmPluginActive = 1;

		sprintf(Plugin, LIB_LOAD_PATH"/libgui%s.so", gateway_type);
		if (loadmodule(Plugin) == -1)
			return ;

		if (Inf.plugin_gui_init)
			Inf.plugin_gui_init ();

		strcpy(vendorfile, Inf.userHome);
		strcat(vendorfile, VENDOR_PROFILE_PATH1);
		strcat(vendorfile, "vendor_");
		strcat(vendorfile, (char *)gtk_entry_get_text ((GtkEntry *)pmprofileNameEntry));
		strcat(vendorfile, ".prf");

		if (isFileExist (vendorfile)==0) {
			if (Inf.plugin_pm_load_vendorProfile)
				Inf.plugin_pm_load_vendorProfile (vendorfile);
		}
		setph1ModeCombo ("AM");
		gtk_widget_set_sensitive (pmSavBtn, TRUE);

	} else if (auth_method == TPIKE_AUTH_TYPE_X509) {
		if (pmPluginActive == 1) {
			unloadmodule ();
			pmPluginActive = 0;
		}

		gtk_widget_set_sensitive (pmSavBtn, FALSE);
		setCertificatesOnpmCombo (NULL);
		setph1ModeCombo ("MM");
		gtk_widget_set_sensitive (pmSavBtn, TRUE);
	}
}

void
on_pmSplitTunnelCheckBtn_toggled (GtkToggleButton *togglebtn, gpointer user_data)
{
	const gchar *nosplittunnel = ui_helper_get_split_tunnel ();

	if (strcmp(nosplittunnel, "yes") == 0)
		Inf.no_split_tunnel = 1;
	else
		Inf.no_split_tunnel = 0;
}

int confirm_profile_delete(void)
{
	int ret = 0;
	
	GtkWidget *dialog = gtk_dialog_new_with_buttons (_("Profile Deletion"),
                                                  (GtkWindow *)mainWindow,
                                                  GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                  GTK_STOCK_YES,
                                                  GTK_RESPONSE_YES,
                                                  GTK_STOCK_NO,
                                                  GTK_RESPONSE_NO,
                                                  NULL);
	GtkWidget *label = gtk_label_new (_("\nDo you really want to delete this profile ?\n"));
	gtk_container_add (GTK_CONTAINER (GTK_DIALOG(dialog)->vbox),label);
	gtk_widget_show_all (dialog);
	gint result = gtk_dialog_run (GTK_DIALOG (dialog));
	switch (result)
	{
		case GTK_RESPONSE_YES:
			ret = 1;
		break;
		case GTK_RESPONSE_NO:
			ret = 0;
		break;
		default:
			printf("unknown response\n");
			ret = 0;
		break;
	}
	gtk_widget_destroy (dialog);
	return ret;
}
