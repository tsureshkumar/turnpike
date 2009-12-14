
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif // HAVE_CONFIG_H

#include <sys/stat.h>
#include <sys/queue.h>
#include <dirent.h>
#include <netdb.h>
#include <errno.h>
#include <pwd.h>
#include <string.h>

#include <gtk/gtk.h>
#include <gmodule.h>

/* Racoon headers */
#include "racoon/admin.h"
#include "racoon/evt.h"
#include "racoon/oakley.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/ipsec_doi.h"

typedef struct admin_com comHeader_t;
typedef struct admin_com_indexes comIndexes_t;

#include "utility.h"
#include "profile.h"
#include "callbacks.h"
#include "support.h"
#include "vpncErrorHandling.h"
#include "getip.h"
#include "guiErrors.h"

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "CommonUI.h"

#include "ui-helpers.h"

extern int unloadmodule();
extern int updatePmProfileList(void);
extern char* errString(int, char*);
extern int loadmodule(const char *file_name);
extern int vpnExtCerts(const char *pfxFilePath, const char *password);
extern void writePhase2PoliciesToFile(xmlNode *policy_node);
extern int initSocket();

GModule* module = NULL;
GtkWidget *mainWindow = NULL;
GtkWidget *mainNotebook = NULL;
GtkWidget *gwMaintable = NULL;
GtkWidget *profileLabel = NULL;
GtkWidget *profileCombo = NULL;
GtkWidget *gwtypeLabel = NULL;
GtkWidget *gwtypeCombo = NULL;
GtkWidget *gwLabel = NULL;
GtkWidget *gwEntry = NULL;
GtkWidget *authenticateLabel = NULL;
GtkWidget *authenticateCombo = NULL;
GtkWidget *authFrame = NULL;
GtkWidget *authenticateHeadingLabel = NULL;
GtkWidget *auth1label = NULL;
GtkWidget *auth1Combo = NULL;
GtkWidget *auth2Label = NULL;
GtkWidget *auth2Entry = NULL;
GtkWidget *dynamicsVbox = NULL;
GtkWidget *profileManagerVbox = NULL;
GtkWidget *profilePanel = NULL;
GtkWidget *mainWindowHbox = NULL;

GtkWidget *mainConnectBtn = NULL;
GtkWidget *mainCancelBtn = NULL;
GtkWidget *mainDisconnectBtn = NULL;
GtkWidget *mainHelpBtn = NULL;

//Connection Panel
GtkWidget *connPanelVBox = NULL;
GtkWidget *connStatusLabel = NULL;
GtkWidget *connLabel = NULL;
GtkWidget *addbtn = NULL;
GtkWidget *rembtn = NULL;

//Profile Manager

GtkWidget *ph2treeview = NULL;
GtkWidget *pmprofileCombo = NULL;
GtkWidget *pmprofileNameEntry = NULL;
GtkWidget *pmGwEntry = NULL;
GtkWidget *pmgwtypeCombo = NULL;
GtkWidget *pmauthtypeCombo = NULL;
GtkWidget *pmauthenticateCombo = NULL;
GtkWidget *pmauthenticateLabel = NULL;
GtkWidget *pmAuthframe = NULL;
GtkWidget *pmNotebook = NULL;
GtkWidget *pmauthCombo = NULL;
GtkWidget *pmSavBtn = NULL;
GtkWidget *pmAddBtn = NULL;
GtkWidget *pmremBtn = NULL;
GtkWidget *pmCancelBtn = NULL;
GtkWidget *pmGeneralTable = NULL;

GtkWidget *pmPh1ModeCombo = NULL;
GtkWidget *pmPh1DhCombo = NULL;
GtkWidget *pmPh2DhCombo = NULL;
GtkWidget *pmSplitTunnelCheckBtn = NULL;

GtkWidget *pmProfileLabel = NULL;
GtkWidget *pmProfileNameLabel = NULL;
GtkWidget *pmGwTypeLabel = NULL;
GtkWidget *pmGwIP = NULL;
GtkWidget *pmAuthenticateLabel = NULL;
GtkWidget *pmUserCertLabel = NULL;
GtkWidget *pmPh1ModeLabel = NULL;
GtkWidget *pmPh1DhLabel = NULL;
GtkWidget *pmPh2PfsLabel = NULL;
GtkWidget *connDetailsTable = NULL;
GtkWidget *connIPAddressLabel = NULL;
GtkWidget *connUptimeLabel = NULL;

char profile_files[MAX_PROFILES][MAX_PROFILE_FILENAME_LENGTH];
char certificates[MAX_CERTIFICATE][MAX_CERTIFICATE_LENGTH];
char PLOG_FILE[MAX_STRING_LEN] = { '\0' };
int profileManagerActive = FALSE;
int pmPluginActive = 0;
time_t connectedTime;
char ph1Config[512];
char ph1Proposal[512];
extern Inf_t Inf;

static struct Evtmsg evtmsg[] = {
        { EVTT_PHASE1_UP, "Phase 1 established", INFO },
        { EVTT_PHASE1_DOWN, "Phase 1 deleted", INFO },
        { EVTT_XAUTH_SUCCESS, "Xauth exchange passed", INFO },
        { EVTT_ISAKMP_CFG_DONE, "ISAKMP mode config done", INFO },
        { EVTT_PHASE2_UP, "Phase 2 established", INFO },
        { EVTT_PHASE2_DOWN, "Phase 2 deleted", INFO },
        { EVTT_DPD_TIMEOUT, "Peer not reachable anymore", ERROR },
        { EVTT_PEER_NO_RESPONSE, "Peer not responding", ERROR },
        { EVTT_PEER_DELETE, "Peer terminated security association", ERROR },
        { EVTT_RACOON_QUIT, "Raccon terminated", ERROR },
        { EVTT_OVERFLOW, "Event queue overflow", ERROR },
        { EVTT_XAUTH_FAILED, "Xauth exchange failed", ERROR },
        { EVTT_PEERPH1AUTH_FAILED, "Peer failed phase 1 authentication ""(certificate problem?)", ERROR },
        { 0, NULL, UNSPEC },
};

int getWidgetPointers(GtkWidget       *widget)
{	
	mainWindow = widget;
	if((mainNotebook = (GtkWidget *) lookup_widget(widget, WIDGET_MAIN_NOTEBOOK)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_MAIN_NOTEBOOK not found .. \n");
	if((gwMaintable = (GtkWidget *)lookup_widget(widget, WIDGET_GW_MAIN_TABLE)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_MAIN_TABLE not found .. \n");
	
	if((dynamicsVbox = (GtkWidget *)lookup_widget(widget, WIDGET_DYN_VBOX)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_DYN_VBOX not found .. \n");
		
	if((profilePanel = (GtkWidget *)lookup_widget(widget, WIDGET_PROFILE_PANEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PROFILE_PANEL not found .. \n");
	
	if((profileManagerVbox = (GtkWidget *)lookup_widget(widget, WIDGET_PROFILE_MGR_VBOX)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PROFILE_MGR_VBOX not found .. \n");
		
	if((profileLabel = (GtkWidget *)lookup_widget(widget, WIDGET_GW_PROFILE_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_PROFILE_LABEL not found .. \n");
	if((profileCombo = (GtkWidget *)lookup_widget(widget, WIDGET_GW_PROFILE_COMBO)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_PROFILE_COMBO not found .. \n");
	
	
	if((gwtypeLabel = (GtkWidget *)lookup_widget(widget, WIDGET_GW_TYPE_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_TYPE_LABEL not found .. \n");
	
	
	if((gwtypeCombo = (GtkWidget *)lookup_widget(widget, WIDGET_GW_TYPE_COMBO)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_TYPE_COMBO not found .. \n");
	
	if((gwLabel = (GtkWidget *)lookup_widget(widget, WIDGET_GW_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_LABEL not found .. \n");
	

	
	
	if((gwEntry = (GtkWidget *)lookup_widget(widget, WIDGET_GW_ENTRY)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_ENTRY not found .. \n");
	
	
	if((authenticateLabel = (GtkWidget *)lookup_widget(widget, WIDGET_GW_AUTHENTICATE_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_AUTHENTICATE_LABEL not found .. \n");
	
	
	if((authenticateCombo = (GtkWidget *)lookup_widget(widget, WIDGET_GW_AUTHENTICATE_COMBO)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_AUTHENTICATE_COMBO not found .. \n");
	
	
	if((authFrame = (GtkWidget *)lookup_widget(widget, WIDGET_GW_AUTH_FRAME)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_AUTH_FRAME not found .. \n");
	
	
	if((authenticateHeadingLabel = (GtkWidget *)lookup_widget(widget, WIDGET_GW_AUTH_HEADING_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_AUTH_HEADING_LABEL not found .. \n");
	
	
	if((auth1label = (GtkWidget *)lookup_widget(widget, WIDGET_GW_AUTH1_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_AUTH1_LABEL not found .. \n");
	
	
	if((auth1Combo = (GtkWidget *)lookup_widget(widget, WIDGET_GW_AUTH1COMBO)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_AUTH1COMBO not found .. \n");
	
	if((auth2Label = (GtkWidget *)lookup_widget(widget, WIDGET_GW_AUTH2LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_AUTH2LABEL not found .. \n");
	
	if((auth2Entry = (GtkWidget *)lookup_widget(widget, WIDGET_GW_AUTH2ENTRY)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_AUTH2ENTRY not found .. \n");
	
	if((mainWindowHbox = (GtkWidget *)lookup_widget(widget, WIDGET_MAIN_HBOX)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_MAIN_HBOX not found .. \n");
	
	if((mainConnectBtn = (GtkWidget *)lookup_widget(widget, WIDGET_MAIN_CONNECTBTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_MAIN_CONNECTBTN not found .. \n");

	if((mainCancelBtn = (GtkWidget *)lookup_widget(widget, WIDGET_MAIN_CANCELBTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_MAIN_CANCELBTN not found .. \n");
	if((mainDisconnectBtn = (GtkWidget *)lookup_widget(widget, WIDGET_MAIN_DISCONNECTBTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_MAIN_DISCONNECTBTN not found .. \n");

	if((mainHelpBtn = (GtkWidget *)lookup_widget(widget, WIDGET_MAIN_HELPBTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_MAIN_HELPBTN not found .. \n");

		
	//Connection Details panel
	if((connPanelVBox = (GtkWidget *)lookup_widget(widget, WIDGET_CONN_MAIN_VBOX)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_CONN_MAIN_VBOX not found .. \n");
	
	if((connStatusLabel = (GtkWidget *)lookup_widget(widget, WIDGET_CONN_STATUS_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_CONN_STATUS_LABEL not found .. \n");
	
	if((connLabel = (GtkWidget *)lookup_widget(widget, WIDGET_CONN_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_CONN_LABEL not found .. \n");

		
	//Profile Manager
	
	if((ph2treeview = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PH2_TREEVIEW)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PH2_TREEVIEW not found .. \n");
		
	if((addbtn = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PH2_ADDBTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PH2_ADDBTN not found .. \n");

	if((rembtn = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PH2_REMBTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PH2_REMBTN not found .. \n");
	
	
	if((pmprofileCombo = (GtkWidget *)lookup_widget(widget, WIDGET_GW_PM_PROFILE_COMBO)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_GW_PM_PROFILE_COMBO not found .. \n");

	if((pmNotebook = (GtkWidget *)lookup_widget(widget, WIDGET_PM_NOTEBOOK)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_NOTEBOOK not found .. \n");
	if((pmprofileNameEntry = (GtkWidget *)lookup_widget(widget, WIDGET_PM_NAME_ENTRY)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_NAME_ENTRY not found .. \n");
	if((pmGwEntry = (GtkWidget *)lookup_widget(widget, WIDGET_PM_GW_ENTRY)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_GW_ENTRY not found .. \n");
	if((pmgwtypeCombo = (GtkWidget *)lookup_widget(widget, WIDGET_PM_GW_TYPE)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_GW_TYPE not found .. \n");
	if((pmauthtypeCombo = (GtkWidget *)lookup_widget(widget, WIDGET_PM_AUTH_TYPE)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_GW_TYPE not found .. \n");
	if((pmauthenticateCombo = (GtkWidget *)lookup_widget(widget, WIDGET_PM_AUTH_COMBO)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_AUTH_COMBO not found .. \n");
	if((pmauthenticateLabel = (GtkWidget *)lookup_widget(widget, WIDGET_PM_AUTH_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_AUTH_LABEL not found .. \n");		
	if((pmAuthframe = (GtkWidget *)lookup_widget(widget, WIDGET_PM_AUTH_FRAME)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_AUTH_FRAME not found .. \n");
	if((pmauthCombo = (GtkWidget *)lookup_widget(widget, WIDGET_PM_AUTH_COMBO1)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_AUTH_COMBO1 not found .. \n");
	
	if((pmSavBtn = (GtkWidget *)lookup_widget(widget, WIDGET_PM_SAV_BTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_SAV_BTN not found .. \n");
	
	if((pmAddBtn = (GtkWidget *)lookup_widget(widget, WIDGET_PM_ADD_BTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_ADD_BTN not found .. \n");
	
	if((pmremBtn = (GtkWidget *)lookup_widget(widget, WIDGET_PM_REM_BTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_REM_BTN not found .. \n");

	if((pmCancelBtn = (GtkWidget *)lookup_widget(widget, WIDGET_PM_CANCEL_BTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_CANCEL_BTN not found .. \n");

	if((pmGeneralTable = (GtkWidget *)lookup_widget(widget, WIDGET_PM_GEN_TABLE)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_GEN_TABLE not found .. \n");

        if((pmPh1ModeCombo = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PH1_MODE_COMBO)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PH1_MODE_COMBO not found .. \n");

	if((pmPh1DhCombo = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PH1_DH_COMBO)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PH1_DH_COMBO not found .. \n");

	if((pmPh2DhCombo = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PH2_DH_COMBO)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PH2_DH_COMBO not found .. \n");

	if((pmSplitTunnelCheckBtn = (GtkWidget *)lookup_widget(widget, WIDGET_PM_NO_SPLITTUNNEL_CHECKBTN)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_NO_SPLITTUNNEL_CHECKBTN not found .. \n");

	if((pmProfileLabel = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PROF_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PROF_LABEL not found .. \n");

	if((pmProfileNameLabel = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PROF_NAME_LABEL )) == NULL)
		plog(LLV_ERROR, NULL, NULL," WIDGET_PM_PROF_NAME_LABEL not found .. \n");
	
	if(( pmGwTypeLabel= (GtkWidget *)lookup_widget(widget, WIDGET_PM_GWTYPE_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_GWTYPE_LABEL not found .. \n");
	
	if((pmGwIP = (GtkWidget *)lookup_widget(widget, WIDGET_PM_GWIP_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_GWIP_LABEL not found .. \n");
	
	if((pmAuthenticateLabel = (GtkWidget *)lookup_widget(widget, WIDGET_PM_AUTHENTICATE_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_AUTHENTICATE_LABEL not found .. \n");
	
	if((pmUserCertLabel = (GtkWidget *)lookup_widget(widget, WIDGET_PM_USER_CERT_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_USER_CERT_LABEL not found .. \n");
	
	if((pmPh1ModeLabel = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PH1_MODE_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PH1_MODE_LABEL not found .. \n");
	
        if((pmPh1DhLabel = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PH1_DH_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PH1_DH_LABEL not found .. \n");
	
	if((pmPh2PfsLabel = (GtkWidget *)lookup_widget(widget, WIDGET_PM_PH2_PFS_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_PM_PH2_PFS_LABEL not found .. \n");
	
	if((connDetailsTable = (GtkWidget *)lookup_widget(widget, WIDGET_CONN_DETAILS_TABLE)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_CONN_DETAILS_TABLE not found .. \n");
	
	if((connIPAddressLabel = (GtkWidget *)lookup_widget(widget, WIDGET_CONN_IPADDRESS_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_CONN_IPADDRESS_LABEL not found .. \n");

	if((connUptimeLabel = (GtkWidget *)lookup_widget(widget, WIDGET_CONN_UPTIME_LABEL)) == NULL)
		plog(LLV_ERROR, NULL, NULL,"WIDGET_CONN_UPTIME_LABEL not found .. \n");
	return 0;
}


void setInitialSensitivities(void)
{
	gtk_entry_set_text((GtkEntry *)gwEntry, "");
	gtk_combo_box_set_active((GtkComboBox *)gwtypeCombo,0);
	gtk_widget_hide(authenticateLabel);
	gtk_widget_hide(authenticateCombo);
	gtk_widget_hide(authFrame);
	gtk_widget_set_sensitive(mainConnectBtn, FALSE);
	gtk_widget_set_sensitive(mainCancelBtn, TRUE);
	gtk_widget_set_sensitive(mainDisconnectBtn, FALSE);
	gtk_widget_hide(mainDisconnectBtn);

	return;	
}

//int load_nortel_plugin(void)
int load_plugin()
{
	char Plugin[MAX_STRING_LEN] = { '\0' };
	gtk_widget_set_sensitive(mainConnectBtn, TRUE);
	gtk_widget_hide(authenticateLabel);
	gtk_widget_hide(authenticateCombo);
	if(strcmp(Inf.gatewayType,"Standard IPsec gateway") == 0)
	{
		unloadmodule();
		return 1;
	}
	if(strcmp(Inf.gatewayType , "") != 0)
	{
		sprintf(Plugin, LIB_LOAD_PATH"/libgui%s.so", Inf.gatewayType);
		loadmodule(Plugin) ;
		if(Inf.plugin_gui_init)
			Inf.plugin_gui_init();
		if(Inf.plugin_load_vendorProfile)
			Inf.plugin_load_vendorProfile(Inf.vendorfile);
	}
	return 0;
}

//int dir_check(char *string)

//int file_check(char *string)

//int get_dir_list(char *directory,char array[][MAX_PROFILE_FILENAME_LENGTH],char *ext)

//int get_profile_list(char *directory,char array[][MAX_PROFILE_FILENAME_LENGTH],char *ext)

void do_profile_manager(void)
{
	gtk_notebook_set_current_page((GtkNotebook *)mainNotebook, 3);
	profileManagerActive = TRUE;
	updatePmProfileList();
	on_pmprofileCombo_changed((GtkComboBox *)pmprofileCombo, NULL);
	setpmsensitivities(PM_INITIAL);
	return;
}

void resetMainWindowFields(void)
{
	return;
}

int setCertificatesOnCombo(char *profileCert)
{
	int numberofCerts = 0, i;
	GtkTreeIter iter;
	GtkListStore* store;
	int certIndex = -1;
	char error_string[MAX_STRING_LEN] = {0};

	if (dir_check(Inf.pfx_file_path) == FILE_EXIST) {
		numberofCerts = get_dir_list(Inf.pfx_file_path, certificates, ".pfx");
		if (numberofCerts == 0) {
			show_dialog_message(errString(NO_PFX_FILES, error_string));
			return -1;
		} else {
			g_signal_handlers_disconnect_by_func(G_OBJECT(auth1Combo),
					G_CALLBACK(on_auth1Combo_changed), NULL);

			store = gtk_list_store_new(1, G_TYPE_STRING);

			//Append Choose Profile
			gtk_list_store_append (store, &iter);
			gtk_list_store_set (store, &iter,0,"Choose certificate",-1);

			for (i = 0; i < numberofCerts; i ++) {
				gtk_list_store_append (store, &iter);
				gtk_list_store_set (store, &iter,0,certificates[i],-1);
				if (strcmp(profileCert, certificates[i]) == 0)
					certIndex = i;
			}
			gtk_combo_box_set_model((GtkComboBox *)auth1Combo, (GtkTreeModel *)store);

			//set the first profile to be active
			if (certIndex != -1)
				gtk_combo_box_set_active((GtkComboBox *)auth1Combo,certIndex+1);
			else {
				show_dialog_message(errString(INVALID_PROFILE_CERT, error_string));
				gtk_combo_box_set_active((GtkComboBox *)auth1Combo,0);
			}

			g_signal_connect(G_OBJECT(auth1Combo), "changed", 
					G_CALLBACK(on_auth1Combo_changed), NULL);
		}
	} else {
		plog(LLV_ERROR, NULL, NULL," Directory %s does not exist \n", Inf.pfx_file_path);
		show_dialog_message(errString(CERT_DIR_DOES_NOT_EXIST, error_string));

		return -1;
	}

	return 0;

}


int setCertificatesOnpmCombo(char *profileCert)
{
	int numberofCerts = 0, i;
	GtkTreeIter iter;
	GtkListStore* store;
	int certIndex = -1;
	char error_string[MAX_STRING_LEN] = {0};
	
	if(dir_check(Inf.pfx_file_path) == FILE_EXIST)
	{
		numberofCerts = get_dir_list(Inf.pfx_file_path, certificates, ".pfx");
		if(numberofCerts==0)
		{
			show_dialog_message(errString(NO_PFX_FILES, error_string));
			return -1;
		}
		else
		{
			g_signal_handlers_disconnect_by_func(G_OBJECT(pmauthCombo), G_CALLBACK(on_pmauthCombo_changed), NULL);
			
			store = gtk_list_store_new(1, G_TYPE_STRING);
			
			//Append Choose Profile
			gtk_list_store_append (store, &iter);
			gtk_list_store_set (store, &iter,0,"Choose certificate",-1);
			
			for(i = 0; i < numberofCerts; i ++)
			{
				gtk_list_store_append (store, &iter);
				gtk_list_store_set (store, &iter,0,certificates[i],-1);
				if(profileCert)
					if(strcmp(profileCert, certificates[i]) == 0)
						certIndex = i;
			}
			gtk_combo_box_set_model((GtkComboBox *)pmauthCombo, (GtkTreeModel *)store);
			
			//set the first profile to be active
			if(certIndex != -1)
				gtk_combo_box_set_active((GtkComboBox *)pmauthCombo,certIndex+1);
			else
			{
				if(profileCert)
					show_dialog_message(errString(INVALID_PROFILE_CERT, error_string));
				gtk_combo_box_set_active((GtkComboBox *)pmauthCombo,0);
				g_signal_connect(G_OBJECT(pmauthCombo), "changed", 
					G_CALLBACK(on_pmauthCombo_changed), NULL);

				return -1;
			}
			
			g_signal_connect(G_OBJECT(pmauthCombo), "changed", 
					G_CALLBACK(on_pmauthCombo_changed), NULL);
		}
	}
	else
	{
		plog(LLV_ERROR, NULL, NULL," Directory %s does not exist \n", Inf.pfx_file_path);
		show_dialog_message(errString(CERT_DIR_DOES_NOT_EXIST, error_string));
		return -1;
	}
	return 0;

}

void show_dialog_message(char *string)
{

	GtkWidget *message = gtk_message_dialog_new(GTK_WINDOW(mainWindow), 
		GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, string);
	gtk_dialog_run(GTK_DIALOG(message));

	gtk_widget_destroy (message);
}


int getAndValidateFields_for_Connect(void)
{
	char *content = NULL;
	char password[64] = {0};
	char error_string[MAX_STRING_LEN] = {0};
	char certname[MAX_CERTIFICATE_LENGTH] = {0};

	// Check the Server IP, the return value must not be freed.
	content = (char *)gtk_entry_get_text((GtkEntry *)gwEntry);	
	if (content) {
		strncpy(Inf.serverIPAddr, content, MAX_STRING_LEN - 1);
		if (!getIPAddrFromGatewayDnsName(&Inf)) {
			plog(LLV_ERROR, NULL, NULL,"IP address is incorrect\n");
			return -1;
		}
	} else {
		show_dialog_message(errString(ENTER_IP, error_string));
		return -1;
	}

	// Get and check certificate, the return value need be freed.
	content = (char *)get_active_text_from_combobox((GtkComboBox *)auth1Combo);
	if ((strlen(content) + strlen(Inf.pfx_file_path)) >= MAX_CERTIFICATE_LENGTH) {
		show_dialog_message(errString(CERT_TOO_LENGTHY, error_string));
		return -1;
	}

	snprintf(certname, MAX_CERTIFICATE_LENGTH, "%s%s", Inf.pfx_file_path, content);
	// need to free
	if (content) {
		free (content);
		content = NULL;
	}

	// Get password
	strcpy(password, (char *)gtk_entry_get_text(GTK_ENTRY(auth2Entry)));
	if (password[0] == '\0') {
		show_dialog_message(errString(ENTER_PASSWORD, error_string));
		return -1;
	}

	// Extract the Certificate
	if (vpnExtCerts(certname, password)) {
		show_dialog_message(errString(CERT_EXTRACTION_FAILED, error_string));
		return -1;
	}

	getsourceip(&Inf);

	// Get the profile's name, the return value need be freed.
	content = (char *)get_active_text_from_combobox((GtkComboBox *)profileCombo);
	snprintf(Inf.selectedProfile, MAX_STRING_LEN,
			"%sprofile_%s.prf", Inf.profile_path, content);

	strcpy(Inf.selectedProfileFile, content);
	Inf.withProfileFile = 1;

	// need to free
	if (content) {
		free (content);
		content = NULL;
	}

	return 0;
}


int getAndValidateField_for_Plugin_Connect(void)
{
	char *serverip;
	char temp1[256];
	char *profile;

	serverip = (char *)gtk_entry_get_text((GtkEntry *)gwEntry);	
	if (serverip) {
		strcpy(Inf.serverIPAddr, serverip);
		if (!getIPAddrFromGatewayDnsName(&Inf)) {
			plog(LLV_ERROR, NULL, NULL,"IP address is incorrect\n");
			return -1;
		}
	}
	getsourceip(&Inf);	

	profile = (char *)get_active_text_from_combobox((GtkComboBox *)profileCombo);

	sprintf(temp1,"%sprofile_%s.prf",Inf.profile_path,profile);

	strcpy(Inf.selectedProfile, temp1);
	strcpy(Inf.selectedProfileFile, profile);
	Inf.withProfileFile = 1;

	if (profile) {
		free(profile);
		profile = NULL;
	}

	return 0;
}

//int check_server_ip()
	
//int printf_ph1Config_to_racoon_conf(FILE *fp)

//int printf_ph2Config_to_racoon_conf(FILE *fp)

//combostring has to be freed by the caller
char * get_active_text_from_combobox(GtkComboBox *combobox) 
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	char *comboString = NULL;
	
	model = gtk_combo_box_get_model (combobox);
	if (gtk_combo_box_get_active_iter (combobox, &iter)) 
	{
		gtk_tree_model_get (model, &iter, 0, &comboString, -1);
	}
	
	return comboString;
	
}

//int parse_profile_to_racoon_conf_buf(void)

//int writeRacoonConfFile(void)

//int writeGenericRacoonConfFile(void)

//int connectToServer(void)

//int sendMessage(int sock,unsigned short msgType)

//int receiveMessage(int sock, char **outbuf, int *outbuflen,time_t starttime )

void setConnStatus(int state)
{
	
	switch(state)
	{
		case IKE_CONN_IN_PROGRESS:
			gtk_widget_show(connPanelVBox);
			gtk_widget_set_sensitive((GtkWidget *)gwMaintable, FALSE);
			gtk_widget_set_sensitive((GtkWidget *)mainConnectBtn, FALSE);
			gtk_widget_set_sensitive((GtkWidget *)connPanelVBox, TRUE);
			gtk_notebook_set_current_page((GtkNotebook *)mainNotebook, 1);
			gtk_label_set_text(GTK_LABEL(connLabel), "Connection in progress ..");
			
		break;
		
		default:
		break;
	}
	return;
}

//int startEventPoll(void)

//int receiveEvents(void)

char *saddr2str(const struct sockaddr *saddr)
{
	static char buf[NI_MAXHOST + NI_MAXSERV + 10];
	char addr[NI_MAXHOST], port[NI_MAXSERV];

	if (saddr == NULL)
		return NULL;

	if (saddr->sa_family == AF_UNSPEC)
		snprintf (buf, sizeof(buf), "%s", "anonymous");
	else {
		GETNAMEINFO(saddr, addr, port);
		snprintf(buf, sizeof(buf), "%s[%s]", addr, port);
	}

	return buf;
}

//void writeSuccessfulProfile(void)

void restoreGatewayPanel(void)
{
	Inf.keepMainWindow = 1;
	Inf.runEventPoll = 0;

	if(Inf.connInProgress)
	{
		Inf.connInProgress = FALSE;
		disconnectServer(&Inf, 1);
	}

	gtk_widget_set_sensitive((GtkWidget *)gwMaintable, TRUE);
        gtk_widget_show(mainWindowHbox);
        gtk_notebook_set_current_page((GtkNotebook *)mainNotebook, 0);
	gtk_widget_set_sensitive(mainConnectBtn, TRUE);
	gtk_widget_hide(connPanelVBox);

  	return;
}

void activateConnDetailsTable(void)
{
	connectedTime = time(NULL);
	gtk_widget_show(connDetailsTable);	
	gtk_label_set_text(GTK_LABEL(connIPAddressLabel), Inf.serverIPAddr);
	return;
}

void updateUptime(void)
{
	char timestring[128];
	int days = 0, hours = 0, minutes = 0, seconds = 0;
	int _d = 24*60*60;
	int _h = 60*60;
	int _m = 60;

	time_t t = time(NULL) - connectedTime;

	days = t/_d;
	t = t%_d;

	hours = t/_h;
	t = t%_h;

	minutes = t/_m;
	t = t%_m;

	seconds = t;
	sprintf(timestring, "%d %.2d:%.2d:%.2d", days, hours, minutes, seconds);
	gtk_label_set_text(GTK_LABEL(connUptimeLabel), timestring);
	return;
}

void print_evt(char *buf, int len)
{
	struct evtdump *evtdump = (struct evtdump *)buf;
	int i;
	char *srcstr;
	char *dststr;
	char labeltext[128];
	char src[64], dst[64];
	char error_string[MAX_STRING_LEN] = {0};
	
	for (i = 0; evtmsg[i].msg; i++)
		if (evtmsg[i].type == evtdump->type)
			break;				
	
	if (evtmsg[i].msg == NULL) 
	{
		plog(LLV_INFO, NULL, NULL,"Event %d: \n", evtdump->type);
		sprintf(labeltext,"Event %d: ", evtdump->type); 
		gtk_label_set_text(GTK_LABEL(connStatusLabel), labeltext);
	}
	else
	{
		plog(LLV_INFO, NULL, NULL,"%s : \n", evtmsg[i].msg);
		sprintf(labeltext,"%s ", evtmsg[i].msg); 
		gtk_label_set_text(GTK_LABEL(connStatusLabel), labeltext);
	}
	if(evtdump->type == EVTT_ISAKMP_CFG_DONE)
	{
		if(Inf.plugin_state_notification)
			Inf.plugin_state_notification(evtdump->type);
	}
	
	//Do this only once
	if(!Inf.connected)
	{
		if(( evtdump->type == EVTT_PHASE1_UP) && !Inf.plugin)
		{
			setFieldsSentitivities(AFTER_CONNECT_SUCCESS);
			gtk_label_set_text(GTK_LABEL(connLabel), _("Connected"));
			writeSuccessfulProfile(&Inf, 1);
			Inf.connected = 1;
			activateConnDetailsTable();
		}

		if(( evtdump->type == EVTT_PHASE2_UP) && Inf.plugin)
		{
			setFieldsSentitivities(AFTER_CONNECT_SUCCESS);
			gtk_label_set_text(GTK_LABEL(connLabel), _("Connected"));
			writeSuccessfulProfile(&Inf, 1);
			Inf.connected = 1;
			activateConnDetailsTable();
		}

		if(( evtdump->type == EVTT_XAUTH_FAILED) && Inf.plugin)
		{
			gtk_label_set_text(GTK_LABEL(connLabel), _("Authentication Failed"));
			Inf.connected = 0;
			restoreGatewayPanel();
			show_dialog_message(errString(AUTHENTICATION_FAILED, error_string));
		}


	}

	if(( evtdump->type == EVTT_PEER_NO_RESPONSE) && Inf.plugin)
	{
		gtk_label_set_text(GTK_LABEL(connLabel), _("Gateway not responding"));
		Inf.runEventPoll = 0;
		show_dialog_message(errString(GATEWAY_NOT_RESPONDING, error_string));
		disconnectServer(&Inf, 1);
	}
		
	if ((srcstr = saddr2str((struct sockaddr *)&evtdump->src)) == NULL)
		sprintf(src,"%s", "unknown");
	else 
		sprintf(src, "%s", srcstr);
		
	if ((dststr = saddr2str((struct sockaddr *)&evtdump->dst)) == NULL)
		sprintf(dst,"%s", "unknown");
	else 
		sprintf(dst, "%s", dststr);

	plog(LLV_INFO, NULL, NULL, "%s -> %s\n", srcstr, dststr);
	return ;
}

//int recvEventReply(void)

int setFieldsSentitivities(int stage)
{

	switch(stage)
	{
		case AFTER_CONNECT_SUCCESS:
			gtk_widget_set_sensitive(mainConnectBtn, FALSE);
			gtk_widget_set_sensitive(mainCancelBtn, FALSE);
			gtk_widget_show(mainDisconnectBtn);
			gtk_widget_set_sensitive(mainDisconnectBtn, TRUE);
			
		break;
		
		case AFTER_CONNECT_FAILURE_RETRY:
		
		break;
		
		default:
		break;
	}
	return 0;
}

//int disconnectServer()

//int isFileExist(char *string)

#if 0
int getip( const char *destip, char *srcip, char *srcif, char *errstring){

	char *tmpfile=".tmp",*tmperrfile=".tmperr";
	
	if(isFileExist("/sbin/ip")!=0){
//		return VPNC_ERR_GUICLI_IPROUTE_MISSING;
		return -1;
	}
	
	
	if((fork())==0){//child
		int fd=creat(tmpfile,S_IRWXU);
		dup2(fd,fileno(stdout));	
		int errfd=creat(tmperrfile,S_IRWXU);
		dup2(errfd,fileno(stderr));	
		execl("/sbin/ip","ip","route","get",destip, NULL);
		close(fd);
		close(errfd);
	}
	else{
		int status;
		wait(&status);
	}

	if(isFileExist(tmperrfile)==0){ //file exusts => error 
		FILE *fp=fopen(tmperrfile,"r");
		if(fp==NULL){
			remove(tmpfile);
			remove(tmperrfile);
			return -1;
		}
		fscanf(fp,"%[^\n]",errstring);
		fclose(fp);	
		remove(tmpfile);
		remove(tmperrfile);
		return -2;
		//return VPNC_ERR_GUICLI_IPADDRESS_NOTRESOLVED;
	}

	char temp[20];
	int i;

	FILE *fp=fopen(".tmp","r");
	if(fp==NULL){
		remove(tmpfile);
		remove(tmperrfile);
		return -1;
	}

	
	for(i=0 ; ;i++){	
		
		if(fscanf(fp,"%s ",temp)!=1)
			break;
		if(strcmp(temp,"dev")==0){
			fscanf(fp,"%s ",temp);
			i++;
			strcpy(srcif,temp);
		}
		if(strcmp(temp,"src")==0){
			fscanf(fp,"%s ",temp);
			i++;
			strcpy(srcip,temp);
		}
			
	}
	
	fclose(fp);		

	remove(tmpfile);
	remove(tmperrfile);
	return 0;
}
#endif

//int getsourceip(void)

void removeCurrentProfile(void)
{
	char *profileName = NULL;
	char fileName[256] = {0};
		
	profileName = (char *)gtk_entry_get_text((GtkEntry *)pmprofileNameEntry);
	
	sprintf(fileName,"%sprofile_%s.prf",Inf.profile_path, profileName);
	if(!isFileExist(fileName)) //Remove 
	{
		remove(fileName);
		gtk_widget_set_sensitive(pmSavBtn, FALSE);
		gtk_widget_set_sensitive(pmAddBtn, TRUE);
		gtk_widget_set_sensitive(pmremBtn, FALSE);
		updatePmProfileList();
		on_pmprofileCombo_changed((GtkComboBox *)pmprofileCombo, NULL);
		
	}

	return;
}
int writePhase1PoliciesToFile(xmlNode *policy_node)
{
	xmlNodePtr childptr = NULL, proposalptr = NULL, entryptr = NULL;
	
	childptr=xmlNewChild(policy_node,NULL,(const xmlChar *)"phase1", NULL);
	proposalptr=xmlNewChild(childptr,NULL,(const xmlChar *)"proposals", NULL);
	entryptr=xmlNewChild(proposalptr,NULL,(const xmlChar *)"entry", NULL);

	xmlNewProp(entryptr,
                   (const xmlChar *)"mode",
                   (const xmlChar*) ui_helper_get_exchange_mode_text ());

	xmlNewProp(entryptr,
                   (const xmlChar *) "dhgroup",
                   (const xmlChar *) ui_helper_get_dh_group ());

	xmlNewProp(entryptr,
                   (const xmlChar *) "authmethod",
                   (const xmlChar *) ui_helper_get_authmethod_text ());

	return 0;
}

/* Cause the config mode between phase1 and phase2, we used phase15 */
int writePhase15PoliciesToFile(xmlNode *policy_node)
{
	xmlNodePtr childptr = NULL, entryptr = NULL;

	childptr = xmlNewChild(policy_node,
		   	NULL,
		   	(const xmlChar *)"phase_config",
		   	NULL);
	entryptr = xmlNewChild(childptr,
		   	NULL,
		   	(const xmlChar *)"entry",
		   	NULL);

	xmlNewProp(entryptr,
			(const xmlChar *) "nosplittunnel",
			(const xmlChar *) ui_helper_get_split_tunnel ());
	return 0;
}

int writePhase2ProposalsToFile(xmlNode *policy_node)
{
	xmlNodePtr proposalptr = NULL, entryptr = NULL;
        const char * pfs_group;
	
	proposalptr=xmlNewChild(policy_node,NULL,(const xmlChar *)"proposals", NULL);
	
	entryptr=xmlNewChild(proposalptr,NULL,(const xmlChar *)"entry", NULL);

	pfs_group =  ui_helper_get_pfs_group ();
	
	xmlNewProp(entryptr, (const xmlChar *)"pfsgroup", (const xmlChar *) pfs_group);

	return 0;
}

int writeCurrentProfileToFile()
{
	char *profileName = NULL;;
	char *gatewayip = NULL;
	char *gatewayType = NULL;
	char *authentication_type = NULL;
	char *cert = NULL;
	char fileName[256] = {0};
	int i, len;
	
	xmlNodePtr childptr, policyptr = NULL;
	xmlNodePtr root_node = NULL;
	xmlDocPtr doc;

	extern int h_errno;
	struct 	hostent *gateway_info;
	char error_string[MAX_STRING_LEN] = {0};
		
	profileName = (char *)gtk_entry_get_text((GtkEntry *)pmprofileNameEntry);
	len = strlen(profileName);
	if(len == 0)
	{
		show_dialog_message(errString(INVALID_PROFILE_NAME, error_string));
		return -1;
	}
	for(i = 0; i< len; i++)
	{
		if(profileName[i] == ' ')
			profileName[i] = '_';
	}
	gatewayip = (char *)gtk_entry_get_text((GtkEntry *)pmGwEntry);
	gatewayType = get_active_text_from_combobox((GtkComboBox *)pmgwtypeCombo);
	authentication_type = get_active_text_from_combobox((GtkComboBox *)pmauthtypeCombo);
	cert = get_active_text_from_combobox((GtkComboBox *)pmauthCombo);

	sprintf(fileName,"%sprofile_%s.prf",Inf.profile_path, profileName);

	gateway_info = gethostbyname(gatewayip);
	if(gateway_info == NULL) 
	{
		switch(h_errno) 
		{
			case NO_ADDRESS	    :
			case HOST_NOT_FOUND :
			show_dialog_message(errString(INVALID_GW_IP, error_string));
			return -1;	
		}
	}
	
	if(!isFileExist(fileName)) //Remove and rewrite it 
	{
		remove(fileName);
	}
	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "profile");
	xmlDocSetRootElement(doc, root_node);
	
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);
	
	
	xmlNewProp(root,(const xmlChar *)"name",(const xmlChar *) profileName);
	if(pmPluginActive)
	{
		char vfile[256];
		
		strcpy(vfile, VENDOR_PROFILE_PREFIX);
		strcat(vfile, profileName);
		strcat(vfile, ".prf");
		childptr=xmlNewTextChild(root,NULL,(const xmlChar *)"vendor",(const xmlChar *)vfile);
		
		strcpy(vfile, Inf.userHome);
		strcat(vfile, VENDOR_FILE);
		strcat(vfile, profileName);
		strcat(vfile, ".prf");
		if(Inf.plugin_pm_write)
		{
			if(Inf.plugin_pm_write(vfile, gatewayip))
			{
				show_dialog_message(errString(INVALID_PROFILE_AUTH_DETAILS, error_string));
			return -1;
			}
			
		}

		unloadmodule();
		pmPluginActive = 0;
	}
	childptr=xmlNewTextChild(root,NULL,(const xmlChar *)"gateway_ip",(const xmlChar *)gatewayip);
	childptr=xmlNewTextChild(root,NULL,(const xmlChar *)"gateway_type",(const xmlChar *)gatewayType);
	if(strcmp(authentication_type, "X.509 Certificate") == 0)
		childptr=xmlNewTextChild(root,NULL,(const xmlChar *)"certificate",(const xmlChar *)cert);
	
	policyptr=xmlNewChild(root,NULL,(const xmlChar *)"policies", NULL);
	writePhase1PoliciesToFile(policyptr);	
	/* Cause the config mode between phase1 and phase2, we used phase15 */
	writePhase15PoliciesToFile (policyptr);
	writePhase2PoliciesToFile(policyptr);	
	
	xmlKeepBlanksDefault(0);
	xmlSaveFormatFile(fileName,doc,1);
	xmlFreeDoc(doc);

	profileName = NULL;;
	gatewayip = NULL;
	cert = NULL;
	return 0;
}

void setpmsensitivities(int state)
{
	switch(state)
	{
		case	PM_INITIAL: 
			gtk_widget_set_sensitive(pmremBtn, FALSE);
			gtk_widget_set_sensitive(pmAddBtn, TRUE);
			gtk_widget_set_sensitive(pmSavBtn, FALSE);
			gtk_widget_set_sensitive(pmauthenticateCombo,TRUE);
			gtk_widget_hide(pmAuthframe);
			gtk_widget_hide(pmauthenticateLabel);
			gtk_widget_hide(pmauthenticateCombo);
		break;

		case	PM_CHOOSE_PROFILE:
			gtk_widget_hide(pmAuthframe);
			gtk_widget_hide(pmauthenticateLabel);
			gtk_widget_hide(pmauthenticateCombo);
		break;
		
		case	PM_BEFORE_LOAD_PROFILE:
			gtk_widget_set_sensitive(pmremBtn, TRUE);
			gtk_widget_set_sensitive(pmAddBtn, TRUE);
			gtk_widget_set_sensitive(pmSavBtn, TRUE);
			gtk_widget_set_sensitive(pmauthtypeCombo, TRUE);
			gtk_button_set_label((GtkButton *)pmCancelBtn, "Cancel");
			if(pmPluginActive == 1)
			{
				unloadmodule();
				pmPluginActive = 0;
			}
			gtk_combo_box_set_active((GtkComboBox*)pmgwtypeCombo, 0);
			gtk_combo_box_set_active((GtkComboBox*)pmauthtypeCombo, 0);
		break;
		
		case	PM_ADD_BTN_CLICKED:
				
				gtk_notebook_set_current_page((GtkNotebook *)pmNotebook, 0);
				gtk_widget_hide(pmAuthframe);
				gtk_widget_hide(pmauthenticateLabel);
				gtk_widget_hide(pmauthenticateCombo);
				gtk_widget_set_sensitive(pmAddBtn, FALSE);
				gtk_widget_set_sensitive(pmprofileNameEntry, TRUE);
				gtk_entry_set_text((GtkEntry *)pmprofileNameEntry, "");
				gtk_entry_set_text((GtkEntry *)pmGwEntry, "");
				gtk_combo_box_set_active((GtkComboBox *)pmgwtypeCombo,0);
				gtk_combo_box_set_active((GtkComboBox *)pmauthtypeCombo,0);
				gtk_combo_box_set_active((GtkComboBox *)pmauthenticateCombo,0);	
				gtk_combo_box_set_active((GtkComboBox *)pmprofileCombo,0);	
				gtk_widget_set_sensitive(pmremBtn, FALSE);
				gtk_button_set_label((GtkButton *)pmCancelBtn, "Cancel");
			
                                /*gtk_widget_set_sensitive(pmPh1ModeCombo, TRUE);*/
				gtk_widget_set_sensitive(pmauthtypeCombo, TRUE);
			        gtk_combo_box_set_active((GtkComboBox *)pmPh1DhCombo, 1);

                                gtk_combo_box_set_active((GtkComboBox *)pmPh1ModeCombo, 1);

			        gtk_combo_box_set_active((GtkComboBox *)pmPh2DhCombo, 1);


		break;
		
		case	PM_ADD_BTN_FINISHED:
			
		break;
		
		case	PM_SAVE_BTN_CLICKED:
		break;
		
		case	PM_SAVE_BTN_FINISHED:
			gtk_widget_set_sensitive(pmSavBtn, FALSE);
			gtk_widget_set_sensitive(pmAddBtn, TRUE);
			gtk_widget_set_sensitive(pmremBtn, FALSE);
			gtk_button_set_label((GtkButton *)pmCancelBtn, "Done");
			gtk_combo_box_set_active((GtkComboBox *)pmprofileCombo,0);
		break;
		
		case	PM_REM_BTN_CLICKED:
			gtk_button_set_label((GtkButton *)pmCancelBtn, "Done");
			gtk_combo_box_set_active((GtkComboBox *)pmprofileCombo,0);	
		break;
		
		case	PM_REM_BTN_FINISHED:
		break;
		
		default:
		break;
	}
	return;
}
//int copyph2PoliciesIntobuffer(char *selectedProfile, char *currptr)

//int ph1ModeValue(char *buffer)

//int ph1EncValue(char *buffer)

//int ph1DhValue(char *buffer)

//int ph1AuthValue(char *buffer)

//int ph1HashValue(char *buffer)

//int ph2EncValue(char *buffer)

//int ph2DhValue(char *buffer)

//int ph2HashValue(char *buffer)


int sendPluginMessageToAdminPort(char *sendBuf, size_t bufLen)
{
	size_t sendLen = 0;
	int ret = 0;
	char *outbuf=NULL;
	int outbuflen=0;
	char error_string[MAX_STRING_LEN] = {0};


	if((Inf.sockfd=initSocket())<0){
		show_dialog_message(errString(RACOON_CONNECT_FAILURE, error_string));
		return -1;
	}

	sendLen = send(Inf.sockfd, sendBuf,bufLen,0);
	if(sendLen)
		plog(LLV_INFO, NULL, NULL,"Successfully sent plugin message to admin port\n");
	else
		plog(LLV_ERROR, NULL, NULL,"Failed to send plugin message to admin port");


	time_t t=time(NULL);

	while(t+TIMEOUTINSECONDS > time(NULL))
	{

		if((ret=receiveMessage(&Inf,&outbuf,&outbuflen,t))<0)
		{ //To free outbuf.
			if(outbuf)
				free(outbuf);
			if(ret==-1)
				//show_dialog_message("Error in receiving the message from Gateway ");
				show_dialog_message(errString(FAILED_TO_RECEIVE_FROM_GATEWAY, error_string));
			if(ret==-2){
				//show_dialog_message("TimeOut in Receiving the Message .. ");
				show_dialog_message(errString(FAILED_TO_RECEIVE_FROM_GATEWAY, error_string));
				return ret ;
			}

			return -1;
		}
		else
		{
			plog(LLV_INFO, NULL, NULL,"Received response from admin port\n");
			if(Inf.plugin_admin_port_parse_message)
			{
				Inf.plugin_admin_port_parse_message(outbuf);
			}
			free(outbuf);
			return 0;
		}
	}


	return 0;
}


/*int convertMaskToLength(unsigned int mask)
{
	int length = 0, i = 0;
	unsigned int testbit = 0x0001;
	
	while(i < 32)
	{	
		if(htonl(mask) & testbit)
			break;
		testbit <<= 1;
		length++;
		i++;
	}
	return (32 - length);
}*/

//int loadmodule(const char *file_name)

//int unloadmodule(void)
/*
void tpike_guihook_pm_display (int (*f)(char *))
{
	Inf.plugin_pm_display = f;
	return;
}

void tpike_guihook_pm_write (int (*f)(char *))
{
	Inf.plugin_pm_write = f;
	return;
}

void tpike_guihook_pm_load_vendorprofile (int (*f)(char *))
{
	Inf.plugin_pm_load_vendorProfile = f;
	return;
}

void tpike_guihook_load_vendorprofile (int (*f)(char *))
{
	Inf.plugin_load_vendorProfile = f;
	return;
}

void tpike_guihook_connect (int (*f)(char * ))
{
	Inf.plugin_connect = f;
}

void tpike_guiunhook_connect (void)
{
	Inf.plugin_connect = NULL;
	return;
}

void tpike_guihook_ph1_config (int (*f)(char * ))
{
	Inf.plugin_ph1_config = f;
	return;
}

void tpike_guihook_ph1_proposal (int (*f)(char * ))
{
	Inf.plugin_ph1_proposal = f;
	return;
}
void tpike_guihook_disconnect (int (*f)(char * ))
{
	Inf.plugin_disconnect = f;
	return;
}
void tpike_guihook_state_notification (void (*f)(int ))
{
	Inf.plugin_state_notification = f;
	return;
}

void tpike_guihook_admin_port_parse_message (int (*f)(char * ))
{
	Inf.plugin_admin_port_parse_message = f;
	return;
}

void tpike_guihook_racoon_conf_write (int (*f) (char *))
{
	Inf.plugin_racoon_conf_write= f;
	return;
}
void tpike_guihook_profile_update (int (*f) (char *))
{
	Inf.plugin_update_profile = f;
	return;
}
*/

/*
void register_pm_display_callback(void (*f)(char *))
{
	Inf.plugin_pm_display = f;
	return;
}

void register_pm_write_callback(int (*f)(char *))
{
	Inf.plugin_pm_write = f;
	return;
}

void register_pm_load_vendorProfile_callback(void (*f)(char *))
{
	Inf.plugin_pm_load_vendorProfile = f;
	return;
}

void register_load_vendorProfile_callback(void (*f)(char *))
{
	Inf.plugin_load_vendorProfile = f;
	return;
}

void register_connect_callback(int (*f)(char * ))
{
	Inf.plugin_connect = f;
	return;
}

void deregister_connect_callback(void)
{
	Inf.plugin_connect = NULL;
	return;
}

void register_ph1_config_callback(int (*f)(char * ))
{
	Inf.plugin_ph1_config = f;
	return;
}

void register_ph1_proposal_callback(int (*f)(char * ))
{
	Inf.plugin_ph1_proposal = f;
	return;
}
void register_disconnect_callback(int (*f)(char * ))
{
	Inf.plugin_disconnect = f;
	return;
}
void register_state_notification_callback(void (*f)(int ))
{
	Inf.plugin_state_notification = f;
	return;
}

void register_admin_port_parse_message_callback(int (*f)(char * ))
{
	Inf.plugin_admin_port_parse_message = f;
	return;
}

void register_racoon_conf_write_callback(int (*f) (char *))
{
	Inf.plugin_racoon_conf_write = f;
	return;
}
void register_profile_update_callback(int (*f) (char *))
{
	Inf.plugin_update_profile = f;
	return;
}

*/
//void setUserEnv(void)

//void loadLastSuccessfulProfile(void)

void set_missing_mnemonics(void)
{
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmProfileLabel), pmprofileCombo);
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmProfileNameLabel), pmprofileNameEntry);
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmGwTypeLabel), pmgwtypeCombo);
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmGwIP),pmGwEntry );
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmAuthenticateLabel), pmauthenticateCombo);
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmUserCertLabel), pmauthCombo);
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmPh1ModeLabel), pmPh1ModeCombo);
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmPh1DhLabel), pmPh1DhCombo);
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmPh2PfsLabel), pmPh2DhCombo);

	return;
}

//void copyProfiles(void)

void get_connect_client_sock( char* connect_client_sock)
{
	strcat(connect_client_sock , "/.turnpike/guiClient.sock");
}

void get_connect_client_event_poll_sock( char* connect_client_event_poll_sock)
{
	strcat(connect_client_event_poll_sock, "/.turnpike/guieventpoll.sock");
}

void printing_function (char* string)
{
	show_dialog_message(string);
}
  
void connecting_time_update (char* progressString)
{
	gtk_label_set_text(GTK_LABEL(connLabel), progressString);
}

void conection_status_update (char* labeltext)
{
	gtk_label_set_text(GTK_LABEL(connStatusLabel), labeltext);
	refresh();
}

void on_vpnlogin_destroy_mainWindow()
{
	on_vpnlogin_destroy((GtkObject *)mainWindow, NULL);
}

int loadmodule(const char *file_name) /*Needs to be Modified*/
{
	if (!g_module_supported()) 
	{
		plog(LLV_ERROR, NULL, NULL,"loadable modules not supported on this plaform\n");
		return -1;
	}

	if ((module = g_module_open(file_name, G_MODULE_BIND_LAZY)) == NULL)
	{
		plog(LLV_ERROR, NULL, NULL,"failed to load module %s: %s\n", file_name, g_module_error());
		return -1;
	}
	Inf.plugin = 1;
	return 0;
}

void cleanup_resources()
{
	if(Inf.plugin)
	{
		Inf.plugin_disconnect(NULL);
		unloadmodule();
	}
	remove(Inf.userCert);
	remove(Inf.userPvtKey);
	return;
}

int unloadmodule()
{
	if(module != NULL)
	{
		g_module_close(module);
		Inf.plugin = 0;
		module = NULL;
	}
	return 0;
}

void refresh_events()
{
        while (gtk_events_pending())
                gtk_main_iteration();
}
