
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

#ifndef __UTILITY_H__
#define __UTILITY_H__

#include <gtk/gtk.h>
#include <time.h>

#include "plog.h"
#include "vpncErrorHandling.h"
#include "guiErrors.h"
#include "profile.h"



#define IKE_CONN_IN_PROGRESS 0x0001 

#define MAX_CERTIFICATE 10
#define MAX_CERTIFICATE_LENGTH 80
#define MAX_GATEWAY_IP_LENGTH 16
//#define PFX_FILE_PATH "/etc/opt/novell/turnpike/usercerts/"
#define TURNPIKE_DIR "/.turnpike/"
#define PFX_FILE_PATH1 TURNPIKE_DIR"usercerts/"
#define VPNLOGIN_LOCK_FILE TURNPIKE_DIR"vpnlogin_lock"

#define VENDOR_FILE TURNPIKE_DIR"vendorprofiles/vendor_"
#define VENDOR_PROFILE_PREFIX "vendor_"
#define VENDOR_PROFILE_PATH1 TURNPIKE_DIR"vendorprofiles/"

//#define SYSTEM_PROFILE_PATH "/etc/opt/novell/turnpike/profiles/"
//#define SYSTEM_VENDOR_PROFILE_PATH "/etc/opt/novell/turnpike/vendorprofiles/"

#define PLOG_FILE1 TURNPIKE_DIR"log.txt"
//#define HELP_FILE "/opt/novell/turnpike/vpn_docbook/vpn_linux.xml"
#define TIMEOUTINSECONDS 30

# define refresh()\
		while (gtk_events_pending())\
			gtk_main_iteration();

#define MAX_BUFFER_SIZE 		2048
#define MAX_CONNECTION_TIMEOUT		300	//5 minutes 

#define NIFLAGS	(NI_NUMERICHOST | NI_NUMERICSERV)

#define CERTFILE	"usercert.pem"
#define	PVTKEYFILE	"userkeyunenc.pem"

#define RACOON_CERT_PATH1 TURNPIKE_DIR
#define USERCERT RACOON_CERT_PATH1 CERTFILE
#define USERPVTKEY RACOON_CERT_PATH1 PVTKEYFILE
#define CACERT	RACOON_CERT_PATH1"myCAfile.pem"
#define LASTPROFILE_FILE TURNPIKE_DIR"lastProfile.xml"




# define GUI_CONNECT_CLIENT1 TURNPIKE_DIR"guiClient.sock"
# define GUI_CONNECT_CLIENT_EVENTPOLL1 TURNPIKE_DIR"guieventpoll.sock"
#define RACOON_CONF_FILE1 TURNPIKE_DIR"racoon.conf"



#define BEFORE_CONNECT			1
#define AFTER_CONNECT_SUCCESS		2
#define	AFTER_CONNECT_FAILURE_RETRY	3
#define	AFTER_CONNECT_FAILURE_EXIT	4


/* Turnpike Interface information */
#define TURNPIKE_INTERFACE_VERSION 1


/* function prototypes */
//void cleanup_resources(void);
int getWidgetPointers(GtkWidget       *widget);
void setInitialSensitivities(void);
//int dir_check(char *string);
//int file_check(char *string);
//int get_dir_list(char *directory,char array[][MAX_PROFILE_FILENAME_LENGTH],char *ext);

int loadProfile(char *filename);
void do_profile_manager(void);
int setCertificatesOnCombo(char *profileCert);
void show_dialog_message(char *string);
int getAndValidateFields_for_Connect(void);
//int check_server_ip(void);
//int receiveMessage(int sock, char **outbuf, int *outbuflen,time_t starttime );
//int sendMessage(int sock,unsigned short msgType);
//int startEventPoll(void);
int setFieldsSentitivities(int stage);
//int disconnectServer(void);
void on_pmprofileCombo_changed                (GtkComboBox     *combobox,
                                        gpointer         user_data);
void on_pmauthCombo_changed                  (GtkComboBox     *combobox,
                                        gpointer         user_data);

int writeCurrentProfileToFile(void);
void removeCurrentProfile(void);
void setpmsensitivities(int);
//int copyph2PoliciesIntobuffer(char *selectedProfile, char *currptr);
char * get_active_text_from_combobox(GtkComboBox *);
//int loadmodule(const char *modulefile);
void test_module(void);
/*int (*plugin_connect_callback) (char *); 
int (*plugin_ph1_config_callback) (char *); 
int (*plugin_ph1_proposal_callback) (char *); 
void (*plugin_pm_display_callback)(char *);
int (*plugin_pm_write_callback)(char *);
void (*plugin_pm_load_vendorProfile_callback)(char *);
void (*plugin_load_vendorProfile_callback)(char *);
int (*plugin_racoon_conf_write_callback)(char *);*/


int getAndValidateField_for_Plugin_Connect(void);
//void setUserEnv(void);
//void loadLastSuccessfulProfile(void);
void set_missing_mnemonics(void);
//int isFileExist(char *);
//void copyProfiles(void);

#define WIDGET_MAIN_WINDOW		"vpnlogin"
#define WIDGET_MAIN_NOTEBOOK		"mainNotebook"
#define WIDGET_GW_MAIN_TABLE		"gwMainTable"
#define WIDGET_GW_PROFILE_LABEL		"profileLabel"
#define WIDGET_GW_PROFILE_COMBO		"profileCombo"
#define WIDGET_GW_TYPE_LABEL		"gwtypeLabel"
#define WIDGET_GW_TYPE_COMBO		"gwtypeCombo"
#define WIDGET_GW_LABEL			"gwLabel"
#define WIDGET_GW_ENTRY			"gwEntry"
#define WIDGET_GW_AUTHENTICATE_LABEL	"authenticateLabel"
#define WIDGET_GW_AUTHENTICATE_COMBO	"authenticateCombo"
#define WIDGET_GW_AUTH_FRAME		"authFrame"
#define WIDGET_GW_AUTH_HEADING_LABEL	"authenticateHeadingLabel"
#define WIDGET_GW_AUTH1_LABEL		"auth1label"
#define WIDGET_GW_AUTH1COMBO		"auth1Combo"
#define WIDGET_GW_AUTH2LABEL		"auth2Label"
#define WIDGET_GW_AUTH2ENTRY		"auth2Entry"
#define WIDGET_MAIN_CONNECTBTN		"mainConnectBtn"
#define WIDGET_MAIN_CANCELBTN		"mainCancelBtn"
#define WIDGET_MAIN_DISCONNECTBTN	"mainDisconnectBtn"
#define WIDGET_MAIN_HELPBTN		"mainHelpBtn"





#define WIDGET_DYN_VBOX			"dynamicsVbox"


#define WIDGET_PROFILE_MGR_VBOX		"profileManagerVbox"
#define WIDGET_PROFILE_PANEL		"profilePanel"
#define WIDGET_MAIN_HBOX		"mainWindowHbox"

//Connection details panel
#define WIDGET_CONN_MAIN_VBOX		"connPanelVBox"
#define WIDGET_CONN_STATUS_LABEL	"connStatusLabel"
#define WIDGET_CONN_LABEL		"connLabel"
#define WIDGET_CONN_UPTIME_LABEL	"connUptime"
#define WIDGET_CONN_IPADDRESS_LABEL	"connIPAddress"
#define WIDGET_CONN_DETAILS_TABLE	"connDetailsTable"


//Profile Manager

#define WIDGET_PM_PH2_TREEVIEW		"ph2treeview"
#define WIDGET_PM_PH2_ADDBTN		"addbtn"
#define WIDGET_PM_PH2_REMBTN		"rembtn"
#define WIDGET_GW_PM_PROFILE_COMBO		"pmprofileCombo"
#define WIDGET_PM_NOTEBOOK		"pmNotebook"
#define WIDGET_PM_NAME_ENTRY		"pmprofileNameEntry"
#define WIDGET_PM_GW_ENTRY		"pmGwEntry"
#define WIDGET_PM_GW_TYPE		"pmgwtypeCombo"
#define WIDGET_PM_AUTH_TYPE		"pmauthtypeCombo"
#define WIDGET_PM_AUTH_COMBO		"pmauthenticateCombo"
#define WIDGET_PM_AUTH_LABEL		"pmAuthenticateLabel"
#define WIDGET_PM_AUTH_FRAME		"pmAuthframe"
#define WIDGET_PM_AUTH_COMBO1		"pmauthCombo"
#define WIDGET_PM_SAV_BTN		"pmSavBtn"
#define WIDGET_PM_ADD_BTN		"pmAddBtn"
#define WIDGET_PM_REM_BTN		"pmRembtn"
#define WIDGET_PM_CANCEL_BTN		"pmCancelBtn"
#define WIDGET_PM_GEN_TABLE		"pmGeneralTable"

#define WIDGET_PM_PH1_MODE_COMBO	"pmPh1ModeCombo"
#define WIDGET_PM_PH1_ENC_COMBO		"pmPh1EncCombo"
#define WIDGET_PM_PH1_HASH_COMBO	"pmPh1HashCombo"
#define WIDGET_PM_PH1_DH_COMBO		"pmPh1DhCombo"
#define WIDGET_PM_PH1_AUTH_COMBO	"pmPh1AuthCombo"

#define WIDGET_PM_PH2_ENC_COMBO		"pmPh2EncCombo"
#define WIDGET_PM_PH2_HASH_COMBO	"pmPh2HashCombo"
#define WIDGET_PM_PH2_DH_COMBO		"pmPh2DhCombo"
#define WIDGET_PM_NO_SPLITTUNNEL_CHECKBTN		"pmSplitTunnelCheckBtn"

#define WIDGET_PM_PROF_LABEL		"pmProfileLabel"
#define WIDGET_PM_PROF_NAME_LABEL	"pmProfileNameLabel"
#define WIDGET_PM_GWTYPE_LABEL		"pmGwTypeLabel"
#define WIDGET_PM_GWIP_LABEL		"pmGwIP"
#define WIDGET_PM_AUTHENTICATE_LABEL	"pmAuthenticateLabel"
#define WIDGET_PM_USER_CERT_LABEL	"pmUserCertLabel"
#define WIDGET_PM_PH1_MODE_LABEL	"pmPh1ModeLabel"
#define WIDGET_PM_PH1_ENC_LABEL		"pmPh1EncLabel"
#define WIDGET_PM_PH1_HASH_LABEL	"pmPh1HashLabel"
#define WIDGET_PM_PH1_DH_LABEL		"pmPh1DhLabel"
#define WIDGET_PM_PH1_AUTH_LABEL	"pmPh1AuthLabel"
#define WIDGET_PM_PH2_ENC_LABEL		"pmPh2EncLabel"
#define WIDGET_PM_PH2_HASH_LABEL	"pmPh2HashLabel"
#define WIDGET_PM_PH2_PFS_LABEL		"pmPh2PfsLabel"


//Sensitivity states

#define PM_INITIAL		0x0001
#define	PM_CHOOSE_PROFILE	0x0002
#define	PM_ADD_BTN_CLICKED	0x0003
#define	PM_ADD_BTN_FINISHED	0x0004
#define	PM_ADD_BTN_FAILED	0x0005
#define	PM_SAVE_BTN_CLICKED	0x0006
#define	PM_SAVE_BTN_FINISHED	0x0007
#define	PM_SAVE_BTN_FAILED	0x0008
#define	PM_REM_BTN_CLICKED	0x0009
#define	PM_REM_BTN_FINISHED	0x000A
#define PM_BEFORE_LOAD_PROFILE	0x000B



#define GW_TYPE_STANDARD_IPSEC	0x0001
#define GW_TYPE_NORTEL 		0x0002

#endif // __UTILITY_H__
