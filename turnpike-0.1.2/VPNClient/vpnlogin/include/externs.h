
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

/* GTK headers */
#include <gtk/gtk.h>
#include <gmodule.h>

/* GUI headers */
#include "profile.h"
#include "utility.h"


extern GtkWidget *mainWindow ;
extern GtkWidget *mainNotebook ;
extern GtkWidget *gwMaintable ;
extern GtkWidget *profileLabel ;
extern GtkWidget *profileCombo ;
extern GtkWidget *gwtypeLabel ;
extern GtkWidget *gwtypeCombo ;
extern GtkWidget *gwLabel ;
extern GtkWidget *gwEntry ;
extern GtkWidget *authenticateLabel ;
extern GtkWidget *authenticateCombo ;
extern GtkWidget *authFrame ;
extern GtkWidget *authenticateHeadingLabel ;
extern GtkWidget *auth1label ;
extern GtkWidget *auth1Combo ;
extern GtkWidget *auth2Label ;
extern GtkWidget *auth2Entry ;
extern GtkWidget *dynamicsVbox;
extern GtkWidget *profileManagerVbox;
extern GtkWidget *profilePanel;
extern GtkWidget *mainWindowHbox;
extern GtkWidget *mainConnectBtn;
extern GtkWidget *mainCancelBtn;
extern GtkWidget *mainDisonnectBtn;
extern GtkWidget *mainHelpBtn;

//Profile Manager
extern GtkWidget *ph2treeview;
extern GtkWidget *addbtn;
extern GtkWidget *rembtn;
extern GtkWidget *pmprofileCombo ;
extern GtkWidget *pmNotebook ;
extern GtkWidget *pmprofileNameEntry;
extern GtkWidget *pmGwEntry;
extern GtkWidget *pmgwtypeCombo;
extern GtkWidget *pmauthtypeCombo;
extern GtkWidget *pmauthenticateCombo;
extern GtkWidget *pmauthenticateLabel;
extern GtkWidget *pmAuthframe;
extern GtkWidget *pmauthCombo;
extern GtkWidget *pmSavBtn;
extern GtkWidget *pmAddBtn;
extern GtkWidget *pmremBtn;
extern GtkWidget *pmCancelBtn;
extern GtkWidget *pmGeneralTable;

extern GtkWidget *pmPh1ModeCombo;
extern GtkWidget *pmPh1EncCombo;
extern GtkWidget *pmPh1HashCombo;
extern GtkWidget *pmPh1DhCombo;
extern GtkWidget *pmPh1AuthCombo;

extern GtkWidget *pmPh2EncCombo;
extern GtkWidget *pmPh2HashCombo;
extern GtkWidget *pmPh2DhCombo;
extern GtkWidget *pmPh2PfsCombo;
extern GtkWidget *pmSplitTunnelCheckBtn;

//Connection Panel
extern GtkWidget *connPanelVBox;
extern GtkWidget *connStatusLabel;
extern GtkWidget *connDetailsTable;
extern GtkWidget *connIPAddressLabel;
extern GtkWidget *connUptimeLabel;



extern char profile_files[MAX_PROFILES][MAX_PROFILE_FILENAME_LENGTH];
extern char certificates[MAX_CERTIFICATE][MAX_CERTIFICATE_LENGTH];
//extern char certname[MAX_CERTIFICATE_LENGTH];



extern int profileManagerActive;
//extern int mainWindowActive;
//extern int connInProgress;

extern int pmPluginActive;
//extern int gwType;
//extern char pluginBuf[];
//extern int pluginBufLen;
//extern char gwTypeStr[];
extern GModule* module;
//extern int guiplugin;
//extern char userHome[];
//extern char userCert[];
//extern char userPvtKey[];
//extern char PROFILE_PATH[];
//extern char GUI_CONNECT_CLIENT[];
//extern char GUI_CONNECT_CLIENT_EVENTPOLL[];
//extern char lastProfile[];
//extern char vendorProfile[];
extern char PLOG_FILE[];
//extern char errStr[];
//extern int keepMainWindow;
//extern int runEventPoll;
//char source_ip[MAX_GATEWAY_IP_LENGTH];
//extern char selectedProfile[];
//extern char selectedProfileFile[];
//extern time_t startTime;
extern time_t connectedTime;
//extern int connected ;
//extern GtkWidget *connLabel ;
//extern char nortelPlugin[];
void get_connect_client_sock( char* );
void get_connect_client_event_poll_sock( char* );
void print_evt(char *, int);
void connecting_time_update (char* );
void conection_status_update (char* );
void on_vpnlogin_destroy_mainWindow();
void printing_function(char*);
void updateUptime(void);

