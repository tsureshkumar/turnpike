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


#ifndef __MY_UTILITY_H__
#define __MY_UTILITY_H__

#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include "plog.h"
#include "vpncErrorHandling.h"


#define CONNECT         0x00000001
#define DISCONNECT      0x00000002
#define LIST            0x00000004
#define HELP            0x00000008
#define VERBOSE			0x00000010
#define CREATE_VENDOR_PROFILE   0x00000020
#define DHGROUP			0x00000040
#define UPSCRIPT		0x00000080
#define ROUTES			0x00000160
#define PFSGROUP		0x00000320
#define NOSPLITTUNNEL	0x00000640

#define MAX_STRING_LEN  256
#define MAX_BUF_LEN     1024
#define MAX_PATH_LEN    512 
#define SMALL_STRING_LEN  32

#define IPV4_ADDR_LEN   32

#ifdef ENABLE_NLS
#  include <libintl.h>
#  undef _
#  define _(String) dgettext (PACKAGE, String)
#  ifdef gettext_noop
#    define N_(String) gettext_noop (String)
#  else
#    define N_(String) (String)
#  endif
#else
#  define textdomain(String) (String)
#  define gettext(String) (String)
#  define dgettext(Domain,Message) (Message)
#  define dcgettext(Domain,Message,Type) (Message)
#  define bindtextdomain(Domain,Directory) (Domain)
#  define _(String) (String)
#  define N_(String) (String)
#endif


#define IKE_CONN_IN_PROGRESS 0x0001 

#define MAX_CERTIFICATE 10
#define MAX_CERTIFICATE_LENGTH 80
#define MAX_GATEWAY_IP_LENGTH 16

#define TURNPIKE_DIR "/.turnpike/"
#define PFX_FILE_PATH1 TURNPIKE_DIR"usercerts/"
#define VPNLOGIN_LOCK_FILE TURNPIKE_DIR"vpnlogin_lock"

#define 	PROFILE_PATH1	TURNPIKE_DIR"profiles/"
#define	FILE_NOT_EXIST -1
#define 	FILE_EXIST 	0

#define VENDOR_FILE TURNPIKE_DIR"vendorprofiles/vendor_"
#define VENDOR_PROFILE_PREFIX "vendor_"
#define VENDOR_PROFILE_PATH1 TURNPIKE_DIR"vendorprofiles/"

#define CONFIG_PATH	"/etc/"
#define SYSTEM_PROFILE_PATH CONFIG_PATH"turnpike/profiles/"
#define SYSTEM_VENDOR_PROFILE_PATH CONFIG_PATH"turnpike/vendorprofiles/"

#define PLOG_FILE1 TURNPIKE_DIR"log.txt"
#define HELP_FILE CONFIG_PATH"turnpike/vpn_docbook/vpn_linux.xml"
#define TIMEOUTINSECONDS 30

/*# define refresh()\
		while (gtk_events_pending())\
			gtk_main_iteration();*/

#define MAX_BUFFER_SIZE 		2048
#define MAX_CONNECTION_TIMEOUT		300	//5 minutes 

#define NIFLAGS	(NI_NUMERICHOST | NI_NUMERICSERV)
#define GETNAMEINFO(x, y, z) \
do { \
	if (getnameinfo((x), 16, (y), sizeof(y), (z), sizeof(z), \
			NIFLAGS) != 0) { \
		if (y != NULL) \
			strncpy((y), "(invalid)", sizeof(y)); \
		if (z != NULL) \
			strncpy((z), "(invalid)", sizeof(z)); \
	} \
} while (0);

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
#define MAX_PROFILE_FILENAME_LENGTH	80
#define 	MAX_PROFILE_FILENAME_LENGTH 	80
#define 	MAX_PROFILES			16

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

#define MAX_ENC_TYPES 2
#define MAX_HASH_TYPES 2
#define MAX_MODE_TYPES 2
#define MAX_DH_TYPES 2
#define MAX_AUTH_TYPES 2 
#define MAX_PFS_TYPES 3 

#define CERTIFICATE 1
#define XAUTH 2

typedef int boolean_t;

struct racoon_conf;
struct ph1_config;
struct Routes
{
	char network[50];
	char mask[50];
	struct Routes* next;
};
typedef struct Interface
{
	/* Flags Begin */
	unsigned long argumentMask;
	int isVerbose;
	char isStandardGateway;
	char isUserEnvSet;
	char withProfileFile;
	char authentication_type;
	/* Flags End */

	/* Network Manager Related Variables : Begin */
	char upscript[MAX_PATH_LEN]; // Network Manager helper script
	/* Network Manager Related Variables : End */

	/* Profile Related vars : Begin */
	char profileName[MAX_STRING_LEN];
	char profile_files[MAX_PROFILES][MAX_PROFILE_FILENAME_LENGTH];
	char serverIPAddr[MAX_STRING_LEN]; // of the selected profile 
	char sourceIPAddr[MAX_STRING_LEN]; // to reach the server ip of selected profile 
	char lastProfile[MAX_STRING_LEN]; // Last successful Profile
	char gatewayType[MAX_STRING_LEN]; 
	char vendorfile[MAX_STRING_LEN];
	int dh_group;
	int pfs_group;
	int no_split_tunnel;
	/* Profile Related vars : End */
	
	/* Related to Standard Gateway Begin */
	char certFileName[MAX_STRING_LEN]; /* Will be undermined for Non-Standard Gateways  as of now */
	/* Related to Standard Gateway End */
	
	/* User Env vars : Begin */
	char profile_path[MAX_PATH_LEN] ;
	char vendor_profile_path[MAX_PATH_LEN];
	char userHome[MAX_PATH_LEN] ;
	char userCert[MAX_PATH_LEN] ;
	char userPvtKey[MAX_PATH_LEN] ;
	char pfx_file_path[MAX_PATH_LEN] ;
	char racoon_conf_file[MAX_PATH_LEN];
	char racoon_cert_path[MAX_PATH_LEN];
	char connect_client[MAX_STRING_LEN];
	char connect_client_eventpoll[MAX_STRING_LEN];
	/* User Env vars : End */
	
	/* For Racoon Admin Port : Begin*/
	int sockfd;
	int eventsockfd;
	int lastEvtRecvd;
    /* For Racoon Admin Port : End*/
	
	char selectedProfile[MAX_STRING_LEN] ;
	char selectedProfileFile[MAX_STRING_LEN] ;
	char errStr[MAX_STRING_LEN];
	time_t startTime;
	int connInProgress;
	int runEventPoll ;
	int connected ;
	int mainWindowActive ;
	int keepMainWindow;

	char pluginBuf[1024];
	int pluginBufLen;
	
	int plugin;
	void *so_handle;	//plugin library handle
	void *pluginInfo;
	struct Routes *network_mask_list;
	
	/* Plugin function handlers */
	int (*plugin_get_privdata) (char *, void *); 
	int (*plugin_disconnect) (char *); 
	int (*plugin_cli_init) (void *, void **);
	int (*plugin_write_racoon_conf_for_reparse) (struct racoon_conf *, void *);
	int (*plugin_event_handler) (int, void *);
	int (*plugin_get_ikeplugin_lib_path)(char *);
	int (*plugin_update_profile)(char *);
	int (*plugin_create_vendor_profile)(char *);

	void(*plugin_gui_init) ();
	size_t (*plugin_connect) (char *); 
	int (*plugin_ph1_config) (char *); 
	int (*plugin_ph1_proposal) (char *); 
	int (*plugin_pm_display)(char *);
	int (*plugin_pm_write)(char *, char*);
	int (*plugin_pm_load_vendorProfile)(char *);
	int (*plugin_load_vendorProfile)(char *);
	int (*plugin_racoon_conf_write)(char *);
	void (*plugin_state_notification)(int);
	int (*plugin_admin_port_parse_message) (char*);

	void (*get_connect_client_sock)(char*);
	void (*get_connect_client_event_poll_sock) (char*);
	void (*printing_function) (char*);
	void (*print_event) (char *, int);
	void (*connecting_time_update) (char*);
	void (*conection_status_update) (char*);
	void (*on_vpnlogin_destroy_mainWindow)();
	void (*refresh)();
	void (*updateUptime) ();
	void (*loadmodule)(char*);
	void (*unloadmodule)();
}Inf_t;

struct ph2enctypes 
{
        int value;
        char *string;
};

struct ph2hashtypes 
{
        int value;
        char *string;
};

struct ph2dhtypes 
{
        int value;
        char *string;
};

struct ph1enctypes 
{
        int value;
        char *string;
};

struct ph1hashtypes 
{
        int value;
        char *string;
};

struct ph1modetypes 
{
        int value;
        char *string;
};

struct ph1dhtypes 
{
        int value;
        char *string;
};

struct ph1authtypes 
{
        int value;
        char *string;
};

struct Evtmsg 
{
        int type;
        char *msg;
        enum { UNSPEC, ERROR, INFO } level;
};

typedef struct
{
	char filename[256];
	int nat_traversal;
	char serverIPAddr[64];
	char sourceIPAddr[64];
	char racoon_cert_path[256];
	struct 
	{
		char encalgo[64];
		char hashalgo[64];
		char authmethod[64];
		char dhgroup[64];
	} ph1_proposal;
	struct 
	{
		char encalgo[64];
		char hashalgo[64];
		char pfsgroup[64];
	} ph2_proposal;
} racoon_conf_info;

//racoon_conf_info rbuf;

#endif

int setUserEnv(Inf_t*);
void loadLastSuccessfulProfile(Inf_t*);
int dir_check(char *string);
int file_check(char *string);
int get_dir_list(char *directory,char array[][MAX_PROFILE_FILENAME_LENGTH],char *ext);
int isFileExist(char *string);
int getsourceip(Inf_t*);
int convertMaskToLength(unsigned int mask);
int get_dh_group_filled(Inf_t*);
int printf_ph1Config_to_racoon_conf(FILE *fp, Inf_t*);
int get_pfs_group_filled(Inf_t*);
int printf_ph2Config_to_racoon_conf(FILE *fp, Inf_t*);
int startEventPoll(Inf_t*, int);
int receiveEvents(Inf_t*);
int recvEventReply(Inf_t*);
int disconnectServer(Inf_t*, int);
int connectToServer(Inf_t*, int);
void copyProfiles(Inf_t*);
int receiveMessage(Inf_t*, char **outbuf, int *outbuflen,time_t starttime );
int sendMessage(Inf_t*, unsigned short msgType, int);
int writeRacoonConfFile(Inf_t*);
int writeGenericRacoonConfFile(Inf_t*);
int parse_profile_to_racoon_conf_buf(Inf_t* Inf_pointer);
int ph1ModeValue(char *buffer);
int ph1EncValue(char *buffer);
int ph1DhValue(char *buffer);
int ph1AuthValue(char *buffer);
int ph1HashValue(char *buffer);
int ph2EncValue(char *buffer);
int ph2DhValue(char *buffer);
int ph2HashValue(char *buffer);
int writeSuccessfulProfile(Inf_t*, int);
int copyph2PoliciesIntobuffer_no_profile(Inf_t*, char *currptr);
int copyph2PoliciesIntobuffer_with_profile(Inf_t*, char *selectedProfile, char *currptr);
int createPh1Conf(Inf_t*, struct ph1_config *ph1);
int createPh2Conf ( Inf_t*, struct racoon_conf *rc);
int create_rcbuf(Inf_t*, struct racoon_conf **rcbuf);
int write_ph1_proposal(FILE *fp, int);
int getIPAddrFromGatewayDnsName(Inf_t* Inf_pointer);
int get_network_mask(const char* mask, char* ip);
int fill_the_network_mask(char* source_addr, char* mask_for_the_source_addr);
extern int get_profile_list(char *directory,char array[][MAX_PROFILE_FILENAME_LENGTH],char *ext);

extern char errStr[];
extern in_addr_t server_addr;
extern in_addr_t source_addr;
