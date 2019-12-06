
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


#ifndef __CLI_H__
#define __CLI_H__

#include "profile.h"
#include <libintl.h>

#define CONNECT         0x00000001
#define DISCONNECT      0x00000002
#define LIST            0x00000004
#define HELP            0x00000008
#define VERBOSE			0x00000010
#define CREATE_VENDOR_PROFILE   0x00000020

#define MAX_STRING_LEN  256
#define MAX_BUF_LEN     1024
#define MAX_PATH_LEN    512 
#define SMALL_STRING_LEN  32


#define IPV4_ADDR_LEN   32

#define _(str) gettext(str)

typedef struct cliinf{
    
    /* Flags Begin */
    unsigned long argumentMask;
    int isVerbose;
    char isStandardGateway;
    char isUserEnvSet;
	char withProfileFile;
    /* Flags End */
    
    /* Profile Related vars : Begin */
    char profileName[MAX_STRING_LEN];
    char profile_files[MAX_PROFILES][MAX_PROFILE_FILENAME_LENGTH];
    char serverIPAddr[MAX_STRING_LEN]; // of the selected profile 
    char sourceIPAddr[MAX_STRING_LEN]; // to reach the server ip of selected profile 
    char lastProfile[MAX_STRING_LEN]; // Last successful Profile
    char gatewayType[MAX_STRING_LEN]; 
    char vendorfile[MAX_STRING_LEN];
    /* Profile Related vars : End */
    
    /* Related to Standard Gateway Begin */
    char certFileName[MAX_STRING_LEN]; /* Will be undermined for Non-Standard Gateways  as of now */
    /* Related to Standard Gateway End */
    
    /* User Env vars : Begin */
    char profile_path[MAX_STRING_LEN] ;
    char vendor_profile_path[MAX_STRING_LEN];
    char userHome[MAX_STRING_LEN] ;
    char userCert[MAX_STRING_LEN] ;
    char userPvtKey[MAX_STRING_LEN] ;
    char pfx_file_path[MAX_STRING_LEN] ;
    char racoon_conf_file[MAX_STRING_LEN];
    char racoon_cert_path[MAX_STRING_LEN];
    char cli_connect_client[MAX_STRING_LEN];
    char cli_connect_client_eventpoll[MAX_STRING_LEN];
    /* User Env vars : End */
   
    /* For Racoon Admin Port : Begin*/
    int sockfd;
    int eventsockfd;
    int lastEvtRecvd;
    /* For Racoon Admin Port : End*/
	
	/* Plugin related vars : Begin */
	int cliplugin;		//Flag that denotes whether the plugin library is loaded
	void *so_handle;	//plugin library handle
	void *pluginInfo;
	
	/* Plugin function handlers */
	int (*plugin_get_privdata) (char *, void *); 
	int (*plugin_disconnect) (char *); 
	int (*plugin_cli_init) (void *, void **);
	int (*plugin_write_racoon_conf_for_reparse) (struct racoon_conf *, void *);
	int (*plugin_event_handler) (int, void *);
	int (*plugin_get_ikeplugin_lib_path)(char *);
	int (*plugin_update_profile)(char *);
    int (*plugin_create_vendor_profile)(char *);
	/* Plugin related vars : End */
	
	
}cliInf_t;


#endif
