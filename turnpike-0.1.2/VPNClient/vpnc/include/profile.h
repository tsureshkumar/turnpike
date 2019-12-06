
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


#ifndef __CLI_PROFILE_H__
#define __CLI_PROFILE_H__
    
#include <stdio.h>
#include <sys/socket.h>
#include <sys/queue.h>

/* Racoon headers */
#include "racoon/oakley.h"
#include "racoon/evt.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"

/* cli headers  */
#include "racoonconf.h"

#define     TURNPIKE_DIR    "/.turnpike/"
#define     PFX_FILE_PATH1 TURNPIKE_DIR"usercerts/"
#define 	HOME_PROFILE_PATH		"turnpike/profiles/"
#define 	PROFILE_PATH1	TURNPIKE_DIR"profiles/"
#define		LAST_USED_PROFILE_FILE	"lastusedprofile"
#define		PROFILE_PREFIX		"profile_"

#define     VENDOR_FILE TURNPIKE_DIR"vendorprofiles/vendor_"
#define     VENDOR_PROFILE_PREFIX "vendor_"
#define     VENDOR_PROFILE_PATH1 TURNPIKE_DIR"vendorprofiles/"

//#define     SYSTEM_PROFILE_PATH "/etc/opt/novell/turnpike/profiles/"
//#define     SYSTEM_VENDOR_PROFILE_PATH "/etc/opt/novell/turnpike/vendorprofiles/"

//#define 	MAX_PROFILE_FILENAME_LENGTH 	80
#define 	MAX_PROFILES			16

#define		FILE_NOT_EXIST 		-1
#define 	FILE_EXIST 		0


#define CERTFILE	"usercert.pem"
#define	PVTKEYFILE	"userkeyunenc.pem"

#define RACOON_CERT_PATH1 TURNPIKE_DIR
#define USERCERT RACOON_CERT_PATH1 CERTFILE
#define USERPVTKEY RACOON_CERT_PATH1 PVTKEYFILE
#define CACERT	RACOON_CERT_PATH1"myCAfile.pem"
#define LASTPROFILE_FILE TURNPIKE_DIR"lastProfile.xml"


# define CLI_CONNECT_CLIENT1 TURNPIKE_DIR"cliClient.sock"
# define CLI_CONNECT_CLIENT_EVENTPOLL1 TURNPIKE_DIR"clieventpoll.sock"
# define RACOON_CONF_FILE1  TURNPIKE_DIR"racoon.conf"      


int displayProfileList(void);
int getGatewayType();
//int getGatewayAddress(char *file);
int getCertificateNameFromProfile();
//int printf_ph1Config_to_racoon_conf(FILE *fp);
//int printf_ph2Config_to_racoon_conf(FILE *fp);

void print_evt(char *buf, int len);

//int copyph2PoliciesIntobuffer(char *selectedProfile, char *currptr);
//int writeSuccessfulProfile(void);
//int create_rcbuf(struct racoon_conf **rcbuf);
//void copyProfiles(void);


#endif


