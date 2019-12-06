
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

#ifndef PROFILE_H__
#define PROFILE_H__

#define PFX_FILE_PATH1 TURNPIKE_DIR"usercerts/"

#define 	HOME_PROFILE_PATH		"turnpike/profiles/"
//#define 	PROFILE_PATH	"/etc/opt/novell/turnpike/profiles/"
#define 	PROFILE_PATH1	TURNPIKE_DIR"profiles/"
#define		LAST_USED_PROFILE_FILE	"lastusedprofile"
#define		PROFILE_PREFIX		"profile_"


#define 	MAX_PROFILE_FILENAME_LENGTH 	80
#define 	MAX_PROFILES			16

#define		FILE_NOT_EXIST 		-1
#define 	FILE_EXIST 		0

/* Misc definitions */
#define 	MAX_STRING_LEN		256
#define 	MIN_STRING_LEN		128

#endif // __PROFILE_H__

void get_connect_client_sock( char* );
void get_connect_client_event_poll_sock( char* );
void print_evt(char *, int);
void connecting_time_update (char* );
void conection_status_update (char* );
void on_vpnlogin_destroy_mainWindow();
void printing_function(char*);
void updateUptime(void);
void refresh_events();
