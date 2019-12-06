
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


# ifndef __VPNINTERFACE_H__
#define __VPNINTERFACE_H__

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "racoon/admin.h"

void cleanup_socket(int );
int initSocket();
void cleanup_socket(int sock);
void closeEventSockfd();
int initEventSockfd();
/* Allocated buf and buflen */
int fillBuffer(int msgType,/*GUIConnectMessage*/ void   *inbuf, int inbuflen, char **outbuf, int *outbuflen );
int sendBuffer(int sock, char *buf,int buflen);

# define ERR_TIMEDOUT -2

int receiveBuffer(int sock,char *);
int sigChldHandler(int signo);
#endif	
