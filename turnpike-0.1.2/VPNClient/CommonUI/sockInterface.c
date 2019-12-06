
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

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

/* cli headers */
#include "sockInterface.h"
#include "cliErrors.h"
#include "vpncErrorHandling.h"

#include "CommonUI.h"

/* globals */
char errStr[MAX_STRING_LEN];

extern int sockfd, eventsockfd;
extern Inf_t Inf;

void cleanup_socket(int sock)
{
	unlink(Inf.connect_client);
	Inf.sockfd = 0;
	close(sock);
}

void closeEventSockfd()
{
	unlink(Inf.connect_client_eventpoll);
	Inf.eventsockfd = 0;
	close(Inf.eventsockfd);
}

int initEventSockfd()
{
	struct sockaddr_un client_name, server_name;
	int sock,ret;

	unlink(Inf.connect_client_eventpoll);
	sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if(sock < 0)
	{
		printf(_("Failed to create the socket\n"));
		closeEventSockfd();
		return -1;
	}

	bzero(&client_name, sizeof(client_name));
	client_name.sun_family = AF_UNIX;
	strcpy(client_name.sun_path, Inf.connect_client_eventpoll);
    
	/* bind the socket */
	ret= bind(sock, (struct sockaddr * )&client_name, sizeof(client_name));
	if(ret< 0 )
	{
		printf(_("Failed to bind the socket !\n"));
		closeEventSockfd();
		return -1;
	}
	bzero(&server_name, sizeof(server_name));
	server_name.sun_family = AF_UNIX;
	strcpy(server_name.sun_path, ADMINSOCK_PATH);

	if(connect(sock, (struct sockaddr *)&server_name, sizeof(server_name)) < 0)
	{
		(Inf.printing_function)("EventPollSocket : Can not connect to VPNSocket !");
		closeEventSockfd();
		return -1;
	}

	return sock;
}



int initSocket()
{

	struct sockaddr_un client_name, server_name;
	int sock,ret;

	unlink(Inf.connect_client);
	sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if(sock < 0)
	{
		printf(_("Failed to create the socket\n"));
		cleanup_socket(sock);
		return -1;
	}

	bzero(&client_name, sizeof(client_name));
	client_name.sun_family = AF_UNIX;
	strcpy(client_name.sun_path, Inf.connect_client);
    
	/* bind the socket */
	ret = bind(sock, (struct sockaddr * )&client_name, sizeof(client_name));
	if(ret< 0 )
	{
		printf(_("Can not bind the socket !\n"));
		cleanup_socket(sock);
		return -1;
	}
	bzero(&server_name, sizeof(server_name));
	server_name.sun_family = AF_UNIX;
	strcpy(server_name.sun_path, ADMINSOCK_PATH);

	if((ret = connect(sock, (struct sockaddr *)&server_name, sizeof(server_name))) < 0)
	{
		printf(_("Failed to connect to AdminSock(%s)! %d\n"), ADMINSOCK_PATH, errno);
		cleanup_socket(sock);
		return -1;
	}
	return sock;
}


int sendBuffer(int sock, char *buf,int buflen){
	
	int ret;
    
	/* Now send to VPNCSocket */
	ret = send(sock, buf, buflen, 0);
	if(ret < 0)
    {
# if __DEBUG__ == 1
			printf("Error while sending the message \n");
#endif
			
		return -1;
	}
# if __DEBUG__ == 1
	printf("Sent message  in socket %d of  len %d\n",  sock,buflen);
#endif
	printf(_("Sent the Buffer of length %d..\n"),buflen); 
	return 0;
	
}

#if 0
int receiveBuffer(int sock, char  *area){

	VPNCHeader_t peekStruct;
	int recv_len, peek_len,i;
	fd_set rset;
	int maxfd;
	struct timeval tv;
	int ret;

	FD_ZERO(&rset);

# if __DEBUG__ == 1
	printf("About to receive in %d\n",sock);
#endif
	
//	while(1){
		FD_SET(sock,&rset);
		maxfd=sock+1;
		tv.tv_sec=TIMEOUTINSECONDS;
		tv.tv_usec=0;
		//printf("Waiting on Select Call ....\n"); 
		if((ret=select(maxfd,&rset,NULL,NULL,&tv))<=0){
			if(ret==-1){
# if __DEBUG__ == 1
				printf("error in selecting.. \n");
#endif
				return -1;
			}
			if (ret==0){
# if __DEBUG__ == 1
				printf(" Timed Out .. \n");
#endif
				return ERR_TIMEDOUT;
			}
		}

		if(FD_ISSET(sock,&rset)){

			peek_len = recv(sock, &peekStruct, sizeof(VPNCHeader_t), MSG_PEEK);
			if(!peek_len){
				cleanup_socket(sock);
			# if __DEBUG__ == 1
				printf("Connection closed. May be server closed this connection! \n");
			#endif
				return -1;
			}
		# if __DEBUG__ == 1
			printf("peek length = %d, Peeked length = %d\n", peek_len, peekStruct.msgLen);
		#endif
			if(peek_len < VPNC_MAX_BUFFER_SIZE){
				recv_len = recv(sock, area+sizeof(int), peekStruct.msgLen, MSG_WAITALL); //TODO:Error Check.
			# if __DEBUG__ == 1
				printf("Received Length = %d  \n",recv_len);
			#endif

				//break;
			}
		}
//	}
	(*(int *)area) = recv_len;	
	if (Inf.isVerbose)
		printf(" The Received Buffer length is %d ...\n",recv_len);
	return 0;
}





#endif

