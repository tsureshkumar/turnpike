/*
 * Copyright (C) 2005-2009 Novell, Inc.
 * 
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact Novell, Inc.
 * 
 * To contact Novell about this file by physical or electronic mail,
 * you may find current contact information at www.novell.com.
 */
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <linux/errno.h>
#include <time.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "config.h"
/* from racoon */
#include "racoon/admin.h"
#include "racoon/evt.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/ipsec_doi.h"

#include "nortelcli.h"

#include "helper.h"
#include "common/norteladmin.h"
#include "common/helper.h"

#define GETDATA_IPV4_ADDR_MASK	1
#define MAX_BUFFER_SIZE 	2048
#define TIMEOUTINSECONDS	30

#define TURNPIKE_INTERFACE_VERSION 1

#define IPALIASDOWN   LIB_LOAD_PATH"/ipalias down"
#define IPADDR_CFGFILE "/var/tmp/ipcfg"

static void cleanup_socket(int sock);
static int nortel_construct_message (char *sendBuf, short msgType, void *gp);
static int receiveMessage(int sock, char **outbuf, int *outbuflen,time_t starttime );
static int sendPluginMessageToAdminPort(char *sendBuf, int bufLen, void *gp);
static int parse_message_from_admin_port(char *buf, void *gp);

void nortel_event_handler(int state, void *gp);
int initSocket(void *gp);

static void cleanup_socket(int sock)
{
	char client_socket_path[512]; //Enough?
	
	strcpy(client_socket_path, (const char *) getUserHome());
	strcat(client_socket_path, "/.turnpike/cliClient.sock");
	//printf("Client_socket_path : %s\n",client_socket_path);
	unlink(client_socket_path);
	close(sock);
}

static int nortel_construct_message (char *sendBuf, short msgType, void *gp)
{
	size_t bufLen = 0, outlen = 0;
	struct admin_com *comHeader;
	char *currptr; 
	
	struct pluginInfo *pInfo = (struct pluginInfo *)gp;
	
	comHeader = (struct admin_com *)sendBuf;
	comHeader->ac_cmd = msgType;
	comHeader->ac_proto = ADMIN_PROTO_ISAKMP;
	
	bufLen += sizeof(struct admin_com);
		
	currptr = &sendBuf[bufLen];
	switch(msgType)
	{
	case ADMIN_GET_VENDOR_PRIV_DATA: 

		outlen = 0;
		nortel_get_vendor_private_data (currptr, MAX_BUFFER_SIZE, &outlen);
		assert (outlen >= 0);
		bufLen += outlen;
		break;
		
	case ADMIN_REPLACE_SAINFO: //old address, new address
		outlen = 0;
		nortel_admin_replace_sainfo (currptr, MAX_BUFFER_SIZE, &outlen,
					     pInfo->ifInfo.source_ip_addr,
					     pInfo->assigned_ip_addr,
					     pInfo->ifInfo.source_ip_addr);
		assert (outlen >= 0);
		bufLen += outlen;
		break;
			
	default:
		break;
	}
	
	comHeader->ac_len = bufLen;
	return bufLen;
}

static int receiveMessage(int sock, char **outbuf, int *outbuflen,time_t starttime )
{
	char *area=NULL;	
	int ret;

	struct admin_com peekStruct;
	int recv_len, peek_len;
	fd_set rset;
	int maxfd;
	struct timeval tv;

	FD_ZERO(&rset);
	area=malloc(MAX_BUFFER_SIZE+sizeof(int));

	while(starttime+TIMEOUTINSECONDS > time(NULL)){

		FD_SET(sock,&rset);
		maxfd=sock+1;
		tv.tv_sec=0;
		tv.tv_usec=0; 
		if((ret=select(maxfd,&rset,NULL,NULL,&tv))<0){
			if((errno == EINTR))
				continue;

			if(ret==-1){
				printf("error in selecting with tv= %d.. \n",(int) tv.tv_sec);
				return -1;
			}
		}

		if(FD_ISSET(sock,&rset)){

			peek_len = recv(sock, &peekStruct, sizeof(struct admin_com), MSG_PEEK);
			if(!peek_len){
				cleanup_socket(sock);
				printf("Connection closed. May be server closed this connection! \n");
				return -1;
			}
			/*
			  printf("peek length = %d, Peeked length = %d\n", peek_len, peekStruct.ac_len);
			*/
			if(peekStruct.ac_errno)
			{
				printf("Admin port has returned error...\n");
				return -1;
			}
			if(peek_len < MAX_BUFFER_SIZE){
				recv_len = recv(sock, area, peekStruct.ac_len, MSG_WAITALL); //TODO:Error Check.
				/*
				  printf("Received Length= %d  \n",recv_len);
				  printf(" The Received Buffer length is %d ...\n",recv_len);
				*/
				*outbuflen=recv_len;
				*outbuf=area;
				/*
				  printf("Recevied Buffer \n");
				  for(i=0;i<recv_len;i++)
				  printf("%x(%c) ",(*outbuf)[i],(*outbuf)[i]);
				  printf("\n");
				*/
				//handleAdminPortResponse(button, sock, &outbuf, outbuflen );

				return 0;

			}
		}
	}
	//Timed out disconnect the server	
	return -2;
}

static char *getMsgStr(unsigned short msgType)
{
    switch(msgType)
	{
        case ADMIN_GET_VENDOR_PRIV_DATA     : return("ADMIN_GET_VENDOR_PRIV_DATA");
        case ADMIN_REPLACE_SAINFO			: return("ADMIN_REPLACE_SAINFO");
		default				    : return NULL;
    }
}

static int sendPluginMessageToAdminPort(char *sendBuf, int bufLen, void *gp)
{
	int sendLen = 0, ret = 0;
	char *outbuf=NULL;
	int outbuflen=0;
	int sockfd;
	struct pluginInfo *pInfo = (struct pluginInfo *)(gp);
	

	if((sockfd=initSocket(gp))<0){
		printf("Failed to connect to Racoon Daemon !");
		return -1;
	}

	sendLen = send(sockfd, sendBuf,bufLen,0);
	if(sendLen)
	{
		if (pInfo->ifInfo.isVerbose)
			printf("Successfully sent plugin message %s to admin port\n",
				getMsgStr(((struct admin_com *)sendBuf)->ac_cmd));
	}
	else
		printf("Failed to send plugin message to admin port");


	time_t t=time(NULL);

	while(t+TIMEOUTINSECONDS > time(NULL))
	{

		if((ret=receiveMessage(sockfd,&outbuf,&outbuflen,t))<0)
		{ //To free outbuf.
			if(outbuf)
				free(outbuf);
			if(ret==-1)
				printf("Error in receiving the message from Gateway ");
			if(ret==-2){
				printf("TimeOut in Receiving the Message .. ");
				return ret ;
			}

			return -1;
		}
		else
		{
			if (pInfo->ifInfo.isVerbose)
				printf("Received response from admin port\n");
			parse_message_from_admin_port(outbuf, gp);
			free(outbuf);
			return 0;
		}
	}

	return 0;
}

static int setenv_dev (char *filename)
{
	FILE *fp = NULL;
	char line[1024] = {0};
	char *tmp = NULL;
	char devname[256] = {0};

	fp = fopen (filename, "r");
	if (fp) {
		while (fgets (line, 1024, fp) != NULL) {
			tmp = strstr (line, "VIRTUALDEV");
			if (tmp) {
				strcpy (devname, tmp + 11);
				break;
			}
		}

		// dismiss the line break '\n'
		tmp = strchr (devname, '\n');
		if (tmp)
			*tmp = '\0';

		setenv("VIRTUALDEV", devname, 1);

		fclose (fp);
	}

	return 0;
}

static int parse_message_from_admin_port(char *buf, void *gp)
{
 	char *currptr;
	struct admin_com *comHeader;
	char sendBuf[2048];
	int bufLen = 0;
	struct pluginInfo *pInfo = (struct pluginInfo *)(gp);
	struct in_addr addr;
	char dns_entries[300] = {'\0'};
	char* domain_names = NULL;
	
 	//printf("cli plugin: parsing message\n");
	memset(sendBuf, 0, sizeof(sendBuf));
	currptr = buf;
	comHeader = (struct admin_com *)buf;
	//printf("adminport message = %x\n", comHeader->ac_cmd);
	
	switch(comHeader->ac_cmd)
	{
	case ADMIN_GET_VENDOR_PRIV_DATA:
		currptr += sizeof(struct admin_com);
		pInfo->assigned_ip_addr = *(int *)currptr;
		currptr += sizeof(u_int32_t);
		pInfo->assigned_net_mask = *(int *)currptr;
		currptr += sizeof(u_int32_t);
		// get primary dns addr
		pInfo->assigned_dns_addr1 = *(int *)currptr;
		currptr += sizeof(u_int32_t);
		// get secondary dns addr
		pInfo->assigned_dns_addr2 = *(int *)currptr;
		currptr += sizeof(u_int32_t);

		pInfo->assigned_domain_name = (char *)currptr;
		if (pInfo->ifInfo.isVerbose)
		{
			printf("Assigned IP Address = %s\n", inet_ntoa (* ((struct in_addr *) & (pInfo->assigned_ip_addr))));
			printf("Net Mask = %s\n", inet_ntoa(*((struct in_addr *) & (pInfo->assigned_net_mask))));
			printf("Primary DNS Server = %s\n", inet_ntoa(*((struct in_addr *) &
			(pInfo->assigned_dns_addr1))));
		}

		/* Set env vars for the Network Manager vpnc helper to use*/
		addr.s_addr = pInfo->ifInfo.server_ip_addr;
		setenv("VPNGATEWAY",(char *)inet_ntoa(addr),1);

		addr.s_addr = pInfo->assigned_ip_addr;
		setenv("INTERNAL_IP4_ADDRESS",(char *)inet_ntoa(addr),1);

		addr.s_addr = pInfo->assigned_net_mask;
		setenv("route_netmask_1",(char *)inet_ntoa(addr),1);

		strcpy(dns_entries,"dhcp-option ");
		strcat(dns_entries, "DNS ");

		if (pInfo->assigned_dns_addr1 > 0) {
			addr.s_addr = pInfo->assigned_dns_addr1;
			strcat(dns_entries, (char*)inet_ntoa(addr));
		}

		// add the secondary dns to it
		if (pInfo->assigned_dns_addr2 > 0) {
			addr.s_addr = pInfo->assigned_dns_addr2;
			strcat(dns_entries, " ");
			strcat(dns_entries, (char*)inet_ntoa(addr));
		}
		
		{
			int i = 0, j = 0, domain_names_length = 0, One = 0, Two = 0;
			res_init();

			for(; i < _res.nscount; i++)
			{
				strcat(dns_entries, " ");
				strcat(dns_entries, (char*)inet_ntoa((_res.nsaddr_list[i]).sin_addr));
			}

			i = 0;
			while( (_res.dnsrch[i] != NULL ) && (i <= MAXDNSRCH))
			{
				j = j + strlen(_res.dnsrch[i]);
				i++;
			}
			One = i != 0 ? ((sizeof(char) * (j)) + (i) * sizeof(char)):0 ;
			Two = (strcmp(pInfo->assigned_domain_name, "") == 0) ? 0 : (1+strlen(pInfo->assigned_domain_name)) * sizeof(char);
			domain_names_length = One + Two;
			domain_names = (char* ) malloc (sizeof(char) * domain_names_length);

			i = 0;
			strcpy(domain_names, "");
			while( (_res.dnsrch[i] != NULL ) && (i <= MAXDNSRCH))
			{
				strcat(domain_names, _res.dnsrch[i]);
				strcat(domain_names, " ");
				i++;
			}

			if(strcmp(pInfo->assigned_domain_name, "") != 0)
			{
				strcat(domain_names, pInfo->assigned_domain_name);
			}
		}

		setenv("foreign_option_1",dns_entries,1);

		//printf(_("Gateway, IPv4 Address, Mask and DNS are successfully set in env\n"));

		setenv("reason","connect",1);
		setenv("domain_names",domain_names,1);

		if (pInfo->ifInfo.upscript_len > 0) {
			// down the interface, the NM call the nvpn, so they have permission
			//if (-1 == system(IPALIASDOWN)) {
			//	printf("Run script(%s) failed.\n", IPALIASDOWN);
			//}

			setenv_dev (IPADDR_CFGFILE);

			// NM will set the ip address, netmask and DNS
			if (-1 == system(pInfo->ifInfo.upscript)) {
				printf("Run script (%s) failed!\n",
						pInfo->ifInfo.upscript);
			}
		}
		//printf(_("Successfully started the vpnc helper. Env reason set to connect\n"));

		bufLen = nortel_construct_message (sendBuf, ADMIN_REPLACE_SAINFO, gp);	
		if(bufLen)
			sendPluginMessageToAdminPort(sendBuf, bufLen, gp);
			
		break;
		
	case ADMIN_REPLACE_SAINFO:
		
		break;
		
	default:
		printf("Unknown admin port command received by plugin %d", comHeader->ac_cmd);
		break;

	}

 	return 0;
}

 


int initSocket(void *gp)
{

	struct sockaddr_un client_name, server_name;
	struct pluginInfo *pInfo = (struct pluginInfo *)gp;
	int sock,ret;

	char client_socket_path[512]; //Enough?
	
	strcpy(client_socket_path, (const char *) getUserHome());
	strcat(client_socket_path, "/.turnpike/cliClient.sock");
	//printf("CLI_CONNECT_CLIENT  %s\n", _socket_name);
	unlink(client_socket_path);
	sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if(sock < 0)
	{
		printf("Could not open the socket");
		cleanup_socket(sock);
		return -1;
	}

	bzero(&client_name, sizeof(client_name));
	client_name.sun_family = AF_UNIX;
	//strcpy(client_name.sun_path, "/root/.turnpike/cliClient.sock");
	strcpy(client_name.sun_path, (const char *) client_socket_path);
	
	//bind the socket
	ret= bind(sock, (struct sockaddr * )&client_name, sizeof(client_name));
	if(ret< 0 )
	{
		printf("Could not bind the socket !\n");
		cleanup_socket(sock);
		return -1;
	}
	bzero(&server_name, sizeof(server_name));
	server_name.sun_family = AF_UNIX;
	strcpy(server_name.sun_path, (const char * ) pInfo->ifInfo.admin_port_socket_name);

	//bind the socket
	if((ret = connect(sock, (struct sockaddr *)&server_name, sizeof(server_name))) < 0)
	{
		printf("\nCould not connect to VPNCSocket ! %d\n", errno);
		cleanup_socket(sock);
		return -1;
	}

	//printf(" The connected Socket FD is %d ...\n",sock);
	return sock;

}


void nortel_event_handler(int state, void *gp)
{
 	char sendBuf[2048];
	int bufLen = 0;
	
 	//printf("state from admin port = %d\n", state);
	if(state == EVTT_ISAKMP_CFG_DONE)
	{
		bzero(&sendBuf, sizeof(sendBuf));
		//printf("EVTT_ISAKMP_CFG_DONE received by plugin\n");
		bufLen = 
			nortel_construct_message (sendBuf, ADMIN_GET_VENDOR_PRIV_DATA, gp);	
		sendPluginMessageToAdminPort(sendBuf, bufLen, gp);
	}
	return;
}
