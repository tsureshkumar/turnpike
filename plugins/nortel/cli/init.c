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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "nortelcli.h"

int nortel_cli_plugin_init(void *cp, void **gp);

static int cp2gp( struct interfaceInfo *ifInfo, struct interfaceInfo *cp);

int nortel_cli_plugin_init(void *cp, void **gp)
{
	struct pluginInfo *pInfo = NULL;
	struct interfaceInfo *ifInfo = (struct interfaceInfo *)cp;

	//Should be freed, once connect suceeded
	*gp = (struct pluginInfo *)malloc(sizeof(struct pluginInfo)); 

	if (!(*gp)){
		printf("Failed to allocate memory\n");
		return -1;
	}

	pInfo = (struct pluginInfo*)(*gp);
	memset(pInfo, 0, sizeof(struct pluginInfo));

	/* 
	 * Copy the config priv data from base CLI into CLI plugin's global priv data 
	 */

	if(cp){
		if(cp2gp(&(pInfo->ifInfo), ifInfo)<0){
			printf("cp2gp in nortel cli plugin failed\n");
 
			return -1;
		}
	}
	return 0;
}

static int cp2gp( struct interfaceInfo *ifInfo, struct interfaceInfo *cp)
{
	/* Copy Source IP */
	ifInfo->source_ip_addr = cp->source_ip_addr;

	/* Copy Server IP */
	ifInfo->server_ip_addr = cp->server_ip_addr;

	/* Copy Admin port socket name */
	ifInfo->admin_port_socket_name_len = cp->admin_port_socket_name_len;

	/* Should be freed during de-init  */
	ifInfo->admin_port_socket_name = 
		(caddr_t)malloc((ifInfo->admin_port_socket_name_len + 1) * sizeof(char));
	
    
	if(!ifInfo->admin_port_socket_name){
		printf("Failed to allocate memory\n");
		return -1;
        }
    
	memset(ifInfo->admin_port_socket_name, 0,
	       ifInfo->admin_port_socket_name_len + 1);
	memcpy (ifInfo->admin_port_socket_name, cp->admin_port_socket_name,
		ifInfo->admin_port_socket_name_len);
	ifInfo->admin_port_socket_name[ifInfo->admin_port_socket_name_len]='\0';			
    
	/* Copy gateway_type */ 
	ifInfo->gateway_type_len = cp->gateway_type_len;

	ifInfo->gateway_type = (caddr_t) malloc(ifInfo->gateway_type_len * sizeof(char) + 1);//Should be freed during de-init  
    
	if(!ifInfo->gateway_type){
		printf("Failed to allocate memory\n");
		return -1;
        }
    
	memset(ifInfo->gateway_type, 0, ifInfo->gateway_type_len );

	memcpy (ifInfo->gateway_type, cp->gateway_type, ifInfo->gateway_type_len);
	ifInfo->gateway_type[ifInfo->gateway_type_len] ='\0';
	
	/* Copy if Verbose Mode info */
	ifInfo->isVerbose = cp->isVerbose;

	/* Copy the input mode flag */
	ifInfo->withProfileFile = cp->withProfileFile;

	/* Copy the Authentication type */
	ifInfo->authentication_type = cp->authentication_type;
	
	if (ifInfo->withProfileFile)
	{
		/* Copy profile_name */ 
		ifInfo->profile_name_len = cp->profile_name_len;

		ifInfo->profile_name = 
			(caddr_t) malloc(ifInfo->profile_name_len * sizeof(char) + 1);
		//Should be freed during de-init  
    
		if(!ifInfo->profile_name){
			printf("Failed to allocate memory\n");
			return -1;
	        }
    
		memset(ifInfo->profile_name, 0, ifInfo->profile_name_len+1 );
		memcpy (ifInfo->profile_name, cp->profile_name, ifInfo->profile_name_len+1);
	}	

	/* Copy the requested dh_group */
	ifInfo->dh_group = cp->dh_group;
	ifInfo->pfs_group = cp->pfs_group;

	/* Copy the upscript with path */
	ifInfo->upscript_len = cp->upscript_len;
	if (ifInfo->upscript_len)
	{
		//Should be freed  during de-init
		ifInfo->upscript = (caddr_t) malloc(ifInfo->upscript_len * sizeof(char) + 1);
		if (!ifInfo->upscript)
		{
			printf("Failed to allocate memory\n");
			return -1;
		}
		memset(ifInfo->upscript, 0, ifInfo->upscript_len + 1);
		memcpy(ifInfo->upscript, cp->upscript, ifInfo->upscript_len+1);
	}
	
	return 0;
}

