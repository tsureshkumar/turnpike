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
#include <string.h>

#include "adminport.h"
#include "common/norteladmin.h"

int assignedIPAddr = 0;

extern int sendPluginMessageToAdminPort (char *buf, int length); // turnpike
extern int server_addr;
extern int source_addr;


void nortel_state_recv_from_adminport (int state);
int nortel_parse_message_from_adminport (char *buf);
static size_t nortel_construct_message (char *buf, short msgtype);

void
nortel_state_recv_from_adminport(int state)
{
 	char sendBuf[2048];
	int bufLen = 0;
	
	if(state == EVTT_ISAKMP_CFG_DONE)
	{
		bzero(&sendBuf, sizeof(sendBuf));
		bufLen = nortel_construct_message(sendBuf, ADMIN_GET_VENDOR_PRIV_DATA);	
		if(bufLen)
			sendPluginMessageToAdminPort(sendBuf, bufLen);
	}
	return;
}

int
nortel_parse_message_from_adminport(char *buf)
{
 	char *currptr;
	comHeader_t *comHeader;
	char sendBuf[2048];
	size_t bufLen = 0;

	memset(sendBuf, 0, sizeof(sendBuf));
	currptr = buf;
	comHeader = (comHeader_t *)buf;
	
	switch(comHeader->ac_cmd) {
	case ADMIN_GET_VENDOR_PRIV_DATA:
		currptr += sizeof(comHeader_t);
		assignedIPAddr = *(int *)currptr;
			
		bufLen = nortel_construct_message(sendBuf, ADMIN_REPLACE_SAINFO);	
		if(bufLen)
			sendPluginMessageToAdminPort(sendBuf, bufLen);
		break;
	case ADMIN_REPLACE_SAINFO:
		break;
	default:
		printf("Unknown admin port command received by plugin %d", comHeader->ac_cmd);
		break;
	}
 	return 0;
}

static size_t
nortel_construct_message (char *sendBuf, short msgType)
{
	size_t bufLen = 0, outlen = 0;
	comHeader_t *comHeader;
	char *currptr; 

	comHeader = (comHeader_t *)sendBuf;
	comHeader->ac_cmd = msgType;
	comHeader->ac_proto = ADMIN_PROTO_ISAKMP;
	
	bufLen += sizeof(comHeader_t);
		
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
					     source_addr,
					     assignedIPAddr,
					     server_addr);
		assert (outlen >= 0);
		bufLen += outlen;
		currptr += outlen;
		break;

		break;
			
	default:
		break;
	}
	
	comHeader->ac_len = bufLen;
	return bufLen;
}
