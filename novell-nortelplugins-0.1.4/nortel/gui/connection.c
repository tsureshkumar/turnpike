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
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <gtk/gtk.h>

#include "authframe.h"

extern int server_addr;

char grpName[256];
char grpPasswd[256];
char usrName[256];


size_t 
nortel_connect (char *buf)
{
	g_assert (buf != 0);

	size_t bufLen = 0;
	char userName[128] = {'\0'};
	char userPassword[128] = {'\0'};
	char *currptr = buf;
	
	if(strcmp(buf, "CERTIFICATE") != 0)
	{
		strcpy(userName, nortel_gui_get_username ());
		strcpy(userPassword, nortel_gui_get_password ());
	}
	
	*(int32_t *) currptr = server_addr;
	currptr += sizeof(int32_t);
	bufLen += sizeof(int32_t);
	
	*(size_t *)currptr = strlen(grpName);
	currptr += sizeof(size_t);
	bufLen += sizeof(size_t);
	
	strcpy(currptr,grpName);
	currptr +=strlen(grpName);
	bufLen += strlen(grpName);
	
	*(size_t *)currptr = strlen(grpPasswd);
	currptr += sizeof(size_t);
	bufLen += sizeof(size_t);

	strcpy(currptr,grpPasswd);
	currptr +=strlen(grpPasswd);
	bufLen += strlen(grpPasswd);
	
	
	*(size_t *)currptr = strlen(userName);
	currptr += sizeof(size_t);
	bufLen += sizeof(size_t);
	
	strcpy(currptr,userName);
	currptr +=strlen(userName);
	bufLen += strlen(userName);
	
	
	*(size_t *)currptr = strlen(userPassword);
	currptr += sizeof(size_t);
	bufLen += sizeof(size_t);
	
	strcpy(currptr,userPassword);
	currptr +=strlen(userPassword);
	bufLen += strlen(userPassword);
	
	return bufLen;
}

int
nortel_disconnect (char *buf)
{
 	return 0;
}
