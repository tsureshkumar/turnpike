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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

#include "nortelcli.h"
#include "helper.h"

#include "common/helper.h"
#include "common/profile.h"

#define MAX_PATH_LEN        512
#define MAX_STRING_LEN      128
#define PASSWORD_STRING_LENGTH 256

char last_succ_user [MAX_STRING_LEN];

static int getPassword (char *password);

int nortel_get_privdata(char *buf, void *gp);
int nortel_create_vendor_profile(char *vendorProfileFileName);

/* Call back function to create a vendor profile */
int nortel_create_vendor_profile(char *vendorProfileFileName)
{
	char groupN[MAX_STRING_LEN] = {'\0'};
	char groupP[MAX_STRING_LEN] = {'\0'};
	char gatewayIP[MAX_STRING_LEN] = {'\0'};

	char fileName[MAX_PATH_LEN] = {'\0'};
    
	memset(groupN,'\0',MAX_STRING_LEN-1);
	memset(groupP,'\0',MAX_STRING_LEN-1);
    
	/* Get Group Name and Group Password */
	printf("Group Name		: ");

	// don't use getchar() anymore, use fgets for avoiding
	// buffer overflow
	if (NULL != fgets(groupN, MAX_STRING_LEN - 1, stdin)) {
		char *temp = NULL;
		temp = strrchr(groupN, '\n');
		if (temp != NULL)
			*temp = '\0';
	}

	printf("Group Password		: ");
	getPassword(groupP);
	//strcpy(groupP,getpass("*"));
	printf("Gateway IP		: ");
	if (EOF == scanf("%s", gatewayIP)) {
		printf("Error input gatewayIP.\n");	
	}
	/* Given the vendor name create the vendor profile file name */
	// FIXME: buffer overflow
	//strcpy(fileName,"/etc/opt/novell/turnpike/vendorprofiles/");
	strcpy(fileName,vendorProfileFileName);

 	printf("Vendor Profile Name : %s\n",fileName);	
	return nortel_rewrite_profile ( (const char *) fileName,
					(const char *) groupN,
					(const char *) groupP,
					(const char *) gatewayIP);
}    

int nortel_get_privdata(char *buf, void *gp)
{
	struct pluginInfo *pInfo = (struct pluginInfo *)gp;
	char groupName[MAX_STRING_LEN] = {'\0'};
	char groupPassword[MAX_STRING_LEN] = {'\0'};
	char groupUnEncPassword[MAX_STRING_LEN] = {'\0'};
	char userName[MAX_STRING_LEN] = {'\0'};
	char userPassword[MAX_STRING_LEN] = {'\0'};
	char newUserName[MAX_STRING_LEN] = {'\0'};
	int bufLen = 0;
	char *currptr = buf;

	if(pInfo->ifInfo.authentication_type != CERTIFICATE)
	{
		int gpEncFlag = 1;
	
		memset(userName,'\0',MAX_STRING_LEN - 1);
		memset(newUserName,'\0',MAX_STRING_LEN - 1);
		memset(groupName,'\0',MAX_STRING_LEN - 1);
		memset(groupPassword, '\0',MAX_STRING_LEN - 1);
		memset(groupUnEncPassword, '\0',MAX_STRING_LEN - 1);

		if (pInfo->ifInfo.withProfileFile)
		{
	
			if (nortel_read_profile(
				    nortel_get_profile_location ((const char *) (pInfo->ifInfo.profile_name)),
				    (char *) groupName,
				    (char *) groupPassword,
			    	(char *) userName) < 0)
			{
				printf("Error: Unsuccessfully Parsed the vendor profile data \n");
				exit (1);
			};
	
			printf("User Name		: ");
			printf("[%s]", userName);

			// don't use getchar anymore, it's a problem when in PPC,
			// use fgets can avoid buffer overflow.
			if (NULL != fgets(newUserName, MAX_STRING_LEN - 1, stdin)) {
				char *temp = NULL;
				temp = strrchr(newUserName, '\n');
				if (temp != NULL)
					*temp = '\0';
			}
			// when user just input '\n' don't set userName
			if (strlen(newUserName) > 0) {
				strncpy(userName, newUserName, MAX_STRING_LEN - 1);
			}

			//printf("User name selected : %s, newuser : %s\n",userName, newUserName);
	
			printf("User Password		: ");
			getPassword(userPassword);
	
		}
		else
		{
			char buffer[PASSWORD_STRING_LENGTH] = {'\0'};
			if (EOF == scanf("XAuth User %s\n",userName)) {
				printf("Error input userName.\n");	
			}

			if( fgets(buffer, sizeof(buffer), stdin) == NULL)
				exit(1);
			else
			{
				if(strncmp("XAuth Password ", buffer, strlen("XAuth Password ")) == 0)
					strncpy(userPassword, &(buffer[strlen("XAuth Password ")]), strlen(&(buffer[strlen("XAuth Password ")]))-1);
			}
				
			if (EOF == scanf("IPSec ID %s\n",groupName)) {
				printf("Error input groupName.\n");	
			}
			if( fgets(buffer, sizeof(buffer), stdin) == NULL)
				exit(1);
			else {
				if(strncmp("IPSec Password ", buffer, strlen("IPSec Password ")) == 0)
					strncpy(groupPassword,
							&(buffer[strlen("IPSec Password ")]),
							strlen(&(buffer[strlen("IPSec Password ")]))-1);
			}

			// Don't use %d\n cause it need input twice non-blank character.
			if (EOF == scanf("IPSec Password EncFlag %d", &gpEncFlag)) {
				printf("Error input password.\n");	
			}
		
			if (!gpEncFlag)
			{
				strcpy(groupUnEncPassword, groupPassword);
				memset(groupPassword, '\0', MAX_STRING_LEN - 1);
				nortel_enc_password(groupUnEncPassword,
					   	strlen(groupUnEncPassword),
						groupPassword,
						MAX_STRING_LEN);
			}	
		}
	}

	//Update the username for storing in the profile
	memset(last_succ_user,'\0', MAX_STRING_LEN - 1);
	strcpy(last_succ_user, (const char *) userName);
	
	*(int32_t *) currptr = (int) (pInfo->ifInfo.server_ip_addr);
	currptr += sizeof(int32_t);
	bufLen += sizeof(int32_t);
	
	*(size_t *)currptr = strlen(groupName);
	currptr += sizeof(size_t);
	bufLen += sizeof(size_t);
	
	strcpy(currptr, (const char *) groupName);
	currptr +=strlen(groupName);
	bufLen += strlen(groupName);
	
	*(size_t *)currptr = strlen(groupPassword);
	currptr += sizeof(size_t);
	bufLen += sizeof(size_t);
	
	strcpy(currptr, (const char *) groupPassword);
	currptr +=strlen(groupPassword);
	bufLen += strlen(groupPassword);
	
	
	*(size_t *)currptr = strlen(userName);
	currptr += sizeof(size_t);
	bufLen += sizeof(size_t);
	
	strcpy(currptr, (const char *) userName);
	currptr +=strlen(userName);
	bufLen += strlen(userName);
	
	
	*(size_t *)currptr = strlen(userPassword);
	currptr += sizeof(size_t);
	bufLen += sizeof(size_t);
	
	strcpy(currptr, (const char *) userPassword);
	currptr +=strlen(userPassword);
	bufLen += strlen(userPassword);

	return bufLen;
}

static
int getPassword (char *password)
{ 
	struct termios termiosPointer;
	struct  termios oldTermiosPointer;
	
	tcgetattr (0, &termiosPointer);
	oldTermiosPointer=termiosPointer;
	//printf("Certificate Password :");
	termiosPointer.c_lflag &=(~ECHO);
	tcsetattr(0, TCSANOW, &termiosPointer);
		
	if (EOF == scanf("%s",password)) {
		printf("Error input password.\n");	
	}
		
	tcsetattr(0, TCSANOW, &oldTermiosPointer);
	printf("\n");
	return 0;
}

int
nortel_update_profile (char *profilename)
{
	return nortel_profile_update_user (nortel_get_profile_location (profilename),
					   last_succ_user);
}
