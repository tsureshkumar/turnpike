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
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

#include "profile.h"
#include "helper.h"
#include "encrypt.h"

int nortel_profile_update_user (const char *file_name, const char *username);
int nortel_enc_password(char *group_unenc_password, 
			int unenc_len, 
			char *group_enc_password, 
			int enc_len);


int nortel_rewrite_profile (const char *file_name,
			    const char *group_name,
			    const char *group_password,
			    const char *gatewayIP);
int nortel_read_profile (const char *profilename,
			 char *groupName,
			 char *grpPasswd,
			 char *usrName);

const char * nortel_get_profile_location (const char *name);

static int checkuname (const char *str);
static int is_file_exist (const char *filename);

int nortel_profile_update_user (const char *file_name, const char * username)
{
	xmlNode *cur_node;
	xmlChar *buffer;
	xmlDocPtr doc;
	int usrNamefound = 0;

	doc = xmlParseFile (file_name);
	if (doc == NULL) {
		show_error_message ("Could not parse the XML profile");
		return -1;
	}
	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp( (const xmlChar *) root->name, (const xmlChar *) "vendor")) { 
		printf("nortel plugin .. root element not found\n");
		show_error_message ("Bad Profile !!");
		xmlFreeDoc(doc);
		return -1;
	}
	
	
	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) {
		if ( cur_node->type == XML_ELEMENT_NODE  ) {  
			if(strcmp( (const char *) cur_node->name, (const char *) "username") == 0){
				buffer = xmlNodeGetContent(cur_node);
				if(buffer) {
					usrNamefound=1;
					xmlNodeSetContent(cur_node, (const xmlChar *) username);
					xmlFree(buffer);
					buffer = NULL;
				}
			}
		}
	}
	
	if (!usrNamefound)
		xmlNewTextChild(root, NULL, (const xmlChar *) "username", (const xmlChar *) username);

	xmlKeepBlanksDefault(0);
	xmlSaveFormatFile (file_name, doc, 1);
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);

	return 0;

}

int nortel_enc_password(char *group_unenc_password, int unenc_len, char *group_enc_password, int enc_len)
{
	char groupPEnc[128];
	int groupPEncLen = sizeof(groupPEnc);


	if (unenc_len == 0)
		return -1;
		
	nortel_encode(group_unenc_password, unenc_len , groupPEnc, &groupPEncLen, ENCRYPT_KEY, strlen ( (const char *) ENCRYPT_KEY));	
	
	if (enc_len < groupPEncLen )
		return -2;
		
	memcpy(group_enc_password, groupPEnc, groupPEncLen);		
	group_enc_password[groupPEncLen]='\0';
	
	return 0 ;
}


int
nortel_rewrite_profile (const char *file_name,
			const char *group_name,
			const char *group_password,
			const char *gatewayIP)
{
	char groupPEnc [128];
	int groupPEncLen = sizeof(groupPEnc);
	
	xmlNodePtr childptr= NULL;
	xmlNodePtr root_node = NULL;
	xmlDocPtr doc;
	
	if(checkuname (group_name)
	   || (strlen( (const char *) group_password) == 0))
		return -1;
	
	nortel_encode(group_password, strlen(group_password), groupPEnc, &groupPEncLen, ENCRYPT_KEY, strlen ( (const char *) ENCRYPT_KEY));	
	
	if(!is_file_exist(file_name)) //Remove and rewrite it 
		remove(file_name);

	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "vendor");
	xmlDocSetRootElement(doc, root_node);
	
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);
	xmlNewProp(root,(const xmlChar *) "vendorname", (const xmlChar *) "nortel");
	childptr=xmlNewTextChild(root, NULL, (const xmlChar *) "groupname", (const xmlChar *) group_name);
	if(gatewayIP != NULL)
		childptr=xmlNewTextChild(root, NULL, (const xmlChar *) "gatewayip", (const xmlChar *) gatewayIP);
	childptr=xmlNewTextChild(root, NULL, (const xmlChar *) "grouppasswd", (const xmlChar *) groupPEnc);
	
	xmlKeepBlanksDefault(0);
	xmlSaveFormatFile(file_name, doc, 1);
	xmlFreeDoc(doc);
	
	return 0;
}

// FIXME : buffer overflow for passed groupname, ...
int
nortel_read_profile (const char *file_name,
		     char *groupName,
		     char *grpPasswd,
		     char *usrName)
{

	xmlNode *cur_node;
	xmlChar *buffer;
	xmlDocPtr doc;

	doc = xmlParseFile(file_name);
	if (doc == NULL) {
		show_error_message ("Could not XML parse the profile");
		return -1;
	}

	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp ( (const xmlChar *) root->name, (const xmlChar *) "vendor")) { 
		printf("Nortel plugin: Root element not found\n");
		show_error_message ("Bad Profile!");
		xmlFreeDoc(doc);
		return -1;
	}
	

	// FIXME : buffer overflow
	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) {
		if ( cur_node->type == XML_ELEMENT_NODE  ) {  
			if (strcmp( (const char *) cur_node->name,
				    (const char *) "profile_name") == 0) {
				buffer = xmlNodeGetContent(cur_node);
				if(buffer){
					xmlFree(buffer);
					buffer = NULL;
				}
			} else if (strcmp ( (const char *) cur_node->name,
					    (const char *) "groupname") == 0) {
				buffer = xmlNodeGetContent(cur_node);
				strcpy (groupName, (const char *)buffer);
				if(buffer){
					xmlFree(buffer);
					buffer = NULL;
				}
			} else if(strcmp ( (const char *) cur_node->name,
					   (const char *) "grouppasswd") == 0) {
				buffer = xmlNodeGetContent(cur_node);
				if(buffer) {
					strcpy(grpPasswd, (const char *)buffer);
					xmlFree(buffer);
					buffer = NULL;
				}
			} else if(strcmp( (const char *) cur_node->name,
					  (const char *) "username") == 0) {
				buffer = xmlNodeGetContent(cur_node);
				if(buffer) {
					strcpy (usrName, (const char *) buffer);
					xmlFree(buffer);
					buffer = NULL;
				}
			}
		}
	}
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);

	return 0;
}


static int 
checkuname (const char *str)
{
	int len;
	
	len = strlen (str);
	if(len == 0
	   || strchr (str, ' ') != NULL)
		return -1;
	return 0;
}

static
int is_file_exist (const char *filename)
{
	struct stat buf;
	
	if(lstat (filename,&buf)<0)
		return -1;

	else if(!S_ISREG(buf.st_mode) || (buf.st_size==0))
		return -1;

	return 0;
}


const char * 
nortel_get_profile_location (const char *name) 
{
  static char full_path [FILENAME_MAX]; 

  snprintf (full_path, FILENAME_MAX, "%s%s%s", getUserHome (),
	    "/.turnpike/vendorprofiles/",
	    name);
  return (const char *) full_path;
}
