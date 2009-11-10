/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */

/************************************************************************************
*   profile.c - Read VPN configuration from user's directory.                       *
*                                                                                   *
*   Copyright (c) 2008, Novell Inc.,                                                * 
*   All rights reserved.                                                            *
*                                                                                   *
*   Authors: Bin Li <bili@novell.com>                                               *
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

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h> 
#include <dirent.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <unistd.h> 
 
#include <gconf/gconf-client.h> 
#include <nm-setting-connection.h> 
#include <nm-setting-vpn.h> 
#include <gtk/gtk.h>
#include "nm-utils.h" 
#include "src/nm-novellvpn-service.h" 
 
#define GCONF_PATH_VPN_CONNECTIONS "/system/networking/vpn_connections" 
#define GCONF_PATH_NM_CONNECTIONS "/system/networking/connections" 
 
extern char* VPN_Name; 

void search_in_the_directory(char search_keys[][100])
{
	struct match_node
	{
		char file_name[256];
		char gateway_ip[256];
		struct match_node* next;
	};

	struct match_node* group_name_match_list = NULL;

	DIR * dd;
	xmlNode *root = NULL;
	xmlNode *cur_node, *grouppasswd_node;
	xmlChar *buffer;
	xmlDocPtr doc;
	xmlChar *key;	
	struct dirent *dirp; 
	int no_of_matches = 0;
	char VENDOR_PROFILE_PATH[200] = {'\0'};
	char vendor_profile_name[200] = {'\0'};
	char group_name_for_comparison[256] = {'\0'};
	char gateway_ip_for_comparison[256] = {'\0'};
	sprintf(VENDOR_PROFILE_PATH, "%s/%s", getenv("HOME"), ".turnpike");
	strcat(VENDOR_PROFILE_PATH, "/vendorprofiles");
	dd = opendir(VENDOR_PROFILE_PATH);
	if (dd == NULL)
	{
		return;
	}
	while((dirp = readdir(dd)) != NULL)
	{
		strcpy(vendor_profile_name, VENDOR_PROFILE_PATH);
		strcat(vendor_profile_name, "/");
		if(strstr(dirp->d_name,".prf")!=NULL)
		{
			strcat(vendor_profile_name, dirp->d_name);
			doc = xmlParseFile(vendor_profile_name);
			if (doc == NULL)
			{
				fprintf(stderr, "XML_PARSE_FAILED\n");
				continue; 
			}

			root = xmlDocGetRootElement(doc);

			if( !root || !root->name ||xmlStrcmp(root->name,(xmlChar*)"vendor"))
			{
				fprintf(stderr, "INVALID_PROFILE\n");
				xmlFreeDoc(doc);
				continue;
			}
			buffer= xmlGetProp(root,(xmlChar*)"vendorname");

			for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next)
			{
				if ( cur_node->type == XML_ELEMENT_NODE  )
				{
					if(strcmp((const char*)cur_node->name, "groupname") == 0)
					{
						grouppasswd_node = cur_node->xmlChildrenNode;
						if(grouppasswd_node != NULL)
						{
							key = xmlNodeListGetString(doc, grouppasswd_node, 1);
							strcpy(group_name_for_comparison, (char*)key);
						}
					}
					else if(strcmp((const char*)cur_node->name, "gatewayip") == 0)
					{
						grouppasswd_node = cur_node->xmlChildrenNode;
						if(grouppasswd_node != NULL)
						{
							key = xmlNodeListGetString(doc, grouppasswd_node, 1);
							strcpy(gateway_ip_for_comparison, (char*)key);
						}
					}
				}
			}
			if(strcmp(group_name_for_comparison, search_keys[1]) == 0)
			{
				struct match_node* temp = (struct match_node*)malloc(sizeof(struct match_node));
				strcpy(temp->file_name , dirp->d_name);
				strcpy(temp->gateway_ip, gateway_ip_for_comparison);
				temp->next = group_name_match_list;
				group_name_match_list = temp;
				no_of_matches++;
			}
		}
	}

	if(no_of_matches > 1)
	{
		struct match_node* trav = group_name_match_list;
		for(; trav != NULL; trav=trav->next)
		{
			if(strcmp(trav->gateway_ip, search_keys[0]) == 0)
			{
				strcpy(search_keys[2], trav->file_name);
				break;
			}
		}
		if(trav == NULL)
		{
			GtkWidget* confirm_dialog = gtk_message_dialog_new (NULL,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_MESSAGE_WARNING,
					GTK_BUTTONS_CLOSE,
					"Unable to fetch Group Password");
			gtk_message_dialog_format_secondary_text (
					GTK_MESSAGE_DIALOG (confirm_dialog),
					"Try Updating your vendor profiles");
			gtk_dialog_run (GTK_DIALOG (confirm_dialog));
			gtk_widget_destroy (confirm_dialog);
		}
	}
	else if(no_of_matches == 1)
	{
		strcpy(search_keys[2], group_name_match_list->file_name);
	}

	/* Deallocation */
	{
		struct match_node* temp = group_name_match_list;
		while(group_name_match_list != NULL)
		{
			temp = group_name_match_list->next;
			free(group_name_match_list);
			group_name_match_list = temp;
		}
	}
	return;
}

void get_the_vendor_file_name(char* vendor_file_name_to_read, char* vpn_uuid)
{
	GConfClient *gconf_client = NULL;
	/* FIXME: search_keys shouldn't be static */
	char search_keys[3][100] = { {'\0'}, {'\0'}, {'\0'}};
	GSList *conf_list = NULL;
	GSList *iter = NULL;
	char *key = NULL;
	char *val = NULL;
	char *connection_path = NULL;

	gconf_client = gconf_client_get_default();

	/* FIXME: This whole thing sucks: we should not go around poking gconf
	 *        directly, but there's nothing that does it for us right now */

	/* Lists the subdirectories in GCONF_PATH_NM_CONNECTIONS,
	 * The returned list contains allocated strings, so need to free */
	conf_list = gconf_client_all_dirs (gconf_client,
			GCONF_PATH_NM_CONNECTIONS, NULL);
	if (NULL == conf_list) {
		nm_warning ("can't found any connections in %s", 
				GCONF_PATH_NM_CONNECTIONS);
		strcpy( vendor_file_name_to_read, "not_found");
		return;
	}

	/* found the vpn connection dir, 'type' should be vpn, and 
	 * also 'id' should be the VPN_Name */
	for ( iter = conf_list; iter ; iter = iter->next) {
		const char *path = (const char *) iter->data;

		key = g_strdup_printf ("%s/%s/%s", path,
				NM_SETTING_CONNECTION_SETTING_NAME,
				NM_SETTING_CONNECTION_TYPE);
		val = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (NULL == val || 0 != strcmp (val, "vpn")) {
			g_free (val);
			continue;
		}
		/* need free? */
		g_free (val);

		key = g_strdup_printf ("%s/%s/%s", path,
				NM_SETTING_CONNECTION_SETTING_NAME,
				NM_SETTING_CONNECTION_UUID);
		val = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (NULL == val || 0 != strcmp (val, vpn_uuid)) {
			g_free (val);
			continue;
		}
		/* need free? */
		g_free (val);

		/* Woo, found the connection */
		connection_path = g_strdup ((char *) iter->data);
		break;
	}

	if (NULL != connection_path) {
		key = g_strdup_printf ("%s/%s/%s",
				connection_path,
				NM_SETTING_VPN_SETTING_NAME,
				NM_NOVELLVPN_KEY_GATEWAY);
		val = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (NULL != val) {
			strcpy (search_keys[0], val);
		}
		g_free (val);

		key = g_strdup_printf ("%s/%s/%s",
				connection_path,
				NM_SETTING_VPN_SETTING_NAME,
				NM_NOVELLVPN_KEY_GROUP_NAME);
		val = gconf_client_get_string (gconf_client, key, NULL);
		g_free (key);

		if (NULL != val) {
			strcpy (search_keys[1], val);
		}
		g_free (val);
		g_free (connection_path);
	}

	/* g_free() each string in the list, then g_slist_free() the list itself */
	g_slist_foreach (conf_list, (GFunc) g_free, NULL);
	g_slist_free (conf_list);

	strcpy(search_keys[2], "not_found");
	search_in_the_directory(search_keys);
	strcpy(vendor_file_name_to_read, search_keys[2]);

	g_object_unref (gconf_client);
}


int dir_check(char *string)
{
	struct stat buf;

	if(lstat(string,&buf)<0)
	{
		return 0;
	}
	else if(!S_ISDIR(buf.st_mode) || (buf.st_size==0)) 
	{
# if __DEBUG__ == 1
		fprintf(stderr, "file size zero\n");
# endif
		return 0;
	}
	return 1;
}

void copyProfiles(void)
{
	DIR  *dd; 
	struct dirent *dirp; 
	char cmd[256] = {'\0'};
	char turnpike_directory[256] = {'\0'};
	char SYSTEM_PROFILE_PATH[] =  "/etc/turnpike/profiles/";
	char SYSTEM_VENDOR_PROFILE_PATH[] =  "/etc/turnpike/vendorprofiles/" ;
	char profile_path[256] = {'\0'};
	char vendor_profile_path[256] = {'\0'};
	char pfx_file_path[256] = {'\0'};

	sprintf(turnpike_directory, "%s/%s", getenv("HOME"), ".turnpike");

	strcpy(profile_path, turnpike_directory);
	strcat(profile_path, "/");
	strcat(profile_path, "profiles");

	strcpy(vendor_profile_path, turnpike_directory);
	strcat(vendor_profile_path, "/");
	strcat(vendor_profile_path, "vendorprofiles");

	strcpy(pfx_file_path, turnpike_directory);
	strcat(pfx_file_path,  "/");
	strcat(pfx_file_path, "usercerts");

	if(dir_check(profile_path) == 0)
	{
		char tmp[256] = {'\0'};
		strcpy(tmp, "install -m 755 -d ");
		strcat(tmp, profile_path);
		if (system(tmp)) {
			fprintf(stderr, "system(%s) error!\n", tmp);
		}
	}

	if(dir_check(vendor_profile_path) == 0)
	{
		char tmp[256] = {'\0'};
		strcpy(tmp, "install -m 755 -d ");
		strcat(tmp, vendor_profile_path);
		if (system(tmp)) {
			fprintf(stderr, "system(%s) error!\n", tmp);
		}
	}
	if(dir_check(pfx_file_path) == 0)
	{
		char tmp[256] = {'\0'};
		strcpy(tmp, "install -m 755 -d ");
		strcat(tmp, pfx_file_path);
		if (system(tmp)) {
			fprintf(stderr, "system(%s) error!\n", tmp);
		}
	}
	if(dir_check(SYSTEM_PROFILE_PATH) == 1)
	{
		dd = opendir(SYSTEM_PROFILE_PATH);
		if (dd == NULL)
		{
			return;
		}
		while((dirp = readdir(dd)) != NULL)
		{
			if(strstr(dirp->d_name,".prf")!=NULL)
			{
				strcpy(cmd, "cp -u ");
				strcat(cmd, SYSTEM_PROFILE_PATH);
				strcat(cmd, dirp->d_name);
				strcat(cmd , " ");
				strcat(cmd, profile_path);
				if (system(cmd)) {
					fprintf(stderr, "system(%s) error!\n", cmd);
				}
			}
		}

	}

	if(dir_check(SYSTEM_VENDOR_PROFILE_PATH) == 1)
	{
		dd = opendir(SYSTEM_VENDOR_PROFILE_PATH);
		if (dd == NULL)
		{
			return;
		}
		while((dirp = readdir(dd)) != NULL)
		{
			if(strstr(dirp->d_name,".prf")!=NULL)
			{
				strcpy(cmd, "cp -u ");
				strcat(cmd, SYSTEM_VENDOR_PROFILE_PATH);
				strcat(cmd, dirp->d_name);
				strcat(cmd , " ");
				strcat(cmd, vendor_profile_path);
				if (system(cmd)) {
					fprintf(stderr, "system(%s) error!\n", cmd);
				}
			}
		}
	}
	return;
}

int isFileExist(char *string)
{
	struct stat buf;

	if(lstat(string,&buf)<0) 
	{
		return -1;
	}
	else if(!S_ISREG(buf.st_mode) || (buf.st_size==0)) 
	{
		return -1;
	}
	return 0;
}

char* check_for_group_password_in_profile(char *vpn_uuid)
{
	char fileName[256] = {'\0'};

	xmlNode *root = NULL;
	xmlNode *cur_node, *grouppasswd_node;
	xmlChar *buffer;
	xmlDocPtr doc;
	xmlChar *key;	
	DIR *dd;
	char vendor_file_name_to_read[100] = {'\0'};	
	sprintf(fileName, "%s/%s", getenv("HOME"), ".turnpike");	
	dd = opendir(fileName);
	if (dd == NULL)
	{
		copyProfiles();
	}

	strcat(fileName, "/vendorprofiles/");
	get_the_vendor_file_name(vendor_file_name_to_read, vpn_uuid);
	if(strcmp(vendor_file_name_to_read, "not_found") == 0)
	{
		fprintf(stderr, "vendor_file not found\n");
		return NULL;
	}
	strcat(fileName, vendor_file_name_to_read);

	if(isFileExist(fileName))
	{
		return NULL;
	}

	doc = xmlParseFile(fileName);
	if (doc == NULL)
	{
		fprintf(stderr, "XML_PARSE_FAILED\n");
		return NULL;
	}

	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(xmlChar*)"vendor"))
	{
		fprintf(stderr, "INVALID_PROFILE\n");
		xmlFreeDoc(doc);
		return NULL;
	}
	buffer= xmlGetProp(root,(xmlChar*)"vendorname");

	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next)
	{
		if ( cur_node->type == XML_ELEMENT_NODE  )
		{
			if(strcmp((const char*)cur_node->name, "grouppasswd") == 0)
			{
				grouppasswd_node = cur_node->xmlChildrenNode;
				if(grouppasswd_node != NULL)
				{
					key = xmlNodeListGetString(doc, grouppasswd_node, 1);
					return (char*)key;
				}
				break;
			}
		}
	}
	return NULL;
}

