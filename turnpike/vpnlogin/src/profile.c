
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif // HAVE_CONFIG_H

#include<sys/stat.h>
#include <dirent.h>
#include <string.h>

#include "profile.h"
#include "callbacks.h"
#include "externs.h"

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "CommonUI.h"

#include "ui-helpers.h"

/*extern struct ph2enctypes ph2encarray[] ;
extern struct ph2hashtypes ph2hasharray[] ;
extern struct ph2dhtypes ph2dharray[] ;
extern struct ph1enctypes ph1encarray[] ;
extern struct ph1hashtypes ph1hasharray[];
extern struct ph1modetypes ph1modearray[] ;
extern struct ph1dhtypes ph1dharray[] ;
extern struct ph1authtypes ph1autharray[];
extern struct Evtmsg evtmsg[] ;*/
extern Inf_t Inf;
extern char* errString(int, char*);
extern int loadpmProfile(char *file);
extern int loadmodule(char*);
extern int unloadmodule();
extern int load_plugin();
extern int setCertificatesOnpmCombo(char *profileCert);
extern void fillup_ike_ph2_params(xmlNode *policy_node);

typedef struct
{
  char   *network;
  char   *mask;
}ph2entry;

//char gwTypeStr[MIN_STRING_LEN];
int updateProfileList(int loadProfile)
{
	int numberofProfileFiles = 0, i, index = -1;
	GtkTreeIter iter;
	GtkListStore* store;
	char error_string[MAX_STRING_LEN] = {0};
	
	if(dir_check(Inf.profile_path) == FILE_EXIST)
	{
	
		g_signal_handlers_disconnect_by_func(G_OBJECT(profileCombo), G_CALLBACK(on_profileCombo_changed), NULL);
		
		store = gtk_list_store_new(1, G_TYPE_STRING);
	
/*	
		//Append Choose Profile
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,0,"Choose profile",-1);
*/	
		//Append Profile Manager 
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,0,"Profile manager",-1);	
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,0,"-----------------------------------", -1);	
		
		//numberofProfileFiles = get_dir_list(PROFILE_PATH, profile_files, ".prf");
		numberofProfileFiles = get_profile_list(Inf.profile_path, profile_files, ".prf");
		if(numberofProfileFiles)
		{
			 for(i = 0; i < numberofProfileFiles; i ++)
			{
				gtk_list_store_append (store, &iter);
				gtk_list_store_set (store, &iter,0,profile_files[i],-1);
				if(strcmp(Inf.lastProfile, profile_files[i]) == 0)
				{
					index = i;
				}
			}
		}
		gtk_combo_box_set_model((GtkComboBox *)profileCombo, (GtkTreeModel *)store);
		
		//set the first profile to be active
		//gtk_combo_box_set_active((GtkComboBox *)profileCombo,0);
		
		
		
		g_signal_connect(G_OBJECT(profileCombo), "changed", 
				G_CALLBACK(on_profileCombo_changed), NULL);
		
		if((index >= 0) && loadProfile)
			gtk_combo_box_set_active((GtkComboBox *)profileCombo,index + 2);
		else
			gtk_combo_box_set_active((GtkComboBox *)profileCombo,-1);
			
	}
	else
	{
		plog(LLV_ERROR, NULL, NULL, " Directory %s does not exist \n", Inf.profile_path);
		show_dialog_message(errString(PROFILE_DIR_DOES_NOT_EXIST, error_string));
		exit(1);
	}
	return 0;
}




int updatePmProfileList(void)
{
	int numberofProfileFiles = 0, i;
	GtkTreeIter iter;
	GtkListStore* store;
	char error_string[MAX_STRING_LEN] = {0};

	if (dir_check(Inf.profile_path) == FILE_EXIST) {
		g_signal_handlers_disconnect_by_func(
				G_OBJECT(pmprofileCombo),
			   	G_CALLBACK(on_pmprofileCombo_changed),
			   	NULL);

		store = gtk_list_store_new(1, G_TYPE_STRING);


		//Append Choose Profile
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,0,"Choose profile",-1);

		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,0,"------------------------------------",-1);

		/*		//Append Profile Manager
				gtk_list_store_append (store, &iter);
				gtk_list_store_set (store, &iter,0,"Profile Manager",-1);
				*/

		numberofProfileFiles = get_profile_list(Inf.profile_path, profile_files, ".prf");
		if(numberofProfileFiles)
		{
			for(i = 0; i < numberofProfileFiles; i ++)
			{
				gtk_list_store_append (store, &iter);
				gtk_list_store_set (store, &iter,0,profile_files[i],-1);
			}
		}
		gtk_combo_box_set_model((GtkComboBox *)pmprofileCombo, (GtkTreeModel *)store);

		//set the first profile to be active
		gtk_combo_box_set_active((GtkComboBox *)pmprofileCombo,0);

		g_signal_connect(G_OBJECT(pmprofileCombo), "changed", 
				G_CALLBACK(on_pmprofileCombo_changed), NULL);

	}
	else
	{
		plog(LLV_ERROR, NULL, NULL, " Directory %s does not exist \n", Inf.profile_path);
		show_dialog_message(errString(PROFILE_DIR_DOES_NOT_EXIST, error_string));
		exit(1);
	}
	return 0;
}

void
on_pmprofileCombo_changed (GtkComboBox *combobox, gpointer user_data)
{
	char *comboString = NULL, prfname[MAX_STRING_LEN];
	int index = -1;
	
	if ((index = gtk_combo_box_get_active ( (GtkComboBox *)combobox)) == 1) {
		gtk_widget_hide(pmNotebook);
		gtk_widget_set_sensitive(pmSavBtn, FALSE);
		gtk_widget_set_sensitive(pmremBtn, FALSE);
		gtk_widget_set_sensitive(pmAddBtn, TRUE);
		return;
	}

	comboString = get_active_text_from_combobox(combobox);
	
	if (strcmp(comboString, "Choose profile") == 0) {
		gtk_widget_hide(pmNotebook);
		gtk_widget_set_sensitive(pmSavBtn, FALSE);
		gtk_widget_set_sensitive(pmremBtn, FALSE);
		gtk_widget_set_sensitive(pmAddBtn, TRUE);
	
		return;
	} else {
		gtk_widget_show(pmNotebook);
		setpmsensitivities(PM_BEFORE_LOAD_PROFILE);
		
		strcpy(prfname, "profile_");
		strcat(prfname, comboString);
		strcat(prfname, ".prf");
		
		loadpmProfile(prfname);
	}
	
	if(comboString)
		free(comboString);	

	return;
}

int setph1ModeCombo(char *buffer)
{
	if(strcmp(buffer, "AM") == 0)
		gtk_combo_box_set_active((GtkComboBox *)pmPh1ModeCombo, 0);
	else if(strcmp(buffer, "MM") == 0)
		gtk_combo_box_set_active((GtkComboBox *)pmPh1ModeCombo, 1);
	else
		gtk_combo_box_set_active((GtkComboBox *)pmPh1ModeCombo, 1);

	return 0;
}

int setph1DhCombo(char *buffer)
{
	if(strcmp(buffer, "dh1") == 0)
		gtk_combo_box_set_active((GtkComboBox *)pmPh1DhCombo,0);
	else if(strcmp(buffer, "dh2") == 0)
		gtk_combo_box_set_active((GtkComboBox *)pmPh1DhCombo,1);
	else
		gtk_combo_box_set_active((GtkComboBox *)pmPh1DhCombo, 1);

	return 0;
}

int processpmPhase1Policies(xmlNode *policy_node)
{
	xmlNode *cur_node = NULL, *proposal_node = NULL;
	xmlChar *buffer;

	for(cur_node = policy_node->children; cur_node != NULL; cur_node = cur_node->next)
	{

			if(cur_node->type == XML_ELEMENT_NODE)
			{
				if(strcmp((const char*)cur_node->name, "proposals") == 0)
				{
					proposal_node = cur_node;
					break;
				}
			}		
	}

	for(cur_node = proposal_node->children; cur_node != NULL; cur_node = cur_node->next)
	{
		if ( cur_node->type == XML_ELEMENT_NODE  )
		{
			if(strcmp((const char*)cur_node->name, "entry") == 0)
			{
                                buffer= xmlGetProp(cur_node,(const xmlChar *)"mode");
                                if(buffer)
				{
					setph1ModeCombo((char*)buffer);
					xmlFree(buffer);
				}
                        	buffer= xmlGetProp(cur_node,(const xmlChar *)"dhgroup");
				if(buffer)
				{
					setph1DhCombo((char*)buffer);
					xmlFree(buffer);
				}
                        	buffer= xmlGetProp(cur_node,(const xmlChar *)"authmethod");
				if(buffer)
				{
                                        ui_helper_set_authmethod ((char *) buffer);
					xmlFree(buffer);
				}
			}
		}
	}


	return 0;
}


int processpmPhase15Policies (xmlNode *policy_node)
{
	xmlNode *cur_node = NULL;
	xmlChar *buffer = NULL;

	for (cur_node = policy_node->children; cur_node != NULL;
		   	cur_node = cur_node->next) {

		if (cur_node->type == XML_ELEMENT_NODE) {
			if (strcmp ((const char*)cur_node->name, "entry") == 0) {

				buffer = xmlGetProp (cur_node,
						(const xmlChar *)"nosplittunnel");
				if (buffer) {
					ui_helper_set_split_tunnel ((char*)buffer);
					if (strcmp ((char*)buffer, "yes") == 0)
						Inf.no_split_tunnel = 1;
					else
						Inf.no_split_tunnel = 0;
					xmlFree (buffer);
					break;
				}
			}
		}
	}
	return 0;
}

////////////


int setph2DhCombo(char *buffer)
{
	if(strcmp(buffer, "off") == 0)
		gtk_combo_box_set_active((GtkComboBox *)pmPh2DhCombo,0);
	else if(strcmp(buffer, "1") == 0)
		gtk_combo_box_set_active((GtkComboBox *)pmPh2DhCombo,1);
	else if(strcmp(buffer, "2") == 0)
		gtk_combo_box_set_active((GtkComboBox *)pmPh2DhCombo,2);
	else
		gtk_combo_box_set_active((GtkComboBox *)pmPh2DhCombo, 2);

	return 0;
}




//////////////

int processpmPhase2Proposals(xmlNode *policy_node)
{
	xmlNode *cur_node = NULL, *proposal_node = NULL;
	xmlChar *buffer;

	for(cur_node = policy_node->children; cur_node != NULL; cur_node = cur_node->next)
	{
			if(cur_node->type == XML_ELEMENT_NODE)
			{
				if(strcmp((const char*)cur_node->name, "proposals") == 0)
				{
					proposal_node = cur_node;
					break;
				}
			}		
	}
	if(!proposal_node)
		return -1;

	for(cur_node = proposal_node->children; cur_node != NULL; cur_node = cur_node->next)
	{
		if ( cur_node->type == XML_ELEMENT_NODE  )
		{
			if(strcmp((const char*)cur_node->name, "entry") == 0)
			{
                        	buffer= xmlGetProp(cur_node,(const xmlChar *)"pfsgroup");
				if(buffer)
				{
					setph2DhCombo((char*)buffer);
					xmlFree(buffer);
				}

			}
		}
	}



	return 0;
}

int loadpmProfile(char *file)
{
	DIR  *dd = NULL; 
	struct dirent *dirp = NULL; 
	int profileFound = FALSE;

	xmlNode *cur_node = NULL, *policy_node;
	xmlNode	*ph1_node = NULL, *ph2_node = NULL;
	xmlNode *ph15_node = NULL;
	xmlChar *buffer = NULL;
	xmlDocPtr doc;

	char profilename[MAX_STRING_LEN] = {'\0'};
	char vendorfile[MAX_STRING_LEN] = {'\0'};
	char error_string[MAX_STRING_LEN] = {0};

	if (Inf.plugin) {
		unloadmodule();
		pmPluginActive = 0;
	}

	gtk_widget_show((GtkWidget *)pmGeneralTable);
	gtk_notebook_set_current_page((GtkNotebook *)pmNotebook, 0);

	gtk_entry_set_text((GtkEntry *)pmGwEntry, "");
	gtk_widget_hide(pmAuthframe);

	if (dir_check(Inf.profile_path) == FILE_EXIST) {
		dd = opendir(Inf.profile_path);
		while ((dirp = readdir(dd)) != NULL) {
			if (strcmp(dirp->d_name,file)== 0) {
				profileFound = TRUE;
				break;
			}
		}

		if (!profileFound) {
			show_dialog_message(errString(INVALID_PROFILE, error_string));
			closedir(dd);
			return -1;
		}
	}

	closedir(dd);

	gtk_combo_box_set_active((GtkComboBox *)pmgwtypeCombo,0);
	gtk_combo_box_set_active((GtkComboBox *)pmauthenticateCombo,0);	
	gtk_combo_box_set_active((GtkComboBox *)pmauthtypeCombo,0);	
	gtk_widget_set_sensitive(pmremBtn, TRUE);
	gtk_widget_set_sensitive(pmAddBtn, FALSE);

	gtk_combo_box_set_active((GtkComboBox *)pmPh1ModeCombo, 1);
	gtk_combo_box_set_active((GtkComboBox *)pmPh1DhCombo, 1);

	gtk_combo_box_set_active((GtkComboBox *)pmPh2DhCombo, 1);

	/* parse the xml file */
	strcpy(profilename, Inf.profile_path);
	strcat(profilename, file);

	doc = xmlParseFile(profilename);
	if (doc == NULL) {
		show_dialog_message(errString(XML_PARSE_FAILED, error_string));
		return -1;
	}
	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar *)"profile")) { 
		show_dialog_message(errString(INVALID_PROFILE, error_string));
		xmlFreeDoc(doc);
		return -1;
	}

	//Find the name
	for(cur_node = root; cur_node != NULL; cur_node = cur_node->next) {
		if ( cur_node->type == XML_ELEMENT_NODE
				&& !xmlStrcmp(cur_node->name, (const xmlChar *) "profile")) {

			buffer= xmlGetProp(cur_node,(const xmlChar *)"name");
			if(buffer) {
				gtk_entry_set_text((GtkEntry *)pmprofileNameEntry,(char*) buffer);
				xmlFree(buffer);
				buffer=NULL;
			}
			gtk_widget_set_sensitive(pmprofileNameEntry, FALSE);
		}
	}

	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) {
		if ( cur_node->type == XML_ELEMENT_NODE  ) {
			if(strcmp((const char*)cur_node->name, "gateway_ip") == 0) {
				buffer = xmlNodeGetContent(cur_node);
				if(buffer) {
					gtk_entry_set_text((GtkEntry *)pmGwEntry, (char*)buffer);
					xmlFree(buffer);
					buffer=NULL;
				}
			} else if(strcmp((const char*)cur_node->name, "gateway_type") == 0) {
				buffer = xmlNodeGetContent(cur_node);
				if(strcmp((const char*)buffer, "Standard IPsec gateway") == 0) {
					if(pmPluginActive) {
						unloadmodule();
						pmPluginActive = 0;
					}
					gtk_combo_box_set_active((GtkComboBox *)pmgwtypeCombo,1);
				} else if (strcmp((char*)buffer, "nortel") == 0) {
					gtk_combo_box_set_active((GtkComboBox *)pmgwtypeCombo,2);
				}
				strcpy(Inf.gatewayType, (char*)buffer); 
			} else if(strcmp((const char*)cur_node->name, "vendor") == 0) {
				buffer = xmlNodeGetContent(cur_node);
				if(buffer) {
					strcpy(vendorfile, (const char*)buffer);
					strcpy(vendorfile, Inf.userHome);
					strcat(vendorfile, VENDOR_PROFILE_PATH1);
					strcat(vendorfile, (const char*)buffer);

					xmlFree(buffer);
					buffer = NULL;
				}
			} else if(strcmp((const char*)cur_node->name, "certificate") == 0) {
				gtk_widget_show(pmAuthframe);
				buffer = xmlNodeGetContent(cur_node);
				if ( buffer ) {
					if(!setCertificatesOnpmCombo((char*)buffer))
						gtk_widget_set_sensitive(pmSavBtn, TRUE);
					xmlFree(buffer);
					buffer = NULL;
				}	
			} else if(strcmp((const char*)cur_node->name, "policies") == 0) {
				for (policy_node = cur_node->children; policy_node != NULL; policy_node = policy_node->next) {
					if ( policy_node->type == XML_ELEMENT_NODE  ) {
						if(strcmp((const char*)policy_node->name, "phase1") == 0) {
							ph1_node =  policy_node;
						}

						if(strcmp((const char*)policy_node->name, "phase_config") == 0) {
							ph15_node =  policy_node;
						}

						if(strcmp((const char*)policy_node->name, "phase2") == 0) {
							ph2_node = policy_node;
						}
					}
				}
			}
		}
	}

	if(ph1_node)
		processpmPhase1Policies(ph1_node);
	if (ph15_node)
		processpmPhase15Policies (ph15_node);
	if(ph2_node) {
		processpmPhase2Proposals(ph2_node);
		fillup_ike_ph2_params(ph2_node);
	}
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);

	return 0;
}


int loadProfile(char *file)
{	
	DIR  *dd = NULL; 
	struct dirent *dirp; 
	int profileFound = FALSE;

	xmlNode *cur_node, *policy_node = NULL, *proposal_node = NULL, *ph1_node = NULL, *traverse_node = NULL;
	xmlChar *buffer = NULL;
	xmlDocPtr doc;
	
	char profilename[MAX_STRING_LEN];
	char error_string[MAX_STRING_LEN] = {0};

	gtk_widget_set_sensitive(gwtypeCombo, TRUE);
	setInitialSensitivities();
	if(Inf.plugin)
	{
		unloadmodule();
		pmPluginActive = 0;
	}
	
	if(dir_check(Inf.profile_path) == FILE_EXIST)
	{
	
		dd = opendir(Inf.profile_path);
		while((dirp = readdir(dd)) != NULL)
		{
			if(strcmp(dirp->d_name,file)== 0)
			{
				profileFound = TRUE;
				break;
			}
		}
		if(!profileFound)
		{
			show_dialog_message(errString(INVALID_PROFILE, error_string));
			closedir(dd);
			return -1;
		}
	}
	closedir(dd);
	/* parse the xml file */
	strcpy(profilename, Inf.profile_path);
	strcat(profilename, file);

	doc = xmlParseFile(profilename);
	if (doc == NULL) 
	{
		show_dialog_message(errString(XML_PARSE_FAILED, error_string));
		return -1;
	}
	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar *)"profile")) { 
		plog(LLV_ERROR, NULL, NULL, "root element not found\n");
		show_dialog_message(errString(INVALID_PROFILE, error_string));
		xmlFreeDoc(doc);
		return -1;
	}
	
	
	//Find the name
	for(cur_node = root; cur_node != NULL; cur_node = cur_node->next) 
	{
		if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "profile")) 
		{  
			buffer= xmlGetProp(cur_node,(const xmlChar *)"name");
		}
	}

	if(buffer)
	{
		xmlFree(buffer);
		buffer = NULL;
	}

	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) 
	{
		if ( cur_node->type == XML_ELEMENT_NODE  ) 
		{  
			if(strcmp((const char*)cur_node->name, "gateway_ip") == 0)
			{
				buffer = xmlNodeGetContent(cur_node);
				if(buffer)
				{
					gtk_entry_set_text((GtkEntry *)gwEntry, (const char*)buffer);
					xmlFree(buffer);
					buffer = NULL;
				}
			}
			else if(strcmp((const char*)cur_node->name, "gateway_type") == 0)
			{
				buffer = xmlNodeGetContent(cur_node);
				strcpy(Inf.gatewayType, (char *)buffer);
				
				if(strcmp(Inf.gatewayType, "nortel") == 0)
				{
					gtk_combo_box_set_active((GtkComboBox *)gwtypeCombo,2);
				}
				if(buffer)
				{
					xmlFree(buffer);
					buffer = NULL;
				}
			}
			else if(strcmp((const char*)cur_node->name, "certificate") == 0)
			{
				if(Inf.plugin)
					unloadmodule();
				gtk_combo_box_set_active((GtkComboBox *)gwtypeCombo,1);
				//gtk_widget_show(authenticateLabel);
				//gtk_widget_show(authenticateCombo);
				gtk_widget_show(authFrame);
				buffer = xmlNodeGetContent(cur_node);
				if(buffer)
				{
					setCertificatesOnCombo(( char*)buffer);
					xmlFree(buffer);
					buffer = NULL;
				}
				gtk_widget_grab_focus(auth2Entry);
				Inf.authentication_type = CERTIFICATE;
				if (strcmp(Inf.gatewayType, "nortel") == 0)
				{
					char Plugin[MAX_STRING_LEN] = {'\0'};
					sprintf(Plugin, LIB_LOAD_PATH"/libgui%s.so", Inf.gatewayType);
					loadmodule(Plugin) ;
				}
			}
			else if(strcmp((const char*)cur_node->name, "vendor") == 0)
			{
				buffer = xmlNodeGetContent(cur_node);
				if(buffer)
				{
					strcpy(Inf.vendorfile, Inf.userHome);
					strcat(Inf.vendorfile, VENDOR_PROFILE_PATH1);
					strcat(Inf.vendorfile, (char*)buffer);
					xmlFree(buffer);
					buffer = NULL;
				}
			}
			else if(strcmp((const char*)cur_node->name, "policies") == 0)
			{
				for(policy_node = cur_node->children; policy_node != NULL; policy_node = policy_node->next)
				{
					if ( policy_node->type == XML_ELEMENT_NODE  ) 
					{
						if(strcmp((const char*)policy_node->name, "phase1") == 0)
						{
							ph1_node = policy_node;
							break;
						}
					}
				}
			}
			if(ph1_node == NULL) continue;
			for(traverse_node = ph1_node->children; traverse_node != NULL; traverse_node = traverse_node->next)
			{
				if(traverse_node->type == XML_ELEMENT_NODE)
				{
					if(strcmp((const char*)traverse_node->name, "proposals") == 0)
					{
						proposal_node = traverse_node;
						break;
					}
				}		
			}
			if(proposal_node == NULL) continue;
			for(traverse_node = proposal_node->children; traverse_node != NULL; traverse_node = traverse_node->next)
			{
				if ( traverse_node->type == XML_ELEMENT_NODE  )
				{
					if(strcmp((const char*)traverse_node->name, "entry") == 0)
					{
		                        	buffer= xmlGetProp(traverse_node,(const xmlChar *)"authmethod");
						if(buffer)
						{
							if(strcmp((const char*)buffer, "PSK")==0)
							{
								load_plugin() ;
								Inf.authentication_type = XAUTH;
							}
							xmlFree(buffer);
						}
					}
				}
			}
		}
	}
	gtk_widget_set_sensitive(gwtypeCombo, FALSE);
	gtk_widget_set_sensitive(mainConnectBtn, TRUE);
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);
	return 0;
}
