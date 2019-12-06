
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

#include<sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <netdb.h>
#include <errno.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

/* Racoon headers */
#include "racoon/admin.h"
#include "racoon/oakley.h"
#include "racoon/evt.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"

#include "CommonUI.h"
/* XML Parser headers*/
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

/* cli headers */
//#include "cli.h"
#include "profile.h"
#include "utility.h"
#include "cliErrors.h"
#include "vpncErrorHandling.h"

/*  globals */
char errStr[MAX_STRING_LEN];
extern char* errString(int, char*);

struct Evtmsg evtmsg[] = {
        { EVTT_PHASE1_UP, "Phase 1 established", INFO },
        { EVTT_PHASE1_DOWN, "Phase 1 deleted", INFO },
        { EVTT_XAUTH_SUCCESS, "Xauth exchange passed", INFO },
        { EVTT_ISAKMP_CFG_DONE, "ISAKMP mode config done", INFO },
        { EVTT_PHASE2_UP, "Phase 2 established", INFO },
        { EVTT_PHASE2_DOWN, "Phase 2 deleted", INFO },
        { EVTT_DPD_TIMEOUT, "Peer not reachable anymore", ERROR },
        { EVTT_PEER_NO_RESPONSE, "Peer not responding", ERROR },
        { EVTT_PEER_DELETE, "Peer terminated security association", ERROR },
        { EVTT_RACOON_QUIT, "Racoon terminated", ERROR },
        { EVTT_OVERFLOW, "Event queue overflow", ERROR },
        { EVTT_XAUTH_FAILED, "Xauth exchange failed", ERROR },
        { EVTT_PEERPH1AUTH_FAILED, "Peer failed phase 1 authentication ""(certificate problem?)", ERROR },
        { 0, NULL, UNSPEC },
};

extern Inf_t Inf;
/* TODO: Need to check if these can be consumed from ipsectools  */

/*int getVendorProfileName(char *file)
{
    int i = 0;
    int profileFound = FALSE;
    

    xmlNode *cur_node = NULL, *child_node = NULL, *policy_node, *ph1_node = NULL, *ph2_node = NULL;
    xmlChar *buffer = NULL,*buffer1 = NULL;
    xmlDocPtr doc;

    char profilename[MAX_STRING_LEN] = {'\0'};

	
    // parse the xml file
    strcpy(profilename, Inf.profile_path);
    strcat(profilename, file);

    doc = xmlParseFile(profilename);
    if (doc == NULL) 
    {
        fprintf (stderr, errString(CAN_NOT_XML_PARSE_FILE,errStr), profilename);
        return -1;
    }

    // Get the root element node 
    xmlNode *root = NULL;
    root = xmlDocGetRootElement(doc);

    if( !root || !root->name ||xmlStrcmp(root->name,"profile")) { 
        fprintf (stderr, errString(BAD_PROFILE,errStr), profilename);
        xmlFreeDoc(doc);
        return -1;
    }


    // Find the name 
    for(cur_node = root; cur_node != NULL; cur_node = cur_node->next) 
    {
        if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "profile")) 
        {  
            buffer= xmlGetProp(cur_node,"name");
            if(buffer)
            {
                xmlFree(buffer);
                buffer=NULL;
            }
        }
    }

    for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) 
    {
        if ( cur_node->type == XML_ELEMENT_NODE  ) 
        {  
	    if(strcmp(cur_node->name, "vendor") == 0)
	    {
		    buffer = xmlNodeGetContent(cur_node);
		    if(buffer)
		    {
			    strcpy(Inf.vendorfile, buffer);
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
}*/


static int displayGatewayTypeAndAddress(char *file)
{	
    xmlNode *cur_node = NULL;
    xmlChar *buffer = NULL;
    xmlDocPtr doc;

    char profilename[MAX_STRING_LEN] = {'\0'};

    /* parse the xml file */
    strcpy(profilename, Inf.profile_path);
    strcat(profilename, file);

    doc = xmlParseFile(profilename);
    if (doc == NULL) 
    {
        fprintf (stderr, errString (CAN_NOT_XML_PARSE_FILE,errStr), profilename);
        return -1;
    }

    /* Get the root element node */
    xmlNode *root = NULL;
    root = xmlDocGetRootElement(doc);

    if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar *)"profile")) { 
        fprintf (stderr, errString (BAD_PROFILE,errStr), profilename);
        xmlFreeDoc(doc);
        return -1;
    }


    /* Find the name */
    for(cur_node = root; cur_node != NULL; cur_node = cur_node->next) 
    {
        if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "profile")) 
        {  
            buffer= xmlGetProp(cur_node,(const xmlChar *)"name");
            if(buffer)
            {
                printf(_("Profile Name: %s \n"),(const char*)buffer);
                xmlFree(buffer);
                buffer = NULL;
            }
        }
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
                    printf(_("Gateway IP: %s\n"),(const char*)buffer);
                    xmlFree(buffer);
                    buffer = NULL;
                }
            }
            else if(strcmp((const char*)cur_node->name, "gateway_type") == 0)
            {
                buffer = xmlNodeGetContent(cur_node);
                        printf(_("Gateway Type: %s\n"),(const char*)buffer);

            }
        }
    }

    xmlCleanupGlobals();
    xmlCleanupParser();
    xmlFreeDoc(doc);

    return 0;
}


int displayProfileList(void)
{
    int numberofProfileFiles = 0, i;
    
    if(dir_check(Inf.profile_path) == FILE_EXIST)
    {

        numberofProfileFiles = get_dir_list(Inf.profile_path, Inf.profile_files, ".prf");
        if(numberofProfileFiles)
        {
            for(i = 0; i < numberofProfileFiles; i ++)
            {
                printf(_("\nFile Name: %s\n"), Inf.profile_files[i]);
                if(displayGatewayTypeAndAddress(Inf.profile_files[i])<0)
                {
                        fprintf (stderr, errString (CAN_NOT_XML_PARSE_FILE,errStr),Inf.profile_files[i]);
                };                                
                printLine();
            }
        }
    	else
	       fprintf (stderr, errString (PROFILE_DIRECTORY_EMPTY,errStr));
    }
    else
    {
        fprintf (stderr, errString (DIRECTORY_DOES_NOT_EXIST,errStr), Inf.profile_path);
        exit(1);
    }
    return 0;
}

/*
static int isProfileExist(char *file)
{
    DIR  *dd; 
    struct dirent *dirp; 
    int profileFound = FALSE;
    
    
    if(setUserEnv(&Inf)<0)
    {
        fprintf (stderr, errString (CAN_NOT_SET_USR_ENV,errStr));
        return -1;
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
            fprintf (stderr, errString (PROFILE_FILE_NOT_FOUND,errStr),file);
            closedir(dd);
            return -1;
        }
    }
    closedir(dd);
    return 0;
}*/


int getGatewayType()
{	
    xmlNode *cur_node;
    xmlChar *buffer = NULL;
    xmlDocPtr doc;
    xmlNode *root = NULL;

    char profilename[MAX_STRING_LEN];
    
    if(setUserEnv(&Inf)<0){
               fprintf (stderr, errString (CAN_NOT_SET_USR_ENV,errStr));
        return -1;
    }
    
    /* parse the xml file */
    strcpy(profilename, Inf.profile_path);
    strcat(profilename, Inf.profileName);

    doc = xmlParseFile(profilename);
    if (doc == NULL) 
    {
        fprintf (stderr, errString (CAN_NOT_XML_PARSE_FILE,errStr), profilename);
        return -1;
    }
    /* Get the root element node */
    root = xmlDocGetRootElement(doc);

    if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar *)"profile")) { 
         fprintf (stderr, errString (BAD_PROFILE,errStr), profilename);
        xmlFreeDoc(doc);
        return -1;
    }

    /* Find the name */
    for(cur_node = root; cur_node != NULL; cur_node = cur_node->next) 
    {
        if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "profile")) 
        {  
            buffer= xmlGetProp(cur_node,(const xmlChar *)"name");
        }
    }

    xmlFree(buffer);
    for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) 
    {
        if ( cur_node->type == XML_ELEMENT_NODE  ) 
        {  
            if(strcmp((const char*)cur_node->name, "gateway_type") == 0)
            {
                buffer = xmlNodeGetContent(cur_node);
                if(strcmp((char *)buffer, "Standard IPsec gateway") == 0){
#ifdef __DEBUG__
                    printf("STANDARD GATEWAY\n");
#endif
                    Inf.isStandardGateway = 1;
                }    
                else{
#ifdef __DEBUG__
                    printf(_("NON STANDARD GATEWAY - %s\n"), (char *)buffer);
#endif
                    Inf.isStandardGateway = 0;
                }
				strcpy(Inf.gatewayType,(const char*)buffer);
		xmlFree(buffer);
		buffer = NULL;
            }
        }
    }

    xmlCleanupGlobals();
    xmlCleanupParser();
    xmlFreeDoc(doc);
    return 0;
}

int getCertificateNameFromProfile()
{	
    //char gwTypeStr[MAX_STRING_LEN] = {'\0'};
    
    xmlNode *cur_node;
    xmlChar *buffer;
    xmlDocPtr doc;

    char profilename[MAX_STRING_LEN];
    
    if(setUserEnv(&Inf)<0){
         fprintf (stderr, errString (CAN_NOT_SET_USR_ENV,errStr));
        return -1;
    }

    /* parse the xml file */
    strcpy(profilename, Inf.profile_path);
    strcat(profilename, Inf.profileName);

    doc = xmlParseFile(profilename);
    if (doc == NULL) 
    {
        fprintf (stderr, errString (CAN_NOT_XML_PARSE_FILE,errStr), profilename);
        return -1;
    }
    /* Get the root element node */
    xmlNode *root = NULL;
    root = xmlDocGetRootElement(doc);

    if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar *)"profile")) { 
        fprintf (stderr, errString (BAD_PROFILE,errStr), profilename);
        xmlFreeDoc(doc);
        return -1;
    }


   /* Find the name */
    for(cur_node = root; cur_node != NULL; cur_node = cur_node->next) 
    {
        if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "profile")) 
        {  
            buffer= xmlGetProp(cur_node,(const xmlChar *)"name");
        }
    }

    for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) 
    {
        if ( cur_node->type == XML_ELEMENT_NODE  ) 
        {  
    /*        if(strcmp((const char*)cur_node->name, "gateway_type") == 0)
            {
                buffer = xmlNodeGetContent(cur_node);
                strcpy(gwTypeStr, (char *)buffer);
            }*/
            if(strcmp((const char*)cur_node->name, "certificate") == 0)
            {
              //  if(strcmp(gwTypeStr, "Standard IPsec gateway") != 0)
              //      continue;
                buffer = xmlNodeGetContent(cur_node);
                if(buffer)
                {
#ifdef __DEBUG__
                    printf(_("Certificate name is %s\n"),(char *)buffer);
#endif
                    memset(Inf.certFileName,0,MAX_STRING_LEN);
                    strcpy(Inf.certFileName,(const char*)buffer);
                    
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

void print_evt(char *buf, int len)
{
	struct evtdump *evtdump = (struct evtdump *)buf;
	
	int i;
	char srcstr[MAX_STRING_LEN];
	char dststr[MAX_STRING_LEN];
	
        
	for (i = 0; evtmsg[i].msg; i++)
		if (evtmsg[i].type == evtdump->type)
			break;				
	
	if (evtmsg[i].msg == NULL) 
		printf(_("Event %d: "), evtdump->type);
	else
		printf(_("%s  "), evtmsg[i].msg);
    
	if(evtdump->type == EVTT_ISAKMP_CFG_DONE)
	{
		if(Inf.plugin_event_handler)
			Inf.plugin_event_handler(evtdump->type, Inf.pluginInfo);
    }
	if(evtdump->type == EVTT_PHASE1_UP)
	{
		if (Inf.withProfileFile)
        if(writeSuccessfulProfile(&Inf, 0)<0)
                    exit(1);
                
    }
	if (evtdump->type == EVTT_XAUTH_FAILED)
	{
		printf("\n");
		fprintf(stderr, errString(AUTH_FAILED, errStr));
                fflush (stderr);
		exit(1);
	}
		
	strcpy(srcstr,
	 inet_ntoa(((struct sockaddr_in *)(&evtdump->src))->sin_addr));
	 strcpy(dststr,
		inet_ntoa(((struct sockaddr_in *)(&evtdump->dst))->sin_addr));
	if(evtdump->type == EVTT_PHASE2_UP){
		printf("%s -> %s", srcstr, dststr);
		
	}
	printf("\n");

	return ;
}


