
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
#include <netdb.h>
#include <errno.h>
#include <pwd.h>
#include <termios.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
/* cli headers */
#include "utility.h"
#include "vpncErrorHandling.h"
#include "cliErrors.h"
#include "commoncli.h"
#include "getip.h"
#include "CommonUI.h"
#include "racoonconf.h"
/* Racoon Headers */
#include "racoon/admin.h"

#define PASSWORD_STRING_LENGTH 256

extern Inf_t Inf;
extern char errStr[];
char PLOG_FILE[MAX_STRING_LEN] = { '\0' };
extern char* errString(int, char*);
extern int getCertificateNameFromProfile();
extern int getGatewayType();
extern int vpnExtCerts(const char *pfxFilePath, const char *password);
extern int loadmodule(const char *file_name);

int getPassword (char *password)
{
	struct termios termiosPointer;
	struct  termios oldTermiosPointer;
	int ret = 0;
	
	tcgetattr (0, &termiosPointer);
	oldTermiosPointer=termiosPointer;
	printf(_("Certificate Password :"));
	termiosPointer.c_lflag &=(~ECHO);
	tcsetattr(0, TCSANOW, &termiosPointer);
        
	ret = scanf("%s",password);
	if (ret != 1)
		fprintf (stderr, "Certificate Password scanf error.\n");
       
	tcsetattr(0, TCSANOW, &oldTermiosPointer);
	printf("\n");
	return 0;
}

void printLine()
{
	printf("------------------------------------------------------------------\n");
}

void syntax(void)
{
	printf(_("Try \'nvpn --help or nvpn -h\' for usage.\n"));
}

void usage(void)
{

	printf(_("Command Line Interface for VPN Client .\n\n"));
	
	printf(_("Usage: nvpn OPTION\n   or: nvpn OPTION ARGUMENT\n\n"));

	printf(_("If a long option shows an argument as mandatory, then it is mandatory\n"));
	printf(_("for the equivalent short option also.\n\n"));
	printf(_("  -l, --list			        lists the available profiles \n"));
	printf(_("  -c, --connect PROFILENAME	        connects to the VPN gateway configured\n"));
	printf(_("				        in the PROFILENAME\n"));
	printf(_("  -d, --disconnect 	                disconnects from the VPN gateway\n"));
	printf(_("  -h, --help 		                displays this help \n"));
	printf(_("  -v, --verbose			        displays detailed log when used \n"));
	printf(_("				        with [-c,--connect] option\n"));
	printf(_("  -p, --create_vendor_profile PROFILENAME  creates vendor profile \n"));
	printf(_("  -g, --dhgroup dhgroup_value		connects to the vpn gateway using  \n"));
	printf(_("					this dhgroup value \n"));
	printf(_("  -s, --pfsgroup pfsgroup_value	connects to the vpn gateway using  \n"));
	printf(_("					this pfsgroup value \n"));
	printf(_("  -t, --nosplittunel			disable split tunnel\n"));
	printf(_("  -u, --up	UPSCRIPT NAME	script to be executed by the VPN Client \n"));
}

void get_connect_client_sock(char * connect_client_sock)
{
	strcat(connect_client_sock, TURNPIKE_DIR"cliClient.sock");
}

void get_connect_client_event_poll_sock(char* connect_client_event_poll_sock)
{
	strcat( connect_client_event_poll_sock, TURNPIKE_DIR"clieventpoll.sock");
}

void printing_function (char* string)
{
	printf("%s",string);
}

void handle_sigint(int signum)
{
	/* Handle SIGINT (^c) */
	disconnectHandler(1); //Argument implies that the call comes from sigint
	exit(0);	
}

int connectHandler()
{
	//extern Inf_t Inf;
	char password[MAX_STRING_LEN] = { '\0' };
	char certNameWithFullPath[MAX_PATH_LEN] = {'\0'};
	char lib_path_name[MAX_PATH_LEN] = {'\0'};
	char authentication_type_string[MAX_PATH_LEN] = {'\0'};
	struct interfaceInfo *ifInfo = NULL;
	struct racoon_conf *rcbuf = NULL;
	int ret = 0;
	
	signal(SIGINT,handle_sigint); 

	/* Check the input mode : profile file or stdin? */
	if (Inf.withProfileFile)
	{
		/* Input mode is profile file */
		if(isProfileExist()<0)
		{
			fprintf (stderr, errString (PROFILE_FILE_DOES_NOT_EXIST,errStr),Inf.profileName);
			exit(1);
		}
	
		if(getGatewayType()<0)
		{
			fprintf (stderr, errString (BAD_PROFILE,errStr),Inf.profileName);
			exit(1);
		}
		if(getGatewayAddress(TRUE)<0)
		{
			fprintf (stderr, errString (BAD_PROFILE,errStr),Inf.profileName);
			exit(1);
		}
		if(!Inf.isStandardGateway)
		{
			if(getAuthType()<0)
			{
				fprintf (stderr, errString (BAD_PROFILE,errStr),Inf.profileName);
				exit(1);
			}
		}
		else
			Inf.authentication_type = CERTIFICATE;
	}
	else
	{
		/* Input Mode is stdin */
		ret = scanf("IPSec gateway %s\n",Inf.serverIPAddr);
		if (ret != 1)
			fprintf (stderr, "IPSec gateway scanf error.\n");
		ret = scanf("IPSec gateway type %s\n",Inf.gatewayType);
		if (ret != 1)
			fprintf (stderr, "IPSec gateway type scanf error.\n");
		ret = scanf("Authentication type %s\n",authentication_type_string);
		if (ret != 1)
			fprintf (stderr, "Authentication type scanf error.\n");
		
		if( strcmp(authentication_type_string, "XAUTH") == 0)
		{
			Inf.authentication_type = XAUTH;
		}
		else if( strcmp(authentication_type_string, "X509") == 0)
		{
			Inf.authentication_type = CERTIFICATE;
		}

		if( strcmp(Inf.gatewayType, "standard-gateway") == 0)
		{
			Inf.isStandardGateway = 1;
		}
		else 
		{
    			Inf.isStandardGateway = 0;
		}

		/*
		 * Set the User Environment 
		 * FIX ME: Not all the variables are mandatory to set in setUserEnv
		 *			Need to categorize according to the gateway type and 
		 *			input mode
		 */
	    	setUserEnv(&Inf);
	}
        strcpy(Inf.selectedProfile, Inf.profile_path);
        strcat(Inf.selectedProfile, Inf.profileName);

	if(Inf.isStandardGateway)
	{
		/*********************Condition start*******************/
		if(Inf.withProfileFile)
		{
			if(getCertificateNameFromProfile()<0)
			{
				fprintf (stderr, errString (BAD_PROFILE,errStr),Inf.profileName);
				exit(1);
			}
		
			/* Make the cert name with full path */
			sprintf(certNameWithFullPath, "%s%s", Inf.pfx_file_path,Inf.certFileName);
		}
		
		else
		{
			ret = scanf("Certificate Name %s\n",certNameWithFullPath);
			if (ret != 1)
				fprintf (stderr, "Certificate Name scanf error.\n");
		}
		/*********************Condition end*******************/

		/* Check for the existency of cert file */
		if(isFileExist(certNameWithFullPath)<0)
		{
			fprintf (stderr, errString (CERT_PATH_DOES_NOT_EXIST,errStr),certNameWithFullPath);
			exit(1);
		}
		
		/*********************Condition start*******************/
		if(Inf.withProfileFile)
		{
			/*Prompt for Password*/
			getPassword(password);
		}
		else
		{
			char buffer[PASSWORD_STRING_LENGTH] = {'\0'};
			if( fgets(buffer, sizeof(buffer), stdin) == NULL)
				exit(1);
			else
			{
				if(strncmp("Certificate Password ", buffer, strlen("Certificate Password ")) == 0)
				strncpy(password, &(buffer[strlen("Certificate Password ")]), 
					strlen(&(buffer[strlen("Certificate Password ")]))-1);
			}
			/*{
				char * temp = NULL;
				temp = (char*)malloc(strlen(password) + 1);
				strcpy(temp, &(password[2]));
				strcpy(password, temp);
				free(temp);
			}*/
			{
				int i = 0;
				int size_of_certNameWithFullPath = strlen(certNameWithFullPath);
				for(i = size_of_certNameWithFullPath; certNameWithFullPath[i] != '/'; i--)
				{
					;
				}
				i++;
				strcpy(Inf.certFileName, &(certNameWithFullPath[i]));
				i--;
				strncpy(Inf.pfx_file_path, certNameWithFullPath,i); 
			}
		}
		/*********************Condition end*******************/
		/*Extract Certificate*/
		if(vpnExtCerts(certNameWithFullPath,password)!=0)
		{
			fprintf (stderr, errString (FAILED_TO_EXTRACT_CERT,errStr));
			exit(1);
		}
		/* Get Server IP from Profile */
	/*	if(getGatewayAddress(Inf.profileName)<0)
		{
			fprintf (stderr, errString (BAD_PROFILE,errStr),Inf.profileName);
			remove(Inf.userCert);
			remove(Inf.userPvtKey);
			exit(1);
		}*/
		
		/* Check if DNS resolution is required for Gateway Address */
		if (!getIPAddrFromGatewayDnsName(&Inf))
		{
			remove(Inf.userCert);
			remove(Inf.userPvtKey);
			exit(1); //Already error message is printed in the above functions
		}
		/* Update Source IP */
		getsourceip(&Inf);

		if( (writeRacoonConfFile(&Inf)) < 0)
			exit(1);
		
		/* Connect to Server's admin Port  */
		if(connectToServer(&Inf, 0)<0)
		{
			fprintf(stderr, errString(FAILED_TO_CONNECT_TO_GATEWAY,errStr));
			remove(Inf.userCert);
			remove(Inf.userPvtKey);
			exit(1);
		}
		printf(_("Connection in progress.. "));
				
		/* Do event poll */
		if(startEventPoll(&Inf, 0)<0)
		{
			remove(Inf.userCert);
			remove(Inf.userPvtKey);
			exit(1);
		}
	}
	else
	{
		/* Plugin stuff */
	
		/* TODO: Later make the path configurable*/
		sprintf(lib_path_name,LIB_LOAD_PATH"/libcli%s.so",Inf.gatewayType);
		if (Inf.isVerbose)
		{
			printf(_("Loading module : %s\n"),lib_path_name);
		}
		loadmodule(lib_path_name);
			
		/* Check if DNS resolution is required for Gateway Address */
		if (!getIPAddrFromGatewayDnsName(&Inf))
			exit(1);//Already error message is printed in the above functions
	
		/* Update Source IP */
		if(getsourceip(&Inf)<0)
			exit(1);
			
		/* Init Plugin */
		if (create_cp((void**)&ifInfo) < 0)
			exit(1);
			
		if (Inf.plugin_cli_init)
		{
			Inf.plugin_cli_init(ifInfo, &Inf.pluginInfo);
			if(ifInfo)
			{
				if(ifInfo->admin_port_socket_name)
					free(ifInfo->admin_port_socket_name);
				if(ifInfo->gateway_type)
					free(ifInfo->gateway_type);
				if(ifInfo->profile_name)
					free(ifInfo->profile_name);
				if(ifInfo->upscript)
					free(ifInfo->upscript);
				free(ifInfo);
			}
		}
			
		/*
		 *  FIXME: Since Multiple Proposal is implemented create_rcbuf is not required
		 *			However since dhgroup is not yet automatically selected we can choose
		 *			to keep this so as to be compliant with the older versions
		 */
		if (Inf.withProfileFile)
		{
			create_rcbuf(&Inf,&rcbuf);
	
			if(Inf.argumentMask & DHGROUP)
			{
				rcbuf->ph1Config.dh_group = Inf.dh_group;
			}

			if(Inf.argumentMask & PFSGROUP)
			{
				rcbuf->ph2Config.pfs_group = Inf.pfs_group;
			}
		}

		if(Inf.authentication_type == CERTIFICATE )
		{
			if(Inf.withProfileFile)
			{
				if(getCertificateNameFromProfile()<0)
				{
					fprintf (stderr, errString (BAD_PROFILE,errStr),Inf.profileName);
					exit(1);
				}
		
				/* Make the cert name with full path */
				sprintf(certNameWithFullPath, "%s%s", Inf.pfx_file_path,Inf.certFileName);
			}
		
			else
			{
				ret = scanf("Certificate Name %s\n",certNameWithFullPath);
				if (ret != 1)
					fprintf (stderr, "Certificate Name scanf error.\n");
			}
			/*********************Condition end*******************/

			/* Check for the existency of cert file */
			if(isFileExist(certNameWithFullPath)<0)
			{
				fprintf (stderr, errString (CERT_PATH_DOES_NOT_EXIST,errStr),certNameWithFullPath);
				exit(1);
			}
		
			/*********************Condition start*******************/
			if(Inf.withProfileFile)
			{
				/*Prompt for Password*/
				getPassword(password);
			}
			else
			{
				char buffer[PASSWORD_STRING_LENGTH] = {'\0'};
				if( fgets(buffer, sizeof(buffer), stdin) == NULL)
					exit(1);
				else
				{
					if(strncmp("Certificate Password ", buffer, strlen("Certificate Password ")) == 0)
					strncpy(password, &(buffer[strlen("Certificate Password ")]), 
						strlen(&(buffer[strlen("Certificate Password ")]))-1);
				}
				/*{
					char * temp = NULL;
					temp = (char*)malloc(strlen(password) + 1);
					strcpy(temp, &(password[2]));
					strcpy(password, temp);
					free(temp);
				}*/
				{
					int i = 0;
					int size_of_certNameWithFullPath = strlen(certNameWithFullPath);
					for(i = size_of_certNameWithFullPath; certNameWithFullPath[i] != '/'; i--)
					{
						;
					}
					i++;
					strcpy(Inf.certFileName, &(certNameWithFullPath[i]));
					i--;
					strncpy(Inf.pfx_file_path, certNameWithFullPath,i); 
				}
			}

			if(vpnExtCerts(certNameWithFullPath,password)!=0)
			{
				fprintf (stderr, errString (FAILED_TO_EXTRACT_CERT,errStr));
				exit(1);
			}
		}

		if( Inf.plugin_write_racoon_conf_for_reparse)
		{
			Inf.plugin_write_racoon_conf_for_reparse(rcbuf, Inf.pluginInfo);
			if(Inf.withProfileFile)
				free(rcbuf);
		}
		else
		{
			fprintf (stderr, errString (PLUGIN_REPARSE_FUNC_MISSING,errStr),lib_path_name);
		}
	
		/* Connect to Server's admin Port  */
		if(connectToServer(&Inf, 0)<0)
		{
			fprintf(stderr, errString(FAILED_TO_CONNECT_TO_GATEWAY,errStr));
			exit(1);
		}
		printf(_("Connection in progress.. "));
		/* Do event poll */
		startEventPoll(&Inf,0);
	}
	return 0;
}

int disconnectHandler(int caller)
{
	/* 
		caller = 0 ==> function called from command handler
	   	caller = 1 ==> function called from sigint handler
	 */
	 
	/* Read the LastSuccessfulprofile file to get to  know the connected gateway */
	
	//extern Inf_t Inf;

	/*
		When called from command prompt, we need to load the last successful
		profile as we do not have any info.

		When handling sigint, 1. We already have the info, 2. we might not have
		yet written the last successful profile to the disk
	*/
	char LastProfile[MAX_STRING_LEN] = { '\0' };

	if( caller == 0)
	{
		if (Inf.withProfileFile)
		{
			if(setUserEnv(&Inf)<0)
			{
				fprintf (stderr, errString (CAN_NOT_SET_USR_ENV,errStr));
				return -1;
			}
	
			strcpy(LastProfile, "profile_");
			loadLastSuccessfulProfile(&Inf);
			strcat(LastProfile, Inf.lastProfile);
			strcat(LastProfile, ".prf");
			strcpy(Inf.profileName, LastProfile);

			if(getGatewayAddress(FALSE)<0)
			{
				fprintf (stderr, errString (BAD_PROFILE,errStr),Inf.profileName);
				exit(1);
			}
		}
	}

	/* Check if DNS resolution is required for Gateway Address */
	if (!getIPAddrFromGatewayDnsName(&Inf))
	{
		remove(Inf.userCert);
		remove(Inf.userPvtKey);
//		exit(1);//Already error message is printed in the above functions
	}
	remove(Inf.userCert);
	remove(Inf.userPvtKey);
	if (!disconnectServer(&Inf, 0))
	{
		printf(_("VPN client is successfully disconnected from the gateway %s\n"),Inf.serverIPAddr);
	}
	else
	{
		printf(_("Failed to disconnect from the gateway %s\n"),Inf.serverIPAddr);
	}
	return 0;
}

int
getGatewayAddress (boolean_t resolve)
{	
	xmlNode *cur_node = NULL;
	xmlChar *buffer = NULL;
	xmlDocPtr doc;
        boolean_t save_profile = FALSE;
	
	char profilename[MAX_STRING_LEN] = {'\0'};
	
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
	
	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar*)"profile")) 
	{ 
		fprintf (stderr, errString (BAD_PROFILE,errStr), profilename);
		xmlFreeDoc(doc);
		return -1;
	}
	
	/* Find the name */
	for(cur_node = root; cur_node != NULL; cur_node = cur_node->next) 
	{
		if (cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "profile")) 
		{  
			buffer= xmlGetProp(cur_node,(const xmlChar*)"name");
		}
	}

	xmlFree(buffer);	
	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) 
	{
		if ( cur_node->type == XML_ELEMENT_NODE  ) 
		{  
			if(strcmp((const char*)cur_node->name, "gateway_ip") == 0)
			{
                                /* for disconnection, we might not be able to reach nameserver
                                   if "mandatory tunnelling is enabled. so read resolved one for 
                                   disconnection.
                                */
                                buffer = NULL;

                                buffer = resolve || (buffer = xmlGetProp (cur_node, (const xmlChar *) "resolved")) == NULL ?
                                        xmlNodeGetContent(cur_node): buffer;

				if(buffer)
				{
					if (Inf.isVerbose)
                                                printf(_("Gateway IP: %s\n"),(const char*)buffer);
					strcpy(Inf.serverIPAddr,(const char*)buffer);
                                        if (resolve && getIPAddrFromGatewayDnsName(&Inf)) {
                                                if (strcmp ( (const char *) buffer, Inf.serverIPAddr) != 0) {
                                                        if (xmlSetProp (cur_node, (const xmlChar *) "resolved", 
                                                                        (const xmlChar *) Inf.serverIPAddr))
                                                                save_profile = TRUE;
                                                }
                                        }
					xmlFree(buffer);
					buffer=NULL;
				}
			}
		}
	}
	
	xmlCleanupGlobals();
	xmlCleanupParser();
        if (save_profile)
                xmlSaveFile(profilename, doc);
	xmlFreeDoc(doc);
	return 0;
}

int create_cp(void **cp)
{
	struct interfaceInfo *ifInfo = NULL;
	struct in_addr temp_addr;
	
	ifInfo = malloc(sizeof(struct interfaceInfo));
	
	if (!ifInfo)
		return -1;
	
	*cp = ifInfo;

	memset(ifInfo,0,sizeof(struct interfaceInfo));
	
	inet_aton( Inf.sourceIPAddr ,&temp_addr);
	ifInfo->source_ip_addr = temp_addr.s_addr;
	inet_aton( Inf.serverIPAddr ,&temp_addr);
	ifInfo->server_ip_addr = temp_addr.s_addr;
	
	ifInfo->admin_port_socket_name_len = strlen(ADMINSOCK_PATH) + 1;
	ifInfo->admin_port_socket_name = malloc(ifInfo->admin_port_socket_name_len);
	strcpy(ifInfo->admin_port_socket_name, ADMINSOCK_PATH);
	ifInfo->gateway_type_len = strlen(Inf.gatewayType) + 1;
	ifInfo->gateway_type = malloc(ifInfo->gateway_type_len);
	strcpy(ifInfo->gateway_type, Inf.gatewayType);

	ifInfo->authentication_type = Inf.authentication_type;	
	ifInfo->isVerbose = Inf.isVerbose;
	ifInfo->withProfileFile = Inf.withProfileFile;

	if (ifInfo->withProfileFile)
	{
		getVendorProfileName(Inf.profileName);
		ifInfo->profile_name_len = strlen(Inf.vendorfile);
		ifInfo->profile_name = malloc(strlen(Inf.vendorfile)+1);
		memcpy(ifInfo->profile_name,Inf.vendorfile,strlen(Inf.vendorfile)+1);
	}	
	
	ifInfo->dh_group = Inf.dh_group;
	ifInfo->pfs_group = Inf.pfs_group;

	if (Inf.argumentMask & UPSCRIPT)
	{
		ifInfo->upscript_len = strlen(Inf.upscript)+1;
		ifInfo->upscript = malloc(ifInfo->upscript_len);
		strcpy(ifInfo->upscript, Inf.upscript);
	}
	else
		ifInfo->upscript_len = 0;
	
	return 0;
}

int getVendorProfileName(char *file)
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
	
	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar*)"profile")) { 
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
			xmlFree(buffer);
			buffer=NULL;
			}
		}
	}
	
	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) 
	{
		if ( cur_node->type == XML_ELEMENT_NODE  ) 
		{  
			if(strcmp((const char*)cur_node->name, "vendor") == 0)
			{
				buffer = xmlNodeGetContent(cur_node);
				if(buffer)
				{
					strcpy(Inf.vendorfile, (const char*)buffer);
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

int isProfileExist()
{
    DIR  *dd = NULL; 
    struct dirent *dirp; 
    int profileFound = FALSE;
    char profilename[MAX_STRING_LEN];
    strcpy(profilename, Inf.profile_path);
    strcat(profilename, Inf.profileName);
        

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
            if(strcmp(dirp->d_name,Inf.profileName)== 0)
            {
                profileFound = TRUE;
                break;
            }
        }
        if(!profileFound)
        {
//            fprintf (stderr, errString (PROFILE_FILE_NOT_FOUND,errStr),file);
            closedir(dd);
            return -1;
        }
    }
    closedir(dd);
    return 0;
}

int loadmodule(const char *file_name) /*Needs to be Modified*/
{
	Inf.so_handle = dlopen(file_name, RTLD_LAZY);

	if (Inf.so_handle)
	{
		if (Inf.isVerbose)
		{
			printf(_("Opened %s\n"),file_name);
		}

		Inf.plugin_cli_init = dlsym(Inf.so_handle, "nortel_cli_plugin_init");
		Inf.plugin_get_privdata = dlsym(Inf.so_handle, "nortel_get_privdata");
		Inf.plugin_write_racoon_conf_for_reparse= dlsym(Inf.so_handle, "nortel_write_racoon_conf_for_reparse");
		Inf.plugin_event_handler = dlsym(Inf.so_handle, "nortel_event_handler");
		Inf.plugin_disconnect = dlsym(Inf.so_handle, "nortel_disconnect");
		Inf.plugin_get_ikeplugin_lib_path = dlsym(Inf.so_handle,"nortel_get_ikeplugin_lib_path");
		Inf.plugin_update_profile = dlsym(Inf.so_handle,"nortel_update_profile");
		Inf.plugin_create_vendor_profile = dlsym(Inf.so_handle,"nortel_create_vendor_profile");

		//* set the cli handle *
		Inf.plugin = 1;
		return 0;
	}
	printf(_("dlopen error : %s \n"), dlerror());
	Inf.plugin = 0;
	return -1;
}


/*
#if 0
static int getip( const char *destip, char *srcip, char *srcif, char *errstring)
{

	char *tmpfile = ".tmp",
         *tmperrfile = ".tmperr";
	
	if(isFileExist("/sbin/ip")!=0)
    {
		return -1;
	}
    
	if((fork()) == 0)
    {   
        // child 
		int fd = creat(tmpfile,S_IRWXU);
		dup2(fd,fileno(stdout));	
		int errfd = creat(tmperrfile,S_IRWXU);
		dup2(errfd,fileno(stderr));	
		execl("/sbin/ip","ip","route","get",destip, NULL);
		close(fd);
		close(errfd);
	}
	else
    {
		int status;
		wait(&status);
	}

	if(isFileExist(tmperrfile) == 0)
    {   
        // file exists => error  
		FILE *fp = fopen(tmperrfile,"r");
		if(fp == NULL)
        {
			remove(tmpfile);
			remove(tmperrfile);
			return -1;
		}
		fscanf(fp,"%[^\n]",errstring);
		fclose(fp);	
		remove(tmpfile);
		remove(tmperrfile);
		return -2;
	}

	char temp[SMALL_STRING_LEN];
	int i;

	FILE *fp = fopen(".tmp","r");
	if(fp == NULL)
    {
		remove(tmpfile);
		remove(tmperrfile);
		return -1;
	}
	
	for(i = 0 ; ;i++)
    {	
		if(fscanf(fp,"%s ",temp) != 1)
			break;
		if(strcmp(temp,"dev") == 0)
        {
			fscanf(fp,"%s ",temp);
			i++;
			strcpy(srcif,temp);
		}
		if(strcmp(temp,"src") == 0)
        {
			fscanf(fp,"%s ",temp);
			i++;
			strcpy(srcip,temp);
		}
			
	}
	
	fclose(fp);		

	remove(tmpfile);
	remove(tmperrfile);
	return 0;
}
#endif
*/

int getAuthType()
{
	xmlNode *cur_node, *policy_node = NULL, *ph1_node = NULL, *ph1p_node = NULL;
	xmlChar *buffer;
	xmlDocPtr doc;

	char profilename[MAX_STRING_LEN] = {'\0'};

	/* parse the xml file */
	strcpy(profilename, Inf.profile_path);
	strcat(profilename, Inf.profileName);

	doc = xmlParseFile(profilename);

	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar*)"profile")) { 
		xmlFreeDoc(doc);
		return -1;
	}

	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) 
	{
		if ( cur_node->type == XML_ELEMENT_NODE  ) 
		{  
			if(strcmp((const char*)cur_node->name, "policies") == 0)
			{
				policy_node = cur_node;
				break;
			}
		}
	}

	if(policy_node)
	{
		for(cur_node = policy_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "phase1") == 0)
				{
					ph1_node = cur_node;
					break;
				}
			}
		}

	}	
	if(ph1_node)
	{
		for(cur_node = ph1_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "proposals") == 0)
				{
					ph1p_node = cur_node;
				}
			}
		}
	}

	if(ph1p_node)
	{
		for(cur_node = ph1p_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "entry") == 0)
				{

					buffer= xmlGetProp(cur_node,(const xmlChar*)"authmethod");
					if(buffer)
					{
						if(strcmp((const char*)buffer, "X.509") == 0)
							Inf.authentication_type = CERTIFICATE;
						else
							Inf.authentication_type = XAUTH;
						xmlFree(buffer);
					}

				}
			}
		}
	}
	return 0;
}

