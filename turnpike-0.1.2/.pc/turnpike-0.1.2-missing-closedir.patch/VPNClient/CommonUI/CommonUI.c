
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

#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <dirent.h>
#include <netdb.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>

#include "plog.h"

/* Racoon headers */
#include "racoon/admin.h"
#include "racoon/evt.h"
#include "racoon/oakley.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/ipsec_doi.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct admin_com comHeader_t;
typedef struct admin_com_indexes comIndexes_t;

#include "vpncErrorHandling.h"
#include "getip.h"
#include "guiErrors.h"
#include "cliErrors.h"
#include "racoonconf.h"
#include "sockInterface.h"
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "CommonUI.h"
#define TRUE 1
#define FALSE 0


char Error_string [MAX_STRING_LEN] = {0};
char errStr[MAX_STRING_LEN] = { '\0' };
in_addr_t server_addr = 0;
in_addr_t source_addr = 0;
extern char* errString(int, char*);
racoon_conf_info rbuf;

struct ph2enctypes Ph2encarray[] = {
                { OAKLEY_ATTR_ENC_ALG_DES, "des" },
                { OAKLEY_ATTR_ENC_ALG_3DES, "3des" },
                { -1, ""},
        };

struct ph2hashtypes Ph2hasharray[] = {
                { OAKLEY_ATTR_HASH_ALG_MD5, "hmac_md5" },
                { OAKLEY_ATTR_HASH_ALG_SHA, "hmac_sha1" },
                { -1, ""},
        };
struct ph2dhtypes Ph2dharray[] = {
                { 1, "1" }, //OAKLEY_ATTR_GRP_DESC_MODP768
                { 2, "2" }, //OAKLEY_ATTR_GRP_DESC_MODP1024
                { 0, "off"},
		{ -1, ""},
        };
struct ph1enctypes Ph1encarray[] = {
                { OAKLEY_ATTR_ENC_ALG_DES, "des" },
                { OAKLEY_ATTR_ENC_ALG_3DES, "3des" },
                { -1, ""},
        };

struct ph1hashtypes Ph1hasharray[] = {
                { OAKLEY_ATTR_HASH_ALG_MD5, "md5" },
                { OAKLEY_ATTR_HASH_ALG_SHA, "sha1" },
                { -1, ""},
        };

struct ph1modetypes Ph1modearray[] = {
                { ISAKMP_ETYPE_IDENT, "MM" },
                { ISAKMP_ETYPE_AGG, "AM" },
                { -1, ""},
        };

struct ph1dhtypes Ph1dharray[] = {
                { OAKLEY_ATTR_GRP_DESC_MODP768, "dh1" },
                { OAKLEY_ATTR_GRP_DESC_MODP1024, "dh2" },
                { -1, ""},
        };
struct ph1authtypes Ph1autharray[] = {
                { OAKLEY_ATTR_AUTH_METHOD_PSKEY , "PSK" },
                { OAKLEY_ATTR_AUTH_METHOD_RSASIG, "X.509" },
                { -1, ""},
        };

int setUserEnv(Inf_t* Inf_pointer)
{
	int err = 0;
	int ret = 0;
	struct passwd *pw;
	if (!(pw = getpwuid(getuid())))
		return -1;
	strcpy(Inf_pointer->userHome, pw->pw_dir);	

	strcpy(Inf_pointer->userCert, Inf_pointer->userHome);
	strcat(Inf_pointer->userCert, USERCERT);
	
	strcpy(Inf_pointer->userPvtKey, Inf_pointer->userHome);
	strcat(Inf_pointer->userPvtKey, USERPVTKEY);

	strcpy(Inf_pointer->racoon_cert_path, Inf_pointer->userHome);
	strcat(Inf_pointer->racoon_cert_path, RACOON_CERT_PATH1);
	
	strcpy(Inf_pointer->pfx_file_path, Inf_pointer->userHome);
	strcat(Inf_pointer->pfx_file_path, PFX_FILE_PATH1);

	strcpy(Inf_pointer->profile_path, Inf_pointer->userHome);
	strcat(Inf_pointer->profile_path, PROFILE_PATH1);
	
	strcpy(Inf_pointer->vendor_profile_path, Inf_pointer->userHome);
	strcat(Inf_pointer->vendor_profile_path, VENDOR_PROFILE_PATH1);
	
	strcpy(Inf_pointer->connect_client, Inf_pointer->userHome);
	(Inf_pointer->get_connect_client_sock)(Inf_pointer->connect_client);

	strcpy(Inf_pointer->connect_client_eventpoll, Inf_pointer->userHome);
	(Inf_pointer->get_connect_client_event_poll_sock)(Inf_pointer->connect_client_eventpoll);

	strcpy(Inf_pointer->racoon_conf_file, Inf_pointer->userHome);
	strcat(Inf_pointer->racoon_conf_file, RACOON_CONF_FILE1);
	
	/*strcpy(PLOG_FILE, Inf_pointer->userHome);
	strcat(PLOG_FILE, PLOG_FILE1);*/

	if(dir_check(Inf_pointer->profile_path) == FILE_NOT_EXIST)
	{
		char tmp[MAX_STRING_LEN];
		strcpy(tmp, "install -m 755 -d ");
		strcat(tmp, Inf_pointer->profile_path);
		ret = system(tmp);
		if (ret != 0)
			plog(LLV_ERROR, NULL, NULL,"system(%s) failed.\n", tmp);
		err = -1;
	}

	if(dir_check(Inf_pointer->pfx_file_path) == FILE_NOT_EXIST)
	{
		char tmp[MAX_STRING_LEN];
		strcpy(tmp, "install -m 755 -d ");
		strcat(tmp, Inf_pointer->pfx_file_path);
		ret = system(tmp);
		if (ret != 0)
			plog(LLV_ERROR, NULL, NULL,"system(%s) failed.\n", tmp);
		err = -1;
	}
	if(dir_check(Inf_pointer->vendor_profile_path) == FILE_NOT_EXIST)
	{
		char tmp[MAX_STRING_LEN];
		strcpy(tmp, "install -m 755 -d ");
		strcat(tmp, Inf_pointer->vendor_profile_path);
		ret = system(tmp);
		if (ret != 0)
			plog(LLV_ERROR, NULL, NULL,"system(%s) failed.\n", tmp);
	}
	if(Inf_pointer->withProfileFile == 1)
	{
		copyProfiles(Inf_pointer);
	}
	Inf_pointer->isUserEnvSet = 1;
	return err;
}

void loadLastSuccessfulProfile(Inf_t* Inf_pointer)
{
	char fileName[MAX_STRING_LEN];
	
	xmlNode *root = NULL;
	//xmlNode *cur_node;
	xmlChar *buffer;
	xmlDocPtr doc;
	
	strcpy(fileName, Inf_pointer->userHome);
	strcat(fileName, LASTPROFILE_FILE);
	
	if(isFileExist(fileName))
	{
		return;
	}
	
	doc = xmlParseFile(fileName);
	if (doc == NULL) 
	{
		sprintf(Error_string, errString(XML_PARSE_FAILED, errStr));
		(Inf_pointer->printing_function)(Error_string);
		xmlFreeDoc(doc);
		return;
	}
	
	/*Get the root element node */
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name, (const xmlChar*) "last_profile")) { 
		plog(LLV_ERROR, NULL, NULL,"root element not found\n");
		sprintf(Error_string, errString(INVALID_PROFILE, errStr));
		(Inf_pointer->printing_function)(Error_string);
		xmlFreeDoc(doc);
		return ;
	}
	
	buffer= xmlGetProp(root,(const xmlChar*)"name");
	if(buffer)
	{
		strcpy(Inf_pointer->lastProfile,(const char*) buffer);
	}
	xmlFree(buffer);
	xmlFreeDoc(doc);
	return;
}

int dir_check(char *string)
{
	struct stat buf;

	if(lstat(string,&buf)<0) {
		return FILE_NOT_EXIST;
	}
	else if(!S_ISDIR(buf.st_mode) || (buf.st_size==0)) {
	# if __DEBUG__ == 1
		plog(LLV_ERROR, NULL, NULL,"file size zero\n");
	# endif
		return FILE_NOT_EXIST;
	}
	return FILE_EXIST;
}

int file_check(char *string)
{
	struct stat buf;

	if(lstat(string,&buf)<0) {
		return FILE_NOT_EXIST;
	}
	else if(!S_ISREG(buf.st_mode) || (buf.st_size==0)) {
	# if __DEBUG__ == 1
		plog(LLV_ERROR, NULL, NULL,"file size zero\n");
	# endif
		return FILE_NOT_EXIST;
	}
	return FILE_EXIST;
}

int get_dir_list(char *directory,char array[][MAX_PROFILE_FILENAME_LENGTH],char *ext)
{
	DIR  *dd; 
	struct dirent *dirp; 
	int i=0;

	dd = opendir(directory);
	if (dd == NULL)
	{
	# if __DEBUG__ == 1
		plog(LLV_ERROR, NULL, NULL,"Cannot open %s\n", directory);
	# endif
	}

	while((dirp = readdir(dd)) != NULL)
	{
		if(strstr(dirp->d_name,ext)!=NULL)
		{
			strcpy(array[i++],dirp->d_name); 	
		}
	}
	array[i][0] = '\0';
	closedir(dd);
	return i;
}


int isFileExist(char *string)
{
	struct stat buf;
	
	if(lstat(string,&buf)<0) {
		return -1;
	}
	else if(!S_ISREG(buf.st_mode) || (buf.st_size==0)) {
		return -1;
	}
	return 0;
}

int getsourceip(Inf_t* Inf_pointer)
{
	char interface[20];
	//struct in_addr inaddr;
	
	//getip(&server_ip, &source_ip, &interface, &errstr);
	//getip(&server_ip_addr, &source_ip, &interface, &errstr);
	getip(Inf_pointer->serverIPAddr, Inf_pointer->sourceIPAddr, interface);
	plog(LLV_INFO, NULL, NULL,"server_ip_addr = %s\n, source_ip = %s\n", Inf_pointer->serverIPAddr, Inf_pointer->sourceIPAddr);
	//inet_pton(AF_INET, Inf_pointer->sourceIPAddr, (struct in_addr *)&(Inf_pointer->source_addr));
	inet_pton(AF_INET, Inf_pointer->sourceIPAddr, (struct in_addr *)&(source_addr));
	return 0;
}

int get_profile_list(char *directory,char array[][MAX_PROFILE_FILENAME_LENGTH],char *ext)
{
	DIR  *dd; 
	struct dirent *dirp; 
	int i=0, len = 0;
	//char profilestr[10] = "profile_";
	char temp[512];

	dd = opendir(directory);
	if (dd == NULL)
	{
	# if __DEBUG__ == 1
		plog(LLV_ERROR, NULL, NULL,"Cannot open %s\n", directory);
	# endif
	}

	while((dirp = readdir(dd)) != NULL)
	{
		if(strstr(dirp->d_name,ext)!=NULL)
		{
			if(strlen(dirp->d_name) > 256)
				continue;
			strcpy(temp, dirp->d_name);
			len = strlen(temp);
			temp[8] = '\0';
			if( strcmp(temp, "profile_") ==0 )
			{
				strcpy(temp, &dirp->d_name[8]);
				len = strlen(temp);
				temp[len-4] = '\0';
				strcpy(array[i++],temp);
			}
			
		}
	}
	array[i][0] = '\0';
	closedir(dd);
	return i;
}

int convertMaskToLength(unsigned int mask)
{
	int length = 0, i = 0;
	unsigned int testbit = 0x0001;
	
	while(i < 32)
	{	
		if(htonl(mask) & testbit)
			break;
		testbit <<= 1;
		length++;
		i++;
	}
	return (32 - length);
}

int getIPAddrFromGatewayDnsName(Inf_t* Inf_pointer)
{
	extern int h_errno;
	struct hostent *gateway_info;
	struct in_addr **pptr;
	char error_string[MAX_STRING_LEN] = {0};

	//int len = strlen(Inf_pointer->serverIPAddr);

	gateway_info = gethostbyname(Inf_pointer->serverIPAddr);
	if(gateway_info == NULL) {
		switch(h_errno) {
			case NO_ADDRESS:
				(Inf_pointer->printing_function)(
						errString(INVALID_IP, error_string));
				return FALSE;	

			case HOST_NOT_FOUND:
				(Inf_pointer->printing_function)(
						errString(GATEWAY_IP_INVALID, error_string));
				return FALSE;

			case NO_RECOVERY:
				(Inf_pointer->printing_function)(
						errString(GATEWAY_IP_INVALID, error_string));
				return FALSE;	

			case TRY_AGAIN: 
				(Inf_pointer->printing_function)(
						errString(DNS_RESOLVE_FAILED, error_string));
				return FALSE;	

			default: 
				break;
		}
	}

	pptr = (struct in_addr **)gateway_info->h_addr_list;
	if (Inf_pointer->isVerbose) {
		printf("DNS Resolution for %s is ",Inf_pointer->serverIPAddr);
	}

	server_addr = inet_addr(inet_ntoa(**pptr));	
	strcpy(Inf_pointer->serverIPAddr, (const char *)inet_ntoa(**pptr));
	if (Inf_pointer->isVerbose) {
		printf(" %s \n",Inf_pointer->serverIPAddr);
	}

	return TRUE;
}

int get_dh_group_filled(Inf_t * Inf_pointer)
{
	xmlNode *cur_node, *policy_node = NULL, *ph1_node = NULL, *ph1p_node = NULL;
	xmlChar *buffer;
	xmlDocPtr doc;
	
	doc = xmlParseFile(Inf_pointer->selectedProfile);
	if (doc == NULL) 
	{
		//show_dialog_message(errString(XML_PARSE_FAILED, errStr));
		sprintf(Error_string, errString(XML_PARSE_FAILED, errStr));
		(Inf_pointer->printing_function)(Error_string);
		return -1;
	}

	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar*)"profile")) 
	{ 
		plog(LLV_ERROR, NULL, NULL,"root element not found\n");
		//show_dialog_message(errString(INVALID_PROFILE, errStr));
		sprintf(Error_string, errString(INVALID_PROFILE, errStr));
		(Inf_pointer->printing_function)(Error_string);
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
               				buffer= xmlGetProp(cur_node,(const xmlChar*)"dhgroup");
					if(buffer)
					{
						if(strcmp((const char*)buffer, "dh1") == 0)
							Inf_pointer->dh_group = 1;
						else if(strcmp((const char*)buffer, "dh2") == 0)
							Inf_pointer->dh_group = 2;
						xmlFree(buffer);
					}
				}
			}
		}
	}
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);
	return 0;
}

int printf_ph1Config_to_racoon_conf(FILE *fp, Inf_t* Inf_pointer)
{
	if( (Inf_pointer->withProfileFile) && !(Inf_pointer->argumentMask & DHGROUP))
	{
		if((get_dh_group_filled(Inf_pointer))<0)
			return -1;
	}

	fprintf(fp, "remote %s\n", Inf_pointer->serverIPAddr);
	
	fprintf(fp, "{\n");
	fprintf(fp, "	nat_traversal on;\n");
		fprintf(fp, "	exchange_mode main, aggressive;	\n");
		fprintf(fp, "	doi ipsec_doi;\n	\
situation identity_only;\n	\
verify_cert off;\n	\
my_identifier asn1dn;\n");
		fprintf(fp, "	certificate_type x509 \"%s\" \"%s\";\n", CERTFILE, PVTKEYFILE);

	fprintf(fp, "	nonce_size 16;\n	\
initial_contact on;\n	\
proposal_check obey;	\n\n");

	write_ph1_proposal(fp, Inf_pointer->dh_group);
	fprintf(fp, "}\n");

	return 0;
}

int write_ph1_proposal(FILE *fp, int dh_group)
{
 struct ph2enctypes encarray[] ={
			{ OAKLEY_ATTR_ENC_ALG_DES, "des" }, 
			{ OAKLEY_ATTR_ENC_ALG_3DES, "3des" }, 
			{ -1, ""},
		};

 struct ph2hashtypes hasharray[] = {
			{ OAKLEY_ATTR_HASH_ALG_MD5, "md5" }, 
			{ OAKLEY_ATTR_HASH_ALG_SHA, "sha1" }, 
			{ -1, ""},
		  };

 struct ph1authtypes autharray[] = {
			{ OAKLEY_ATTR_AUTH_METHOD_PSKEY , "pre_shared_key" }, 
			{ OAKLEY_ATTR_AUTH_METHOD_RSASIG, "rsasig" }, 
			{ -1, ""},
		  };

	int  enc = 0, hash = 0, auth = 0;

	for(enc = 0; enc < MAX_ENC_TYPES; enc++)
	{
		for(hash = 0; hash < MAX_HASH_TYPES; hash++)
		{
			for(auth = 1; auth < MAX_AUTH_TYPES; auth++)
			{
				fprintf(fp, "	proposal {\n");
				fprintf(fp, "		encryption_algorithm %s;\n",encarray[enc].string);
				fprintf(fp, "		hash_algorithm %s;\n", hasharray[hash].string);
				fprintf(fp, "		authentication_method %s;\n", autharray[auth].string);
				fprintf(fp, "		dh_group %d;\n",dh_group);

				fprintf(fp, "	}\n");
			
			}
		}
	}
	return 0;
}

int get_pfs_group_filled(Inf_t* Inf_pointer)
{
	xmlNode *cur_node, *policy_node = NULL, *ph2_node = NULL, *ph2p_node = NULL;
	xmlChar *buffer;
	xmlDocPtr doc;
	
	doc = xmlParseFile(Inf_pointer->selectedProfile);
	if (doc == NULL) 
	{
		//show_dialog_message(errString(XML_PARSE_FAILED, errStr));
		sprintf(Error_string, errString(XML_PARSE_FAILED, errStr));
		Inf_pointer->printing_function(Error_string);
		return -1;
	}
	
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(xmlChar*)"profile")) { 
		plog(LLV_ERROR, NULL, NULL,"root element not found\n");
		//show_dialog_message(errString(INVALID_PROFILE, errStr));
		sprintf(Error_string, errString(INVALID_PROFILE, errStr));
		Inf_pointer->printing_function(Error_string);
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
				if(strcmp((const char*)cur_node->name, "phase2") == 0)
				{
					ph2_node = cur_node;
					break;
				}
			}
		}
		
	}
	if(ph2_node)
	{
		for(cur_node = ph2_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "proposals") == 0)
				{
					ph2p_node = cur_node;
				}
			}
		}
	}
	
	if(ph2p_node)
	{
		for(cur_node = ph2p_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "entry") == 0)
				{
                               		buffer= xmlGetProp(cur_node,(xmlChar*)"pfsgroup");
					if(buffer)
					{
						Inf_pointer->pfs_group = ph2DhValue((char*)buffer);
						xmlFree(buffer);
					}

				}
			}
		}
	}
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);
	return 0;
}

int printf_ph2Config_to_racoon_conf(FILE *fp, Inf_t * Inf_pointer)
{
  	if( (Inf_pointer->withProfileFile) && (!(Inf_pointer->argumentMask & PFSGROUP)))
	{
		if( (get_pfs_group_filled(Inf_pointer)) < 0)
			return -1;
	}

	fprintf(fp, "sainfo anonymous\n");
        fprintf(fp, "{\n");
	if(Inf_pointer->pfs_group != 0)
	        fprintf(fp, "\tpfs_group %d;\n", Inf_pointer->pfs_group);
	{
		int i = 0;
		fprintf(fp, "\tencryption_algorithm ");
		for(; i < MAX_ENC_TYPES-1; i++)
		{	
			fprintf(fp, "%s, ", Ph2encarray[i].string);
		}
                fprintf(fp, "%s;\n", Ph2encarray[i].string);
	}
        {
		int i = 0;
		fprintf(fp, "\tauthentication_algorithm ");
		for(; i < MAX_AUTH_TYPES-1; i++)
		{	
			fprintf(fp, "%s, ", Ph2hasharray[i].string);
		}
                fprintf(fp, "%s;\n", Ph2hasharray[i].string);
	}
        fprintf(fp, "\tcompression_algorithm deflate;\n");
        fprintf(fp, "}\n");
	return 0;

/*	if(ph2_node)
	{
		for(cur_node = ph2_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp(cur_node->name, "networks") == 0)
				{
					networks_node = cur_node;
					break;
				}
			}
		}
		
	}
     
	if(Inf_pointer->plugin)
	{
//		fprintf(fp, "sainfo address %s/%d[0] any address 0.0.0.0-ff.ff.ff.ff[0] any from address %s\n", source_ip, 32, server_ip_addr);
		fprintf(fp, "sainfo address %s/%d[0] any address 0.0.0.0-255.255.255.255[0] any\n", Inf_pointer->serverIPAddr, 32);
		fprintf(fp, "{\n");
		if(strcmp(pfs, "off") != 0)
		fprintf(fp, "	pfs_group %s;\n", pfs);
		fprintf(fp, "	encryption_algorithm %s;\n", enc);
		fprintf(fp, "	authentication_algorithm %s;\n", hash);
		fprintf(fp, "	compression_algorithm deflate;\n");
		fprintf(fp, "}\n");
		
		
		
//		fprintf(fp, "sainfo address 0.0.0.0-ff.ff.ff.ff[0] any address %s/%d[0] any from address %s\n", source_ip, 32, server_ip_addr);
		
		fprintf(fp, "sainfo address 0.0.0.0-255.255.255.255[0] any address %s/%d[0] any\n", Inf_pointer->serverIPAddr, 32);
		fprintf(fp, "{\n");
		if(strcmp(pfs, "off") != 0)
			fprintf(fp, "	pfs_group %s;\n", pfs);
		fprintf(fp, "	encryption_algorithm %s;\n", enc);
		fprintf(fp, "	authentication_algorithm %s;\n", hash);
		fprintf(fp, "	compression_algorithm deflate;\n");
		fprintf(fp, "}\n");
	}
	if(!Inf_pointer->plugin)*/
/*	if(networks_node)
	{
		for(cur_node = networks_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp(cur_node->name, "entry") == 0)
				{
					networkBuf= xmlGetProp(cur_node,"network");
					maskBuf= xmlGetProp(cur_node,"mask");
					if(networkBuf)
					{
						if ( inet_aton(networkBuf, &addr.sin_addr) != 0 )
						network = addr.sin_addr.s_addr;
					}
					if(maskBuf)
					{
						if ( inet_aton(maskBuf, &addr.sin_addr) != 0 )
							masklen = convertMaskToLength(addr.sin_addr.s_addr);
					}*/
					//write into conf file
				/*	fprintf(fp, "sainfo address %s/%d[0] any address %s/%d[0] any \n", Inf_pointer->serverIPAddr, 32, networkBuf, masklen);
					fprintf(fp, "{\n");
					if(strcmp(pfs, "off") != 0)
						fprintf(fp, "	pfs_group %s;\n", pfs);
					
					fprintf(fp, "	lifetime time 800 sec;\n");
					fprintf(fp, "	encryption_algorithm %s;\n", enc);
					fprintf(fp, "	authentication_algorithm %s;\n", hash);
					fprintf(fp, "	compression_algorithm deflate;\n");
					fprintf(fp, "}\n");
					
					
					
				//	fprintf(fp, "sainfo address %s/%d[0] any address %s/%d[0] any \n",  networkBuf, masklen,Inf_pointer->serverIPAddr, 32);
					fprintf(fp, "{\n");
					if(strcmp(pfs, "off") != 0)
						fprintf(fp, "	pfs_group %s;\n", pfs);
					
					fprintf(fp, "	lifetime time 800 sec;\n");
					fprintf(fp, "	encryption_algorithm %s;\n", enc);
					fprintf(fp, "	authentication_algorithm %s;\n", hash);
					fprintf(fp, "	compression_algorithm deflate;\n");
					fprintf(fp, "}\n");*/
/*					xmlFree(networkBuf);
					xmlFree(maskBuf);
				}
			}
		}*/
		//Print the anonymous node also.. for rekey issue with NSM
		/*
					fprintf(fp, "sainfo anonymous");
					fprintf(fp, "{\n");
					if(strcmp(pfs, "off") != 0)
						fprintf(fp, "	pfs_group %s;\n", pfs);
					fprintf(fp, "	lifetime time 300 sec;\n");
					fprintf(fp, "	encryption_algorithm %s;\n", enc);
					fprintf(fp, "	authentication_algorithm %s;\n", hash);
					fprintf(fp, "	compression_algorithm deflate;\n");
					fprintf(fp, "}\n");
					*/
/*	}
	else
	{
               fprintf(fp, "sainfo anonymous\n");
               fprintf(fp, "{\n");
               fprintf(fp, "\tpfs_group 1;\n");
               fprintf(fp, "\tencryption_algorithm 3des, des;\n");
               fprintf(fp, "\tauthentication_algorithm hmac_sha1, hmac_md5;\n");
               fprintf(fp, "\tcompression_algorithm deflate;\n");
               fprintf(fp, "}\n");
	}
	
	
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);
	
*/
}

int startEventPoll(Inf_t* Inf_pointer, int cli_or_gui)
{
	char labeltext[128];
	int ph2ctr = 0, ph1ctr = 0;
	int print_once = 0;
	Inf_pointer->startTime = time(NULL);
	Inf_pointer->connInProgress = TRUE;
	struct timeval tv;

	while(Inf_pointer->runEventPoll)
	{
		if(!Inf_pointer->connected && ((time(NULL) - Inf_pointer->startTime) > MAX_CONNECTION_TIMEOUT))
		{
			//show_dialog_message(errString(GATEWAY_CONNECTION_TIMEOUT, errStr));
			sprintf(Error_string, errString(GATEWAY_CONNECTION_TIMEOUT, errStr));
			(Inf_pointer->printing_function)(Error_string);
			Inf_pointer->runEventPoll = 0;
		}
		
		if((Inf_pointer->eventsockfd=initEventSockfd())<0)
		{
			Inf_pointer->runEventPoll = 0;
			plog(LLV_ERROR, NULL, NULL,"Could not connect to admin port ....... \n");
			sprintf(labeltext,"Exiting !!! Admin port error !\n"); 
			//gtk_label_set_text(GTK_LABEL(connStatusLabel), labeltext);
			if(Inf_pointer->conection_status_update)
				Inf_pointer->conection_status_update (labeltext);
			//refresh();
			//show_dialog_message(errString(RACOON_FAILED_TO_RESPOND, errStr));
			sprintf(Error_string, errString(RACOON_FAILED_TO_RESPOND, errStr));
			(Inf_pointer->printing_function)(Error_string);
			//on_vpnlogin_destroy((GtkObject *)mainWindow, NULL);
			if(Inf_pointer->on_vpnlogin_destroy_mainWindow)
				Inf_pointer->on_vpnlogin_destroy_mainWindow();
			exit(1);
		}	

		if(receiveEvents(Inf_pointer))
		{
			Inf_pointer->runEventPoll = 0;
			sprintf(Error_string,errString(IKE_DAEMON_FAILURE,errStr));
			(Inf_pointer->printing_function)(Error_string);
			plog(LLV_ERROR, NULL, NULL,"Could not receive Events from admin port .... exiting \n");
			continue;
		}

		if(cli_or_gui == 0)
		{
			if (Inf_pointer->lastEvtRecvd == EVTT_PHASE1_UP)
			{
				ph1ctr++;
				if (!Inf_pointer->plugin)  //Standard Gateway
				{
					Inf_pointer->connected = 1;
					/* 
					 * Changes for NM - Preggna
					 * 1. Commenting the line below to make vpnc run as daemon 
					 * 2. Printing the connected statement in this if block as vpnc waits as daemon
					 *    (So if we have a common print statement based on connected flag, everytime
					 *     the loop is executed the statement  gets printed )
					 */
					 
					/*		Inf_pointer->runEventPoll = 0; */
					if(print_once == 0)
					{
						sprintf(Error_string,_("VPN client has successfully connected to the gateway %s\n"),
							Inf_pointer->serverIPAddr);
						print_once = 1;
						(Inf_pointer->printing_function)(Error_string);
						if(!Inf_pointer->withProfileFile)
						{
							int ret = 0;

							setenv("VPNGATEWAY",Inf_pointer->serverIPAddr,1);
							setenv("INTERNAL_IP4_ADDRESS",Inf_pointer->sourceIPAddr,1);
							setenv("reason","connect",1);
							{
								char network_mask[MAX_STRING_LEN] = {'\0'};
								char dns_entries[MAX_STRING_LEN] = {'\0'};
								int i = 0;

								fill_the_network_mask(Inf_pointer->sourceIPAddr,network_mask);
								setenv("route_netmask_1",network_mask, 1);
	
								strcpy(dns_entries,"dhcp-option ");
						                strcat(dns_entries, "DNS ");
								res_init();

								for(; i < _res.nscount; i++)
								{
									if(i > 1)
										strcat(dns_entries, " ");
					                		strcat(dns_entries, (char*)inet_ntoa((_res.nsaddr_list[i]).sin_addr));
								}
								
								setenv("foreign_option_1",dns_entries,1);
							}
							ret = system(Inf_pointer->upscript);	
							if (ret != 0)
								plog(LLV_ERROR, NULL, NULL,"system(%s) failed.\n",
										Inf_pointer->upscript);
						}
					}
				}
			}
			if ((ph1ctr) &&(Inf_pointer->lastEvtRecvd == EVTT_PHASE2_UP) ) //Non Std Gateway
			{
				ph2ctr++;
				if (ph2ctr == 2)
				{
					Inf_pointer->connected = 1;
					/* 
					 * Changes for NM - Preggna
					 * 1. Commenting the line below to make vpnc run as daemon 
					 * 2. Printing the connected statement in this if block as vpnc waits as daemon
					 *    (So if we have a common print statement based on connected flag, everytime
					 *     the loop is executed the statement  gets printed )
					 */
				/*	Inf_pointer->runEventPoll = 0; */
				if(Inf_pointer->withProfileFile)
					Inf_pointer->runEventPoll = 0;
				//else
				//	system(Inf_pointer->upscript);
				sprintf(Error_string,_("VPN client has successfully connected to the gateway %s\n"),Inf_pointer->serverIPAddr);
				(Inf_pointer->printing_function)(Error_string);
				}
			}
			/*
			if (Inf_pointer->connected)
			{
				sprintf(Error_string,_("VPN client has successfully connected to the gateway %s\n"),Inf_pointer->serverIPAddr);
				printing_function(Error_string);
			}
			*/
			if ((ph1ctr) &&(Inf_pointer->lastEvtRecvd == EVTT_PEERPH1_NOPROP ))
			{
				int ret = 0;

				Inf_pointer->runEventPoll = 0;
				sprintf(Error_string, "%s\n", errString(PEER_DISCONNECTED, errStr));

				// FIXME: should be done by some API rather than this.
				ret = system ("/usr/sbin/setkey -FP");
				if (ret != 0)
					plog(LLV_ERROR, NULL, NULL,"system(/usr/sbin/setkey -FP) failed.\n");

				ret = system ("/usr/sbin/setkey -F");
				if (ret != 0)
					plog(LLV_ERROR, NULL, NULL,"system(/usr/sbin/setkey -F) failed.\n");

				//sendMessage(Inf_pointer,(unsigned short)ADMIN_DISCONNECT_DST, cli_or_gui);
				fprintf (stderr, "%s\n", Error_string);
                                
				if(Inf_pointer->on_vpnlogin_destroy_mainWindow)
					Inf_pointer->on_vpnlogin_destroy_mainWindow();

				exit(1);
			}	
		}
		closeEventSockfd();
		if (cli_or_gui)
			Inf_pointer->refresh();
		tv.tv_sec = 0;
		tv.tv_usec = 100000;
		select(0, NULL, NULL, NULL, &tv);
	}
	Inf_pointer->connInProgress = FALSE;
	if(!(Inf_pointer->keepMainWindow))
	{
		if(Inf_pointer->on_vpnlogin_destroy_mainWindow)
			Inf_pointer->on_vpnlogin_destroy_mainWindow();
	}

	return 0;
}


int receiveEvents(Inf_t* Inf_pointer)
{
	int 	sendLen;
	size_t 	bufLen = 0;
	char 	sendBuf[1024];
	comHeader_t *comHeader;
	char *currptr;
	
	//extern int server_addr;
	//extern int source_addr;
	bzero(&sendBuf, sizeof(sendBuf));
	comHeader = (comHeader_t *)&sendBuf;
	comHeader->ac_cmd = ADMIN_SHOW_EVT;
	comHeader->ac_proto = 0;
	comHeader->ac_errno = 0;
	
	bufLen += sizeof(comHeader_t);
	currptr = &sendBuf[bufLen];
	
	comHeader->ac_len = bufLen;
	sendLen = send(Inf_pointer->eventsockfd, sendBuf,bufLen,0);
	
	if(!sendLen)
		plog(LLV_ERROR, NULL, NULL,"Failed to send the SHOW_EVT message to adminport\n");

	recvEventReply(Inf_pointer);
	
	return 0;
}

int recvEventReply(Inf_t* Inf_pointer)
{
	char *area=NULL;	
	int ret;
	int evtLen;
	comHeader_t peekStruct;
	int recv_len, peek_len;
	fd_set rset;
	int maxfd;
	struct timeval tv;
	char *evtBuf = NULL, progressString[128];
	time_t t = time(NULL);
	time_t t1 = time(NULL) - Inf_pointer->startTime;
	struct evtdump *evtdump = NULL;
	FD_ZERO(&rset);
	area=malloc(MAX_BUFFER_SIZE+sizeof(int));


	if(!Inf_pointer->connected)
	{
        	sprintf(progressString, _("Connection in progress ... %d seconds"),(int) t1);	
		if(Inf_pointer->connecting_time_update)
			Inf_pointer->connecting_time_update(progressString);
		//gtk_label_set_text(GTK_LABEL(connLabel), progressString);
	}
	else
	{
		if(Inf_pointer->updateUptime)
			Inf_pointer->updateUptime();
	}


	while(t+TIMEOUTINSECONDS > time(NULL))
	{

		FD_SET(Inf_pointer->eventsockfd,&rset);
		maxfd=Inf_pointer->eventsockfd+1;
		tv.tv_sec=0;
		tv.tv_usec=100; 
		if((ret=select(maxfd,&rset,NULL,NULL,&tv))<0){
			if((errno == EINTR))
			continue;

			if(ret==-1){
				plog(LLV_ERROR, NULL, NULL,"error in selecting with tv= %d.. \n",(int)tv.tv_sec);
				if(area)
					free(area);
				return -1;
			}
		}

		if(FD_ISSET(Inf_pointer->eventsockfd,&rset)){

			peek_len = recv(Inf_pointer->eventsockfd, &peekStruct, sizeof(comHeader_t), MSG_PEEK);
			if(!peek_len){
				cleanup_socket(Inf_pointer->eventsockfd);
				plog(LLV_WARNING, NULL, NULL,"Connection closed. May be server closed this connection! \n");
				if(area)
					free(area);
				return -1;
			}
			if(peekStruct.ac_errno)
			{
				plog(LLV_ERROR, NULL, NULL,"Admin port has returned error...\n");
				if(area)
					free(area);
				return -1;
			}
			if(peekStruct.ac_cmd != ADMIN_SHOW_EVT)
			{
				plog(LLV_WARNING, NULL, NULL,"Event reply unknown command ...\n");
				if(area)
					free(area);
				return -1;
			}
			if(peek_len < MAX_BUFFER_SIZE){
				recv_len = recv(Inf_pointer->eventsockfd, area, peekStruct.ac_len, MSG_WAITALL); //TODO:Error Check.
				//parse the buffer here
				evtLen = recv_len - sizeof(comHeader_t);
				if(evtLen == 0)
				{
					free(area);
					return 0;
				}
				evtBuf = area+sizeof(comHeader_t);
				//print_evt(evtBuf, evtLen);
				evtdump = (struct evtdump *)evtBuf;
				Inf_pointer->lastEvtRecvd = evtdump->type;
				Inf_pointer->print_event(evtBuf, evtLen);
				if(area)
					free(area);
				return 0;

			}
		}
	}
	//Timed out disconnect the server	
	if(area)
		free(area);
	return -2;

}


int disconnectServer(Inf_t* Inf_pointer, int cli_or_gui)
{
	//extern int cpid;
	char *outbuf=NULL;
	int outbuflen=0;
	int ret;
	
		
	if((Inf_pointer->sockfd=initSocket())<0){
	
		goto Done;
	}
	
	if(sendMessage(Inf_pointer,(unsigned short)ADMIN_DISCONNECT_DST, cli_or_gui)<0)
		goto Done;
			
	time_t t=time(NULL);
	if((ret=receiveMessage(Inf_pointer,&outbuf,&outbuflen,t))<0)
	{
		//show_dialog_message(errString(FAILED_TO_RECEIVE_FROM_GATEWAY, errStr));
		sprintf(Error_string, errString(FAILED_TO_RECEIVE_FROM_GATEWAY, errStr));
		(Inf_pointer->printing_function)(Error_string);
	}
	if(outbuf)
		free(outbuf);

	cleanup_socket(Inf_pointer->sockfd);
Done:
	if(!Inf_pointer->keepMainWindow)
	{
		if(Inf_pointer->on_vpnlogin_destroy_mainWindow)
			Inf_pointer->on_vpnlogin_destroy_mainWindow(NULL, NULL);
	}
	return 0;
}



void copyProfiles(Inf_t* Inf_pointer)
{
	DIR  *dd; 
	struct dirent *dirp; 
	char cmd[256];
	int ret = 0;

	if(dir_check(SYSTEM_PROFILE_PATH) == FILE_EXIST)
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
				strcat(cmd, Inf_pointer->profile_path);
				ret = system(cmd);
				if (ret != 0)
					plog(LLV_ERROR, NULL, NULL,"system(%s) failed.\n", cmd);
			}
		}

	}
	
	if(dir_check(SYSTEM_VENDOR_PROFILE_PATH) == FILE_EXIST)
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
				strcat(cmd, Inf_pointer->vendor_profile_path);
				ret = system(cmd);
				if (ret != 0)
					plog(LLV_ERROR, NULL, NULL,"system(%s) failed.\n", cmd);

			}
		}
	}
	
	return;
}


int connectToServer(Inf_t* Inf_pointer, int cli_or_gui)
{
	char *outbuf=NULL;
	int outbuflen=0;
	int ret = 0;

	Inf_pointer->keepMainWindow = 0;
	Inf_pointer->runEventPoll = 1;
	if( cli_or_gui == 1)
	{
		if( (writeGenericRacoonConfFile(Inf_pointer))< 0)
			return -1;
	}

	if(Inf_pointer->plugin)
	{
		/* send the message ADMIN_SET_VENDOR_CONFIG_DATA */
		if((Inf_pointer->sockfd=initSocket())<0){
			//show_dialog_message(errString(RACOON_CONNECT_FAILURE, errStr));
			sprintf(Error_string, errString(RACOON_CONNECT_FAILURE, errStr));
			(Inf_pointer->printing_function)(Error_string);
			return -1;
		}
		if(sendMessage(Inf_pointer, (unsigned short)ADMIN_SET_VENDOR_CONFIG_DATA, cli_or_gui) < 0)
		{
			//show_dialog_message(errString(COULD_NOT_SEND_TO_RACOON, errStr));
			sprintf(Error_string, errString(COULD_NOT_SEND_TO_RACOON, errStr));
			(Inf_pointer->printing_function)(Error_string);
			return -2;
		}
		time_t t=time(NULL);
		if((ret=receiveMessage(Inf_pointer,&outbuf,&outbuflen,t))<0)
		{
			if(outbuf)
				free(outbuf);
			//show_dialog_message(errString(FAILED_TO_RECEIVE_FROM_GATEWAY, errStr));
			sprintf(Error_string, errString(FAILED_TO_RECEIVE_FROM_GATEWAY, errStr));
			(Inf_pointer->printing_function)(Error_string);
			return -1;
		}
		else
			free(outbuf);
	}

	/* send message ADMIN_REPARSE_RACOON_CONF */
	if((Inf_pointer->sockfd=initSocket())<0)
	{
		sprintf(Error_string, errString(RACOON_CONNECT_FAILURE, errStr));
		(Inf_pointer->printing_function)(Error_string);
		return -1;
	}
	if(sendMessage(Inf_pointer, (unsigned short)ADMIN_REPARSE_RACOON_CONF, cli_or_gui) < 0)
	{
		sprintf(Error_string, errString(COULD_NOT_SEND_TO_GATEWAY, errStr));
		(Inf_pointer->printing_function)(Error_string);
		return -2;
	}
	time_t  t=time(NULL);
	if((ret=receiveMessage(Inf_pointer,&outbuf,&outbuflen,t))<0)
	{
		if(outbuf)
			free(outbuf);
		sprintf(Error_string, errString(FAILED_TO_RECEIVE_FROM_GATEWAY, errStr));
		(Inf_pointer->printing_function)(Error_string);
		return -1;
	}
	else
		free(outbuf);

	/* 
	 * send message ADMIN_PUSH_PHASE2CONFIG
	 * FIX ME: Change the verb to ADMIN_PUSH_POLICIES
	 */	
	if(!Inf_pointer->plugin)
	{
		if((Inf_pointer->sockfd=initSocket())<0)
		{
			sprintf(Error_string, errString(RACOON_CONNECT_FAILURE, errStr));
			(Inf_pointer->printing_function)(Error_string);
			return -1;
		}
		if(sendMessage(Inf_pointer, (unsigned short)ADMIN_PUSH_PHASE2CONFIG, cli_or_gui) < 0)
		{
			sprintf(Error_string, errString(COULD_NOT_SEND_TO_GATEWAY, errStr));
			(Inf_pointer->printing_function)(Error_string);
			return -2;
		}
		t=time(NULL);
		if((ret=receiveMessage(Inf_pointer,&outbuf,&outbuflen,t))<0)
		{
			if(outbuf)
				free(outbuf);
			sprintf(Error_string, errString(FAILED_TO_RECEIVE_FROM_GATEWAY, errStr));
			(Inf_pointer->printing_function)(Error_string);
			return -1;
		}
		else
			free(outbuf);
	}

	/* send message ADMIN_ESTABLISH_SA */
	if((Inf_pointer->sockfd=initSocket())<0)
	{
		sprintf(Error_string, errString(RACOON_CONNECT_FAILURE, errStr));
		(Inf_pointer->printing_function)(Error_string);
		return -1;
	}

	if(sendMessage(Inf_pointer,(unsigned short)ADMIN_ESTABLISH_SA, cli_or_gui)<0)
	{
		sprintf(Error_string, errString(COULD_NOT_SEND_TO_GATEWAY, errStr));
		(Inf_pointer->printing_function)(Error_string);
		return -2;
	}
	t=time(NULL);

	while(t+TIMEOUTINSECONDS > time(NULL))
	{
		if((ret=receiveMessage(Inf_pointer,&outbuf,&outbuflen,t))<0)
		{
			//To free outbuf.
			if(outbuf)
				free(outbuf);
			if(ret==-1)
			{
				sprintf(Error_string, errString(FAILED_TO_RECEIVE_FROM_GATEWAY, errStr));
				(Inf_pointer->printing_function)(Error_string);
			}
			if(ret==-2)
			{
				sprintf(Error_string, errString(FAILED_TO_RECEIVE_FROM_GATEWAY, errStr));
				(Inf_pointer->printing_function)(Error_string);
				return ret ;
			}
			return -1;
		}
		else
		{ 
			if (Inf_pointer->isVerbose)
			{
				printf(_("Received response from admin port\n"));
			}
			plog(LLV_INFO, NULL, NULL,"Received response from admin port\n");
			free(outbuf);
			return 0;
		}

	}
	return 0;
}

static char *getMsgStr(unsigned short msgType)
{

    switch(msgType){
        case ADMIN_ESTABLISH_SA             : return("ADMIN_ESTABLISH_SA");
        case ADMIN_DELETE_ALL_SA_DST        : return("ADMIN_DELETE_ALL_SA_DST");
        case ADMIN_DISCONNECT_DST           : return("ADMIN_DISCONNECT_DST");
        case ADMIN_PUSH_PHASE2CONFIG        : return("ADMIN_PUSH_PHASE2CONFIG");
        case ADMIN_SET_VENDOR_CONFIG_DATA   : return("ADMIN_SET_VENDOR_CONFIG_DATA");
    	case ADMIN_REPARSE_RACOON_CONF      : return("ADMIN_REPARSE_RACOON_CONF");
	default				    : return NULL;
        }
}

int sendMessage(Inf_t* Inf_pointer, unsigned short msgType, int cli_or_gui)
{
	int 	sendLen, numPh2Policies;
	int 	bufLen = 0;
	char 	sendBuf[1024] = { '\0' };
	comHeader_t *comHeader;
	comIndexes_t *comIndexes;
	char *currptr;
	int sock = Inf_pointer->sockfd;
	struct admin_com_ph2config *ph2 = NULL;
	int retval = 0;

	bzero(&sendBuf, sizeof(sendBuf));
	comHeader = (comHeader_t *)&sendBuf;
	comHeader->ac_cmd = msgType;
	comHeader->ac_proto = ADMIN_PROTO_ISAKMP;

	bufLen += sizeof(comHeader_t);

	currptr = &sendBuf[bufLen];


	switch(msgType){
		case ADMIN_ESTABLISH_SA:
			comIndexes = (comIndexes_t *)currptr;
			//copy source address
			
			//((struct sockaddr_in *)&(comIndexes->src))->sin_addr.s_addr = Inf_pointer->source_addr;
			((struct sockaddr_in *)&(comIndexes->src))->sin_addr.s_addr = source_addr;
			//((struct sockaddr_in *)&(comIndexes->src))->sin_addr.s_addr = 0x00000000;
			((struct sockaddr_in *)&(comIndexes->src))->sin_family = AF_INET;
			
			//copy dest address
			//((struct sockaddr_in *)&(comIndexes->dst))->sin_addr.s_addr =Inf_pointer->server_addr;
			((struct sockaddr_in *)&(comIndexes->dst))->sin_addr.s_addr = server_addr;
			((struct sockaddr_in *)&(comIndexes->dst))->sin_family = AF_INET;
			
			bufLen+=sizeof(comIndexes_t);
			currptr += sizeof(comIndexes_t);

		break;
		
		case ADMIN_DELETE_ALL_SA_DST:
		case ADMIN_DISCONNECT_DST:
			comIndexes = (comIndexes_t *)currptr;
			//copy source address
			
			//((struct sockaddr_in *)&(comIndexes->src))->sin_addr.s_addr = Inf_pointer->source_addr;
			((struct sockaddr_in *)&(comIndexes->src))->sin_addr.s_addr = source_addr;
			((struct sockaddr_in *)&(comIndexes->src))->sin_family = AF_INET;
			
			//copy dest address
			//((struct sockaddr_in *)&(comIndexes->dst))->sin_addr.s_addr = Inf_pointer->server_addr;
			((struct sockaddr_in *)&(comIndexes->dst))->sin_addr.s_addr = server_addr;
			((struct sockaddr_in *)&(comIndexes->dst))->sin_family = AF_INET;
			
			bufLen+=sizeof(comIndexes_t);
			currptr += sizeof(comIndexes_t);
			break;

/*#if NOT_USED		
		case ADMIN_PUSH_PHASE1CONFIG:
			{
				printf("ADMIN_PUSH_PHASE1CONFIG\n");
				if(guiplugin)
				{
					int ph1len;
					ph1len = plugin_ph1_config_callback(&ph1Config);
					memcpy(currptr, ph1Config, sizeof(struct admin_com_ph1config) -1 );
				}
				else
				{
				struct admin_com_ph1config *ph1 = (struct admin_com_ph1config *)currptr;
				
				((struct sockaddr_in *)&(ph1->dst))->sin_addr.s_addr =server_addr;
				((struct sockaddr_in *)&(ph1->dst))->sin_family = AF_INET;
				
				ph1->mode = 2; //MM //isakmp.h
				ph1->verify_cert = 0;
				ph1->certtype = 0;
				strcpy(ph1->mycertfile, userCert);
				strcpy(ph1->myprivfile, userPvtKey);
				strcpy(ph1->peerscertfile, "None for now");
				
				ph1->verify_identifier = 0;
				ph1->my_identifier_type = 5; //ASN1DN
				ph1->my_identifier_len = 0;
				ph1->num_peer_identifier = 0;
				}
				
			}
			currptr += sizeof(struct admin_com_ph1config) -1;
			bufLen += sizeof(struct admin_com_ph1config) -1;
			
			break;	
		

		
		case ADMIN_PUSH_PHASE1PROPOSAL:
			{

#if 0			
				if(guiplugin)
				{
					int ph1ProposalLen;
					ph1ProposalLen = plugin_ph1_proposal_callback(&ph1Proposal);
					memcpy(currptr, ph1Proposal, ph1ProposalLen);
				}
				else
				{
					struct admin_com_ph1proposal_list *ph1 = (struct admin_com_ph1proposal_list *)currptr;
					
					struct admin_com_ph1proposal *ph1p = currptr + sizeof(struct admin_com_ph1proposal_list) -1;
					
					((struct sockaddr_in *)&(ph1->dst))->sin_addr.s_addr =server_addr;
					((struct sockaddr_in *)&(ph1->dst))->sin_family = AF_INET;
					ph1p->encryption_algo = 3; //3DES
					ph1p->hash_algo = 	2; //SHA1
					ph1p->auth_method =1 	; //rsasig
					ph1p->dh_group = 	2; // dhgroup = 2
				}
				
			}
			currptr += sizeof(struct admin_com_ph1proposal_list) -1;
			bufLen += sizeof(struct admin_com_ph1proposal_list) -1;
			
			//TODO: do this in a better way
			currptr += sizeof(struct admin_com_ph1proposal); 
			bufLen += sizeof(struct admin_com_ph1proposal);
			break;	
		
#else
			int numPh1Proposals =  0;	
			struct admin_com_ph1proposal_list *ph1 = (struct admin_com_ph1proposal_list *)currptr;
			struct admin_com_ph1proposal *ph1p = currptr + sizeof
			(struct admin_com_ph1proposal_list) -1;
			((struct sockaddr_in *)&(ph1->dst))->sin_addr.s_addr
						=server_addr;
			((struct sockaddr_in *)&(ph1->dst))->sin_family = AF_INET;

			numPh1Proposals = copyph1ProposalsIntobuffer(selectedProfile, currptr);
			//Currently one proposal from profile gets copied
			currptr += sizeof(struct admin_com_ph1proposal); 
			bufLen += sizeof(struct admin_com_ph1proposal);
			break;	
			}
#endif
#endif
*/		
		case ADMIN_PUSH_PHASE2CONFIG:
			{
			char ProfileName[MAX_STRING_LEN] = { '\0' };
			ph2 = (struct admin_com_ph2config *)currptr;
				
			//((struct sockaddr_in *)&(ph2->src_end_point))->sin_addr.s_addr = Inf_pointer->source_addr;
			((struct sockaddr_in *)&(ph2->src_end_point))->sin_addr.s_addr = source_addr;
			((struct sockaddr_in *)&(ph2->src_end_point))->sin_family = AF_INET;
			
			//copy dest address
			//((struct sockaddr_in *)&(ph2->dst_end_point))->sin_addr.s_addr =Inf_pointer->server_addr;
			((struct sockaddr_in *)&(ph2->dst_end_point))->sin_addr.s_addr =server_addr;
			((struct sockaddr_in *)&(ph2->dst_end_point))->sin_family = AF_INET;
				
			currptr += sizeof(struct admin_com_ph2config) -1;
			bufLen += sizeof(struct admin_com_ph2config) -1;
			if(cli_or_gui == 0)
			{
				strcpy(ProfileName, Inf_pointer->profile_path);
				strcat(ProfileName, Inf_pointer->profileName);
			}
			else if(cli_or_gui == 1)
			{
				strcpy(ProfileName, Inf_pointer->selectedProfile);
			}
			if(Inf_pointer->withProfileFile)
				numPh2Policies = copyph2PoliciesIntobuffer_with_profile(Inf_pointer,ProfileName, currptr);
			else
				numPh2Policies = copyph2PoliciesIntobuffer_no_profile(Inf_pointer, currptr);

			currptr += (numPh2Policies * sizeof(struct admin_com_ph2policy));
			bufLen += (numPh2Policies * sizeof(struct admin_com_ph2policy));
			
			ph2->num_ph2_policies = numPh2Policies;
			break;
			}

		case ADMIN_SET_VENDOR_CONFIG_DATA:
			/*
			 * Message format = admin_com_header + version +
			 * gwType(string value) + plugin name( string value) +
			 * vendor specific data
			 */
			{
				char Plugin[MAX_STRING_LEN] = { '\0' };
				sprintf(Plugin, LIB_LOAD_PATH"/lib%s.so",Inf_pointer->gatewayType);

				comHeader->ac_proto = ADMIN_PROTO_ISAKMP;

				*(short *)currptr = TURNPIKE_INTERFACE_VERSION;
				currptr += sizeof(short);
				bufLen += sizeof(short);

				*(size_t *)currptr = strlen(Inf_pointer->gatewayType);
				currptr += sizeof(size_t);
				bufLen += sizeof(size_t);

				strcpy(currptr, Inf_pointer->gatewayType);
				currptr += strlen(Inf_pointer->gatewayType);
				bufLen += strlen(Inf_pointer->gatewayType);

				*(size_t *)currptr = strlen(Plugin);
				currptr += sizeof(size_t);
				bufLen += sizeof(size_t);

				strcpy(currptr, Plugin);
				currptr +=strlen(Plugin);
				bufLen +=strlen(Plugin);

				if (cli_or_gui == 0) {
					Inf_pointer->pluginBufLen = Inf_pointer->plugin_get_privdata(
							Inf_pointer->pluginBuf,
							Inf_pointer->pluginInfo);
				}

				memcpy(currptr, Inf_pointer->pluginBuf, Inf_pointer->pluginBufLen);
				currptr += Inf_pointer->pluginBufLen;
				bufLen += Inf_pointer->pluginBufLen;

				if (Inf_pointer->no_split_tunnel) {
					memcpy(currptr, "nosplittunnel", strlen("nosplittunnel"));
					currptr += strlen("nosplittunnel");
					bufLen += strlen("nosplittunnel");
				}

				break;
			}
		
		case ADMIN_REPARSE_RACOON_CONF:
			*(int *)currptr = strlen(Inf_pointer->racoon_conf_file);
			currptr +=  sizeof(int);
			bufLen += sizeof(int);
			
			strcpy(currptr, Inf_pointer->racoon_conf_file);
			currptr += strlen(Inf_pointer->racoon_conf_file);
			bufLen += strlen(Inf_pointer->racoon_conf_file);
		break;
		
		default:
			if (Inf_pointer->isVerbose)
			{
				printf(_("Unknown message type passed to sendMessage function: %x\n"),msgType);
			}
			plog(LLV_WARNING, NULL, NULL,"Unknown message type in sendMessage \n");
			break;
	}
	
	comHeader->ac_len = bufLen;
	sendLen = send(sock, sendBuf,bufLen,0);

    if(sendLen)
	{
		plog(LLV_INFO, NULL, NULL,"Successfully sent message type   %x to admin port\n", msgType);
		if (Inf_pointer->isVerbose)
		{
        		printf(_("Successfully sent the  message  %s to IKE Daemon\n"),getMsgStr(msgType));
		}
	}
    else
	{
                fprintf (stderr, errString (IKE_DAEMON_FAILURE, errStr));
                retval = IKE_DAEMON_FAILURE;
		plog(LLV_ERROR, NULL, NULL,"Failed to send socks response %x to admin port", msgType);
	}
	return retval;
}

int writeGenericRacoonConfFile(Inf_t* Inf_pointer)
{
	if(Inf_pointer->plugin)
	{
		parse_profile_to_racoon_conf_buf(Inf_pointer);
		if(Inf_pointer->plugin_racoon_conf_write)
		{
			Inf_pointer->plugin_racoon_conf_write((char *)&rbuf);
		}
	}
	else
	{	
		if( (writeRacoonConfFile(Inf_pointer)) < 0)
			return -1;
	}
	return 0;
}

int writeRacoonConfFile(Inf_t* Inf_pointer)
{
	FILE *fp = NULL;
	umask(006);
	fp = fopen(Inf_pointer->racoon_conf_file, "w+");
	//fp = fopen("/tmp/racoon.conf", "w+");
	if(fp == NULL)
	{
		plog(LLV_ERROR, NULL, NULL,"Could not open file\n");
		return -1;
	}
	fprintf(fp, "# racoon.conf generated by Turnpike\n");
	fprintf(fp, "path include \"/etc/racoon\";  \n");
	//fprintf(fp, "path pre_shared_key \"/etc/racoon/psk.txt\"; \n");
	fprintf(fp, "include \"racoon.conf\";\n"  );
	fprintf(fp, "path certificate \"%s\";\n", Inf_pointer->racoon_cert_path);

	if( (printf_ph1Config_to_racoon_conf(fp, Inf_pointer)) < 0)
		return -1;
	
	if( (printf_ph2Config_to_racoon_conf(fp, Inf_pointer)) < 0)
		return -1;
	
	fprintf(fp, " \n");
	fprintf(fp, " \n");
	fprintf(fp, " \n");
	fprintf(fp, " \n");
	fprintf(fp, " \n");
	
	
	fclose(fp);
	return 0;
}

int ph1ModeValue(char *buffer)
{
	int i;
	for (i = 0; i < MAX_MODE_TYPES; i++)
	{
		if(strcmp(Ph1modearray[i].string, buffer) == 0)
			return Ph1modearray[i].value;
	}
	return Ph1modearray[i].value;
}

int ph1EncValue(char *buffer)
{
	int i;
	for (i = 0; i < MAX_ENC_TYPES; i++)
	{
		if(strcmp(Ph1encarray[i].string, buffer) == 0)
			return Ph1encarray[i].value;
	}
	return Ph1encarray[i].value;
}

int ph1DhValue(char *buffer)
{
	int i;
	for (i = 0; i < MAX_DH_TYPES; i++)
	{
		if(strcmp(Ph1dharray[i].string, buffer) == 0)
			return Ph1dharray[i].value;
	}
	return Ph1dharray[i].value;
}

int ph1AuthValue(char *buffer)
{
	int i;
	for (i = 0; i < MAX_AUTH_TYPES; i++)
	{
		if(strcmp(Ph1autharray[i].string, buffer) == 0)
			return Ph1autharray[i].value;
	}
	return Ph1autharray[i].value;
}

int ph1HashValue(char *buffer)
{
	int i;
	for (i = 0; i < MAX_HASH_TYPES; i++)
	{
		if(strcmp(Ph1hasharray[i].string, buffer) == 0)
			return Ph1hasharray[i].value;
	}
	return Ph1hasharray[i].value;
}

int ph2EncValue(char *buffer)
{
	int i;
	for (i = 0; i < MAX_ENC_TYPES; i++)
	{
		if(strcmp(Ph2encarray[i].string, buffer) == 0)
			return Ph2encarray[i].value;
	}
	return Ph2encarray[i].value;
}

int ph2DhValue(char *buffer)
{
	int i;
	for (i = 0; i < MAX_PFS_TYPES; i++)
	{
		if(strcmp(Ph2dharray[i].string, buffer) == 0)
			return Ph2dharray[i].value;
	}
	return Ph2dharray[i].value;
}

int ph2HashValue(char *buffer)
{
	int i;
	for (i = 0; i < MAX_HASH_TYPES; i++)
	{
		if(strcmp(Ph2hasharray[i].string, buffer) == 0)
			return Ph2hasharray[i].value;
	}
	return Ph2hasharray[i].value;
}

int writeSuccessfulProfile(Inf_t* Inf_pointer, int cli_or_gui)
{
	char fileName[256] = {'\0'};
	
	xmlNodePtr root_node = NULL;
	xmlDocPtr doc;

	strcpy(fileName, Inf_pointer->userHome);
	strcat(fileName, LASTPROFILE_FILE);
	

	
	if(!isFileExist(fileName)) //Remove and rewrite it 
	{
		remove(fileName);
	}
	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "last_profile");
	xmlDocSetRootElement(doc, root_node);
	
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);
	
	if(cli_or_gui == 0)
	{
		int i = 0, j = 0;
		char LastProfile[MAX_STRING_LEN];
		while(Inf_pointer->profileName[i] != '_')
		{
			i++;
		}
		i++;
		while(Inf_pointer->profileName[i] != '.')
		{
			LastProfile[j] = Inf_pointer->profileName[i];
			i++;
			j++;
		}
		LastProfile[j] = '\0';
		xmlNewProp(root,(const xmlChar*)"name",(const xmlChar*) LastProfile);
	}
	else if(cli_or_gui == 1)
	{
		xmlNewProp(root,(const xmlChar*)"name", (const xmlChar*)Inf_pointer->selectedProfileFile);
	}
	
	xmlKeepBlanksDefault(0);
	xmlSaveFormatFile(fileName,doc,1);
	xmlFreeDoc(doc);
	
	//update any plugin profile data
	if(Inf_pointer->authentication_type != CERTIFICATE)
	{
		if(Inf_pointer->plugin)
			Inf_pointer->plugin_update_profile(Inf_pointer->vendorfile);
	}

	return 0;

}

int receiveMessage(Inf_t* Inf_pointer, char **outbuf, int *outbuflen,time_t starttime )
{

	char *area=NULL;	
	int ret;
	int sock = Inf_pointer->sockfd;
	comHeader_t peekStruct;
	int recv_len, peek_len;
	fd_set rset;
	int maxfd;
	struct timeval tv;

	FD_ZERO(&rset);
	area=malloc(MAX_BUFFER_SIZE+sizeof(int));
	*outbuf=area;

	while(starttime+TIMEOUTINSECONDS > time(NULL)){

		FD_SET(sock,&rset);
		maxfd=sock+1;
		tv.tv_sec=0;
		tv.tv_usec=0; 
		if((ret=select(maxfd,&rset,NULL,NULL,&tv))<0){
			if((errno == EINTR))
			continue;

			if(ret==-1){
				plog(LLV_ERROR, NULL, NULL,"error in selecting with tv= %d.. \n",(int)tv.tv_sec);
				return -1;
			}
		}

		if(FD_ISSET(sock,&rset)){

			peek_len = recv(sock, &peekStruct, sizeof(comHeader_t), MSG_PEEK);
			if(!peek_len){
				cleanup_socket(sock);
				plog(LLV_WARNING, NULL, NULL,"Connection closed. May be server closed this connection! \n");
				return -1;
			}
			plog(LLV_INFO, NULL, NULL,"peek length = %d, Peeked length = %d\n", peek_len, peekStruct.ac_len);
			if(peekStruct.ac_errno)
			{
				plog(LLV_ERROR, NULL, NULL,"Admin port has returned error...\n");
				return -1;
			}
			if(peek_len < MAX_BUFFER_SIZE){
				recv_len = recv(sock, area, peekStruct.ac_len, MSG_WAITALL); //TODO:Error Check.
				plog(LLV_INFO, NULL, NULL,"Received Length= %d  \n",recv_len);
				plog(LLV_INFO, NULL, NULL," The Received Buffer length is %d ...\n",recv_len);
				*outbuflen=recv_len;
				//*outbuf=area;
				#ifdef DEBUG
				plog(LLV_INFO, NULL, NULL,"Recevied Buffer \n");
				for(i=0;i<recv_len;i++)
					printf("%x(%c) ",(*outbuf)[i],(*outbuf)[i]);
				printf("\n");
				#endif
				//handleAdminPortResponse(button, sock, &outbuf, outbuflen );
				return 0;

			}
		}
		if(Inf_pointer->refresh)
			Inf_pointer->refresh();

	}
	//Timed out disconnect the server
	return -2;
}

int copyph2PoliciesIntobuffer_with_profile(Inf_t* Inf_pointer, char *selectedProfile, char *currptr)
{
	int numPolicies = 0, masklen = 0, network = 0;
	struct admin_com_ph2policy *ph2p = (struct admin_com_ph2policy *)currptr;

	
	xmlNode *cur_node, *policy_node = NULL, *ph2_node = NULL, *networks_node = NULL;
	xmlChar *networkBuf, *maskBuf;
	xmlDocPtr doc;
	struct sockaddr_in addr;

	doc = xmlParseFile(selectedProfile);
	if (doc == NULL) 
	{
		//show_dialog_message(errString(XML_PARSE_FAILED, errStr));
		sprintf(Error_string, errString(XML_PARSE_FAILED, errStr));
		(Inf_pointer->printing_function)(Error_string);
		return -1;
	}
	
	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar*)"profile")) { 
		plog(LLV_ERROR, NULL, NULL,"root element not found\n");
		//show_dialog_message(errString(INVALID_PROFILE, errStr));
		sprintf(Error_string, errString(INVALID_PROFILE, errStr));
		(Inf_pointer->printing_function)(Error_string);
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
		{	if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "phase2") == 0)
				{
					ph2_node = cur_node;
					break;
				}
			}
		}
		
	}
	
	if(ph2_node)
	{
		for(cur_node = ph2_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "networks") == 0)
				{
					networks_node = cur_node;
					break;
				}
			}
		}
		
	}
	
	if(networks_node)
	{
		for(cur_node = networks_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "entry") == 0)
				{
					networkBuf= xmlGetProp(cur_node,(const xmlChar*)"network");
					maskBuf= xmlGetProp(cur_node,(const xmlChar*)"mask");
					if(networkBuf)
						if ( inet_aton((const char*)networkBuf, &addr.sin_addr) != 0 )
						network = addr.sin_addr.s_addr;
					if(maskBuf)
					{
						if ( inet_aton((const char*)maskBuf, &addr.sin_addr) != 0 )
							masklen = convertMaskToLength(addr.sin_addr.s_addr);
					}
					
					//ph2p->dst_addr = network; // destination network
					((struct sockaddr_in *)&(ph2p->dst_addr))->sin_addr.s_addr =network;
					((struct sockaddr_in *)&(ph2p->dst_addr))->sin_family = AF_INET;
					((struct sockaddr_in *)&(ph2p->dst_addr))->sin_port = 0;
					//ph2p->dst_port = 0;
					ph2p->dst_prefixlen = masklen;
					ph2p-> upperspec = 0;
					ph2p->direction = 3; //BOTH
					ph2p->action = ACTION_ENCRYPT;
					ph2p->protocol = 0; //ESP
					ph2p->mode = 0; //TUNNEL MODE
					if(networkBuf)
						xmlFree(networkBuf);
					if(maskBuf)
						xmlFree(maskBuf);
					numPolicies++;
					//ph2p += sizeof(struct admin_com_ph2policy);
					ph2p += 1;
				}
			}
		}
	}
	
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);
	
	return	numPolicies;
	
}

int copyph2PoliciesIntobuffer_no_profile(Inf_t* Inf_pointer, char *currptr)
{
	int numPolicies = 0, masklen = 0, network = 0;
	struct admin_com_ph2policy *ph2p = (struct admin_com_ph2policy *)currptr;
	struct sockaddr_in addr;

	struct Routes* trav = Inf_pointer->network_mask_list;
	for(; trav != NULL; trav = trav->next)
	{
		if ( inet_aton(trav->network, &addr.sin_addr) != 0 )
			network = addr.sin_addr.s_addr;
		if ( inet_aton(trav->mask, &addr.sin_addr) != 0 )
			masklen = convertMaskToLength(addr.sin_addr.s_addr);
				
		((struct sockaddr_in *)&(ph2p->dst_addr))->sin_addr.s_addr = network;
		((struct sockaddr_in *)&(ph2p->dst_addr))->sin_family = AF_INET;
		((struct sockaddr_in *)&(ph2p->dst_addr))->sin_port = 0;
		ph2p->dst_prefixlen = masklen;
		ph2p-> upperspec = 0;
		ph2p->direction = 3; //BOTH
		ph2p->action = ACTION_ENCRYPT;
		ph2p->protocol = 0; //ESP
		ph2p->mode = 0; //TUNNEL MODE
		numPolicies++;
		ph2p += 1;
	}
	return	numPolicies;
}

int parse_profile_to_racoon_conf_buf(Inf_t* Inf_pointer)
{
	xmlNode *cur_node, *policy_node = NULL, *ph1_node = NULL, *ph1p_node = NULL, *ph2_node = NULL, *ph2p_node = NULL;
	xmlChar *buffer;
	xmlDocPtr doc;
	char enc[20], hash[20], dh[20], auth[20];
	char ph2enc[20], ph2hash[20], ph2pfs[20]; 

	doc = xmlParseFile(Inf_pointer->selectedProfile);
	if (doc == NULL) 
	{
		//show_dialog_message(errString(XML_PARSE_FAILED, errStr));
		sprintf(Error_string, errString(XML_PARSE_FAILED, errStr));
		(Inf_pointer->printing_function)(Error_string);
		return -1;
	}
	
	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar*)"profile")) { 
		plog(LLV_ERROR, NULL, NULL,"root element not found\n");
		//show_dialog_message(errString(INVALID_PROFILE, errStr));
		sprintf(Error_string, errString(INVALID_PROFILE, errStr));
		(Inf_pointer->printing_function)(Error_string);
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
				int mode = -1, encalgo = -1, hashalgo = -1, dhgroup = -1, authmethod = -1;

				if(strcmp((const char*)cur_node->name, "entry") == 0)
				{

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"mode");
					if(buffer)
					{
						mode = ph1ModeValue((char*)buffer);
						xmlFree(buffer);
					}

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"encalgo");
					if(buffer)
					{
						encalgo = ph1EncValue((char*)buffer);
						strcpy(enc, (const char*)buffer);
						xmlFree(buffer);
					}

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"hashalgo");
					if(buffer)
					{
						hashalgo = ph1HashValue((char*)buffer);
						strcpy(hash, (const char*)buffer);
						xmlFree(buffer);
					}

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"dhgroup");
					if(buffer)
					{
						dhgroup = ph1DhValue((char*)buffer);
						if(strcmp((const char*)buffer, "dh1") == 0)
							strcpy(dh, "1");
						else
							strcpy(dh, "2");
						xmlFree(buffer);
					}

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"authmethod");
					if(buffer)
					{
						authmethod = ph1AuthValue((char*)buffer);
						if(strcmp((const char*)buffer, "X.509") == 0)
							strcpy(auth, "rsasig");
						else
							strcpy(auth, "pre_shared_key");
						xmlFree(buffer);
					}

				}
			}
		}
	}
	
	/*fprintf(fp, "	proposal {\n");
	fprintf(fp, "		encryption_algorithm %s;\n", enc);
	fprintf(fp, "		hash_algorithm %s;\n", hash);
	fprintf(fp, "		authentication_method %s;\n", auth);
	fprintf(fp, "		dh_group %s;\n", dh);
	fprintf(fp, "	}\n");
	*/

	strcpy(rbuf.filename, Inf_pointer->racoon_conf_file);
	strcpy(rbuf.serverIPAddr, Inf_pointer->serverIPAddr);
	strcpy(rbuf.sourceIPAddr, Inf_pointer->sourceIPAddr);
	strcpy(rbuf.racoon_cert_path, Inf_pointer->racoon_cert_path);
	rbuf.nat_traversal = 1;
	strcpy(rbuf.ph1_proposal.encalgo, enc);
	strcpy(rbuf.ph1_proposal.hashalgo, hash);
	strcpy(rbuf.ph1_proposal.authmethod, auth);
	strcpy(rbuf.ph1_proposal.dhgroup, dh);
	
	
	//Do the ph2 stuff now
	if(policy_node)
	{
		for(cur_node = policy_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "phase2") == 0)
				{
					ph2_node = cur_node;
					break;
				}
			}
		}
		
	}
	
	if(ph2_node)
	{
		for(cur_node = ph2_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "proposals") == 0)
				{
					ph2p_node = cur_node;
				}
			}
		}
	}
	
	if(ph2p_node)
	{
		for(cur_node = ph2p_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				int encalgo = -1, hashalgo = -1, dhgroup = -1;

				if(strcmp((const char*)cur_node->name, "entry") == 0)
				{

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"encalgo");
					if(buffer)
					{
						encalgo = ph2EncValue((char*)buffer);
						strcpy(ph2enc, (const char*)buffer);
						xmlFree(buffer);
					}

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"hashalgo");
					if(buffer)
					{
						hashalgo = ph2HashValue((char*)buffer);
						strcpy(ph2hash, (const char*)buffer);
						xmlFree(buffer);
					}

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"pfsgroup");
					if(buffer)
					{
						dhgroup = ph2DhValue((char*)buffer);
						strcpy(ph2pfs, (const char*)buffer);
						xmlFree(buffer);
					}

				}
			}
		}
	}
	
	strcpy(rbuf.ph2_proposal.encalgo, ph2enc);
	strcpy(rbuf.ph2_proposal.hashalgo, ph2hash);
	strcpy(rbuf.ph2_proposal.pfsgroup, ph2pfs);

	
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);
	
	return 0;
}


int createPh1Conf(Inf_t* Inf_pointer, struct ph1_config *ph1)
{
	xmlNode *cur_node, *policy_node = NULL, *ph1_node = NULL, *ph1p_node = NULL;
	xmlChar *buffer;
	xmlDocPtr doc;
   	char profilename[MAX_STRING_LEN] = {'\0'};
		
   	/* parse the xml file */
    	strcpy(profilename, Inf_pointer->profile_path);
    	strcat(profilename, Inf_pointer->profileName);
        
	doc = xmlParseFile(profilename);
	if (doc == NULL) 
	{
		sprintf(Error_string,errString(CAN_NOT_XML_PARSE_FILE,errStr), profilename);
		(Inf_pointer->printing_function)(Error_string);		
		return -1;
	}
	
	/* Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar*)"profile")) 
	{ 
                sprintf(Error_string,errString(BAD_PROFILE,errStr), profilename);
		(Inf_pointer->printing_function)(Error_string);
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
                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"mode");
					if(buffer)
					{
						ph1->entry_mode = ph1ModeValue(( char*)buffer);
						xmlFree(buffer);
					}
                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"encalgo");
					if(buffer)
					{
						ph1->encryption_algo = ph1EncValue(( char*)buffer);
						xmlFree(buffer);
					}

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"hashalgo");
					if(buffer)
					{
						ph1->hash_algo = ph1HashValue(( char*)buffer);
						xmlFree(buffer);
					}

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"dhgroup");
					if(buffer)
					{
						ph1->dh_group = ph1DhValue(( char*)buffer);
						xmlFree(buffer);
					}

                        		buffer= xmlGetProp(cur_node,(const xmlChar*)"authmethod");
					if(buffer)
					{
						ph1->auth_method = ph1AuthValue(( char*)buffer);
						xmlFree(buffer);
					}

				}
			}
		}
	}
	
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);
	return 0;
}

int createPh2Conf ( Inf_t* Inf_pointer, struct racoon_conf *rc)
{
	xmlNode *cur_node, 
	*ph2_node = NULL,
	*policy_node = NULL, 
	*ph2p_node = NULL, 
	*networks_node = NULL;
            
	xmlChar *buffer, *networkBuf, *maskBuf;
	xmlDocPtr doc;
	struct sockaddr_in addr;
	char profilename[MAX_STRING_LEN] = {'\0'};
	struct ph2_config  *ph2 = &(rc->ph2Config);

	//extern Inf_t Inf;
	
	/* parse the xml file */
	strcpy(profilename, Inf_pointer->profile_path);
	strcat(profilename, Inf_pointer->profileName);

	doc = xmlParseFile(profilename);
        
	
	if (doc == NULL) 
	{
        	sprintf(Error_string,errString(CAN_NOT_XML_PARSE_FILE,errStr), profilename);
		(Inf_pointer->printing_function)(Error_string);
		return -1;
	}
	
	/* Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar*)"profile")) 
	{ 
		sprintf(Error_string,errString(BAD_PROFILE,errStr), profilename);
		(Inf_pointer->printing_function)(Error_string);
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
				if(strcmp((const char*)cur_node->name, "phase2") == 0)
				{
					ph2_node = cur_node;
					break;
				}
			}
		}
		
	}
	if(ph2_node)
	{
		for(cur_node = ph2_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "proposals") == 0)
				{
					ph2p_node = cur_node;
				}
			}
		}
	}
	
	if(ph2p_node)
	{
		for(cur_node = ph2p_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "entry") == 0)
				{

               				buffer= xmlGetProp(cur_node,(const xmlChar*)"encalgo");
					if(buffer)
					{
						ph2->encryption_algorithm = ph2EncValue(( char*)buffer);
						xmlFree(buffer);
					}

               				buffer= xmlGetProp(cur_node,(const xmlChar*)"hashalgo");
					if(buffer)
					{
						ph2->authentication_algorithm = ph2HashValue(( char*)buffer);
						xmlFree(buffer);
					}

               				buffer= xmlGetProp(cur_node,(const xmlChar*)"pfsgroup");
					if(buffer)
					{
						ph2->pfs_group = ph2DhValue(( char*)buffer);
						xmlFree(buffer);
					}

				}
			}
		}
	}
	
	if(ph2_node)
	{
		for(cur_node = ph2_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "networks") == 0)
				{
					networks_node = cur_node;
					break;
				}
			}
		}
		
	}
	
		
	/* parse_Networks */
	
	rc->num_networks = 1;
	
	char *ptr = rc->networks;
	if(networks_node)
	{
		for(cur_node = networks_node->children; cur_node != NULL; cur_node = cur_node->next) 
		{
			if ( cur_node->type == XML_ELEMENT_NODE  ) 
			{  
				if(strcmp((const char*)cur_node->name, "entry") == 0)
				{
					networkBuf= xmlGetProp(cur_node,(const xmlChar*)"network");
					maskBuf= xmlGetProp(cur_node,(const xmlChar*)"mask");
					if(networkBuf)
					{
						if ( inet_aton((const char*)networkBuf, &addr.sin_addr) != 0 )
						{
							*ptr = addr.sin_addr.s_addr;
							ptr += sizeof(u_int32_t);
						}
					}
					if(maskBuf)
					{
						if ( inet_aton((const char*)maskBuf, &addr.sin_addr) != 0 )
						{
						//	masklen = convertMaskToLength(addr.sin_addr.s_addr);
							*ptr = addr.sin_addr.s_addr;
							ptr += sizeof(u_int32_t);
						}
					}
					/* write into conf file */
					xmlFree(networkBuf);
					xmlFree(maskBuf);
				}
			}
		}
	} 
	
	xmlCleanupGlobals();
	xmlCleanupParser();
	xmlFreeDoc(doc);

	return 0;
}

int create_rcbuf(Inf_t* Inf_pointer, struct racoon_conf **rcbuf)
{
	struct racoon_conf *rc;
	
	/*  TODO: For Multiple networks re-alloc. */
	
	*rcbuf = (struct racoon_conf *)malloc(sizeof(struct racoon_conf) - sizeof(char) + 2 *sizeof(u_int32_t));
	
	if(!*rcbuf)
		exit(1);
    
	rc = *rcbuf;
	createPh1Conf(Inf_pointer, &(rc->ph1Config));	
	createPh2Conf(Inf_pointer, rc);	
	return 0;
}

int fill_the_network_mask(char* source_addr, char* mask_for_the_source_addr)
{
	struct sockaddr_in *s_in;
	int sock, i, count;
	struct ifconf conf;

	res_init();
	printf("%s\n",inet_ntoa((_res.nsaddr_list[0]).sin_addr));

	// Open dummy socket
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("error opening socket");
		return -1;
	}

	memset(&conf, 0, sizeof(conf));
	conf.ifc_len = sizeof(struct ifreq) * 20;
	conf.ifc_buf = (char*) malloc(conf.ifc_len);

	if (ioctl(sock, SIOCGIFCONF, &conf) == -1)
	{
		perror("failed to get device list");
		return -1;
	}

	count = conf.ifc_len / sizeof(struct ifreq);

	for (i = 0; i < count; i++)
	{
		s_in = (struct sockaddr_in*) &conf.ifc_req[i].ifr_netmask;
		if(strcmp(inet_ntoa(s_in->sin_addr), source_addr)==0)
			get_network_mask(conf.ifc_req[i].ifr_ifrn.ifrn_name, mask_for_the_source_addr );
	}

	free(conf.ifc_buf);
	return 0;
}

	
int get_network_mask(const char *eth_name, char* mask_to_be_filled)
{
	struct ifreq for_mask;
	struct sockaddr_in *s_in;
	int sock;

	// Open dummy socket
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("error opening socket");
		return -1;
	}
	// Get list of devices (only gets first 10)
	memset(&for_mask, 0, sizeof(struct ifreq));

	strcpy(for_mask.ifr_ifrn.ifrn_name,eth_name );
	if (ioctl(sock, SIOCGIFNETMASK, &for_mask) == -1)
	{
		perror("failed to get device list");
		return -1;
	}

	s_in = (struct sockaddr_in*) &for_mask.ifr_ifru.ifru_netmask;
	strcpy(mask_to_be_filled, inet_ntoa(s_in->sin_addr));
	return 0;
}

