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
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/un.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include "phase1.h"
#include "racoon/admin.h"
#include "racoon/oakley.h"
#include "racoon/evt.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/ipsec_doi.h"
//#include "adminport.h"
extern int server_addr;

int nortel_fill_ph1_config_buffer(char *buf);
int nortel_fill_ph1_proposal_buffer(char *buf);

Phase1EncodeTypes ph1encarray[] = {
	{ OAKLEY_ATTR_ENC_ALG_DES, "des" }, 
	{ OAKLEY_ATTR_ENC_ALG_3DES, "3des" }, 
	{ OAKLEY_ATTR_ENC_ALG_AES, "aes" }, 
	{ -1, ""},
};


Phase1HashTypes ph1hasharray[] = {
	{ OAKLEY_ATTR_HASH_ALG_MD5, "md5" }, 
	{ OAKLEY_ATTR_HASH_ALG_SHA, "sha1" }, 
	{ -1, ""},
};

Phase1ModeTypes ph1modearray[] = {
	{ ISAKMP_ETYPE_IDENT, "main" }, 
	{ ISAKMP_ETYPE_AGG, "aggressive" }, 
	{ -1, ""},
};
	
Phase1DHTypes ph1dharray[] = {
	{ OAKLEY_ATTR_GRP_DESC_MODP768, "1" }, 
	{ OAKLEY_ATTR_GRP_DESC_MODP1024, "2" }, 
	{ -1, ""},
};

Phase1AuthTypes ph1autharray[] = {
	{ OAKLEY_ATTR_AUTH_METHOD_PSKEY , "pre_shared_key" }, 
	{ OAKLEY_ATTR_AUTH_METHOD_RSASIG, "rsasig" }, 
	{ -1, ""},
};

char *ph1get_encalgo(int enctype)
{
	int i=0;

	for(i=0; i < MAX_ENC_TYPES ; i++)
	{
		if (enctype == ph1encarray[i].value)
			return ph1encarray[i].string;
	}
	return NULL;
}
char *ph1get_hashalgo(int hashtype) 
{

	int i=0;

	for(i=0; i < MAX_HASH_TYPES ; i++)
	{
		if (hashtype == ph1hasharray[i].value)
			return ph1hasharray[i].string;
	}
	return NULL;
}
char *ph1get_authmethod(int authmethod) 
{

	int i=0;

	for(i=0; i < MAX_AUTH_TYPES ; i++)
	{
		if (authmethod == ph1autharray[i].value)
			return ph1autharray[i].string;
	}
	return NULL;
}
char *ph1get_dhtype(int dhtype)
{

	int i=0;

	for(i=0; i < MAX_DH_TYPES ; i++)
	{
		if (dhtype == ph1dharray[i].value)
			return ph1dharray[i].string;
	}
	return NULL;
}
char *ph1get_modestr(int mode)
{
	int i=0;

	for(i=0; i < MAX_MODE_TYPES ; i++)
	{
		if (mode == ph1modearray[i].value)
			return ph1modearray[i].string;
	}
	return NULL;
}


int write_PH1_proposal(FILE *fp, char* dh_group, char* auth_method)
{
	int  enc = 0, hash = 0;

	for(enc = 0; enc < MAX_ENC_TYPES; enc++)
	{
		for(hash = 0; hash < MAX_HASH_TYPES; hash++)
		{
//			for(auth = 0; auth < MAX_AUTH_TYPES; auth++)
			//for(auth = 0; auth < 1; auth++)
//			{
				fprintf(fp, "	proposal {\n");
				fprintf(fp, "		encryption_algorithm %s;\n",ph1encarray[enc].string);
				fprintf(fp, "		hash_algorithm %s;\n", ph1hasharray[hash].string);
				//fprintf(fp, "		authentication_method %s;\n", ph1autharray[auth].string);
				fprintf(fp, "		authentication_method %s;\n", auth_method);
				fprintf(fp, "		dh_group %s;\n",dh_group);
				fprintf(fp, "	}\n");
			
//			}
		}
	}
	return 0;
}

int
nortel_fill_ph1_config_buffer(char *buf)
{
 	int bufLen = 0;
	struct admin_com_ph1config *ph1 = (struct admin_com_ph1config *)buf;
	
	((struct sockaddr_in *)&(ph1->dst))->sin_addr.s_addr = server_addr;
	((struct sockaddr_in *)&(ph1->dst))->sin_family = AF_INET;
	
	ph1->mode = 4; //AM //isakmp.h
	ph1->verify_cert = 0;
	ph1->verify_identifier = 0;
	ph1->my_identifier_type = 3; //KEY-ID
	ph1->my_identifier_len = 0;
	ph1->num_peer_identifier = 0;
	
	
	bufLen = sizeof(struct admin_com_ph1config);
	return bufLen;
}

int
nortel_fill_ph1_proposal_buffer(char *buf)
{
	int bufLen = 0;
	struct admin_com_ph1proposal_list *ph1 = (struct admin_com_ph1proposal_list *)buf;
	struct admin_com_ph1proposal *ph1p = (struct admin_com_ph1proposal *) &ph1->ph1proposal;
	
	((struct sockaddr_in *)&(ph1->dst))->sin_addr.s_addr =server_addr;
	((struct sockaddr_in *)&(ph1->dst))->sin_family = AF_INET;
	ph1->num_proposal = 1;
	
	//bufLen = sizeof(struct admin_com_ph1proposal_list) -1;
	
	ph1p->encryption_algo = 5; //3DES
	ph1p->hash_algo = 	2; //SHA
	ph1p->auth_method =	1; //PSK
	ph1p->dh_group = 	1; // dhgroup = 1
	
	bufLen += sizeof(struct admin_com_ph1proposal_list);
	return bufLen;
}
