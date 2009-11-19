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
	{ OAKLEY_ATTR_AUTH_METHOD_RSASIG, "rsasig" }, 
	{ OAKLEY_ATTR_AUTH_METHOD_PSKEY , "pre_shared_key" }, 
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


int write_PH1_proposal(FILE *fp, short dh_group, int authentication_type)
{
	int  enc = 0, hash = 0, auth = authentication_type - 1;
	for(enc = 0; enc < MAX_ENC_TYPES; enc++)
	{
		for(hash = 0; hash < MAX_HASH_TYPES; hash++)
		{
			fprintf(fp, "	proposal {\n");
			fprintf(fp, "		encryption_algorithm %s;\n",ph1encarray[enc].string);
			fprintf(fp, "		hash_algorithm %s;\n", ph1hasharray[hash].string);
			fprintf(fp, "		authentication_method %s;\n", ph1autharray[auth].string);
			fprintf(fp, "		dh_group %s;\n",ph1dharray[dh_group-1].string);
			fprintf(fp, "	}\n");
		}
	}
	return 0;
}

