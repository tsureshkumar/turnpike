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

#include "phase2.h"


Phase2EncodeTypes ph2encarray[] = {
	{ OAKLEY_ATTR_ENC_ALG_DES, "des" }, 
	{ OAKLEY_ATTR_ENC_ALG_3DES, "3des" }, 
	{ OAKLEY_ATTR_ENC_ALG_AES, "aes" }, 
	{ -1, ""},
};

Phase2HashTypes ph2hasharray[] = {
	{ OAKLEY_ATTR_HASH_ALG_MD5, "hmac_md5" }, 
	{ OAKLEY_ATTR_HASH_ALG_SHA, "hmac_sha1" }, 
	{ -1, ""},
};

Phase2DHTypes  ph2dharray[] = {
	{ OAKLEY_ATTR_GRP_DESC_MODP768, "1" }, 
	{ OAKLEY_ATTR_GRP_DESC_MODP1024, "2" }, 
	{ 0, ""},
};

char *ph2get_enctype(int enctype)
{

	int i=0;

	for(i=0; i < MAX_PH2ENC_TYPES ; i++)
	{
		if (enctype == ph2encarray[i].value)
			return ph2encarray[i].string;
	}
	return NULL;
}

char *ph2get_authmethod(int authmethod)
{

	int i=0;

	for(i=0; i < MAX_PH2HASH_TYPES ; i++)
	{
		if (authmethod == ph2hasharray[i].value)
			return ph2hasharray[i].string;
	}
	return NULL;
}

char *ph2get_pfsgroup(int pfsgroup)
{

	int i=0;

	for(i=0; i < MAX_PH2DH_TYPES ; i++)
	{
		if (pfsgroup == ph2dharray[i].value)
			return ph2dharray[i].string;
	}
	return NULL;
}

/* Multiple proposal for phase 2 */
void write_PH2_proposal(FILE *fp, short pfs_group)
{
	int enc = 0, auth = 0;

	
	/* Supported pfs groups */
/*	fprintf(fp, "	pfs_group ");
	for(pfsg = 1; pfsg <= MAX_PH2DH_TYPES; pfsg++)
	{
		if (pfsg == MAX_PH2DH_TYPES)
			fprintf(fp,"%s;\n",ph2dharray[pfsg-1].string );
		else	
			fprintf(fp,"%s, ", ph2dharray[pfsg-1].string );
	}
*/
	if(pfs_group != 0)
		fprintf(fp, "	pfs_group %d;\n", pfs_group);
	/* Supported enc algo */
	fprintf(fp, "	encryption_algorithm ");
	for(enc = 1; enc <= MAX_PH2ENC_TYPES; enc++)
	{
		if (enc == MAX_PH2ENC_TYPES)
			fprintf(fp,"%s;\n", ph2encarray[enc-1].string);
		else
			fprintf(fp,"%s,", ph2encarray[enc-1].string);
	}

	/* Supported auth algo */
	fprintf(fp, "	authentication_algorithm ");
	for(auth = 1; auth <= MAX_PH2HASH_TYPES; auth++)
	{
		if (auth == MAX_PH2HASH_TYPES)
			fprintf(fp,"%s;\n", ph2hasharray[auth-1].string);
		else
			fprintf(fp,"%s,", ph2hasharray[auth-1].string);
	}
	fprintf(fp, "	compression_algorithm deflate;\n");

	return;
}
