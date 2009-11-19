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
#ifndef __PHASE1_H__
#define __PHASE1_H__ 1

//Racoon Headers
#include "racoon/admin.h"
#include "racoon/oakley.h"
#include "racoon/evt.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/ipsec_doi.h"

typedef struct ph1enctypes       Phase1EncodeTypes;
typedef struct ph1hashtypes      Phase1HashTypes;
typedef struct ph1modetypes      Phase1ModeTypes;
typedef struct ph1dhtypes        Phase1DHTypes;
typedef struct ph1authtypes      Phase1AuthTypes;

#define MAX_ENC_TYPES 3
struct ph1enctypes {
	int value;
	char *string;
};


#define MAX_HASH_TYPES 2
struct ph1hashtypes {
	int value;
	char *string;
};

#define MAX_MODE_TYPES 2
struct ph1modetypes {
	int value;
	char *string;
};
	
#define MAX_DH_TYPES 2

struct ph1dhtypes {
	int value;
	char *string;
} ;

#define MAX_AUTH_TYPES 2 
struct ph1authtypes {
	int value;
	char *string;
};

char *ph1get_encalgo(int enctype);
char *ph1get_hashalgo(int hashtype);
char *ph1get_authmethod(int authmethod) ;
char *ph1get_dhtype(int dhtype);
char *ph1get_modestr(int mode);
int write_PH1_proposal(FILE *fp, short dh_group, int);

#endif // __PHASE1_H__
