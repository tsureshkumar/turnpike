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
#ifndef __PHASE2_H__
#define __PHASE2_H__ 1

/* Racoon Headers */
#include "racoon/admin.h"
#include "racoon/oakley.h"
#include "racoon/evt.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/ipsec_doi.h"


#define MAX_PH2ENC_TYPES 3

typedef struct ph2enctypes     Phase2EncodeTypes;
typedef struct ph2hashtypes    Phase2HashTypes;
typedef struct ph2dhtypes      Phase2DHTypes;

struct ph2enctypes {
	int value;
	char *string;
};

#define MAX_PH2HASH_TYPES 2
struct ph2hashtypes {
	int value;
	char *string;
};

#define MAX_PH2DH_TYPES 2 
struct ph2dhtypes {
	int value;
	char *string;
};

char *ph2get_enctype(int enctype);
char *ph2get_authmethod(int authmethod);
char *ph2get_pfsgroup(int pfsgroup);
void write_PH2_proposal(FILE *fp, short pfs_group);

#endif // __PHASE2_H__
