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
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "nortel_vmbuf.h"
#include "nortel_inf.h"

/* Racoon Headers */
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/nattraversal.h"

#include "plugin_frame/common.h"

int NATDetected = 0;

int check_NortelVID(struct isakmp_gen *gen, struct isakmp_data **resp)
{
    struct isakmp_data *plresp = NULL;
    struct ph1natt_options *natt = NULL;
 
    if(gen==NULL)
    {
	return -1;
    }
//    printf("%x (0x53454e42) \n", (*((u_int32_t *)(gen + 1))));
        
    if(*((u_int32_t *)(gen + 1) ) == 0x53454E42 )
    {
	*resp = (struct isakmp_data *)malloc(sizeof(struct isakmp_data));
	plresp = *resp;
	plresp->type = PRIVATE_VID_PAYLOAD_TYPE;
	plresp->lorv = 0;
        return 0;
    }

    if(!memcmp(gen+1,"NaT-SI",6))
    {
	NATDetected = 1;

	*resp = (struct isakmp_data *)malloc(sizeof(struct isakmp_data) + sizeof(struct ph1natt_options));

	plresp = *resp;
	plresp->type = PRIVATE_NATTVID_PAYLOAD_TYPE;
	plresp->lorv = sizeof(struct ph1natt_options);

	natt = (struct ph1natt_options *) (plresp + 1);

	memset(natt, 0, sizeof(struct ph1natt_options));
	natt->version = NATT_VERSION_VENDOR_SPECIFIC;
	natt->float_port = 4500;
	natt->encaps_type = UDP_ENCAP_ESPINUDP;

        return 0; //NAT Detected
    }   
    return -1;
    
}

