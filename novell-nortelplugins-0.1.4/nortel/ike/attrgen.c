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
#include <sys/queue.h>
#include <netinet/in.h>
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "utility.h"

/* Racoon Headers */
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/nattraversal.h"
#include "racoon/evt.h"

extern int nat_dst_float_port;

/* Attributes to send */

/* Returns the Attr Len */

static int setAttribute_l(struct isakmp_data *data, u_int16_t type, u_int32_t val)
{ 
    plog(LLV_DEBUG2, LOCATION, NULL, "setAttribute_l type:\n");
	plogdump(LLV_DEBUG2, &type, sizeof(u_int16_t));

    data->type = htons((u_int16_t)type) | 0x8000;
    data->lorv = htons((u_int16_t)val);

    plog(LLV_DEBUG2, LOCATION, NULL, "setAttribute_l type after htons:\n");
	plogdump(LLV_DEBUG2, &data->type, sizeof(u_int16_t));

    return sizeof(struct isakmp_data);
}

static int setAttribute_v(struct isakmp_data *data, u_int16_t type, caddr_t val, u_int16_t len )
{ 
    plog(LLV_DEBUG2, LOCATION, NULL, "setAttribute_v type:\n");
	plogdump(LLV_DEBUG2, &type, sizeof(u_int16_t));

    data->type = htons((u_int16_t)type);

    plog(LLV_DEBUG2, LOCATION, NULL, "setAttribute_v type after htons:\n");
	plogdump(LLV_DEBUG2, &data->type, sizeof(u_int16_t));

    data->lorv = (u_int16_t)len;
    if(val)
        memcpy(data+1,val,len);
    return (sizeof(struct isakmp_data) + len) ;
}

/*****************IKE ATTRIBUTES ******************/


int setCESClientVer(struct isakmp_data *data)
{
    return setAttribute_l(data, CONTIVITY_CLIENT_VERSION, CONTIVITY_CLIENT_VERSION_VALUE );

}

/*****************IPSec Attributes ***************/

/*int setNATFloatingPort(struct isakmp_data *data)
{

   nat_dst_float_port = ntohs(data->lorv); 
	
   return 0;
}*/

/***************** CFG ATTRIBUTES ******************/


/*******************REPLY**************/

int replyXauthType(struct isakmp_data *data)
{
    return setAttribute_l ( data, NORTEL_XAUTH_TYPE, XAUTH_TYPE_RADIUS );
}

int replyXauthUserName(struct isakmp_data *data, int unamelen, caddr_t uname)
{
    plog(LLV_DEBUG2, LOCATION, NULL, "replyXauthUserName:\n");
    plogdump(LLV_DEBUG2, uname, unamelen);
    return setAttribute_v ( data, XAUTH_USER_NAME, uname, unamelen );
}

int replyXauthPasswd(struct isakmp_data *data, int passlen, caddr_t passwd)
{
    return setAttribute_v ( data, XAUTH_USER_PASSWORD, passwd, passlen );
}

int replyCfg3PartyLicense(struct isakmp_data *data)
{
    plog(LLV_DEBUG,LOCATION,NULL,"Acking 3PARTY LICENSE\n"); 
//    printf("Acking 3PARTY LICENSE\n");
    return setAttribute_l ( data, CFG_3RDPARTY_LICENSE_NUMBER , 0 );
}

int replyCfg3PartyVersion(struct isakmp_data *data)
{

    /* Should be client name (49-24), client version (23-16), vendor specific (15-8), reserved (7,0) */
    char version[50] = {'\0'};
    plog(LLV_DEBUG,LOCATION,NULL,"Acking 3PARTY VERSION\n"); 
//    printf("Acking 3PARTY VERSION\n");
    return setAttribute_v ( data, CFG_3RDPARTY_VERSION_DATA , (caddr_t) version, 50 );

}

/*******************ACK**************/

int ackKATimer(struct isakmp_data *data , u_int32_t ka)
{

    plog(LLV_DEBUG,LOCATION,NULL,"Acking KA\n"); 
//    printf("Acking INTERNAL IP\n");

    return setAttribute_v ( data, KEEPALIVE_TIME_INTERVAL, NULL, 0 );
}

int ackIPv4Addr(struct isakmp_data *data , u_int32_t internel_ip )
{

    plog(LLV_DEBUG,LOCATION,NULL,"Acking INTERNAL IP\n"); 

    return setAttribute_v ( data, INTERNAL_IPV4_ADDRESS, NULL, 0 );
}

int ackIPv4Mask(struct isakmp_data *data, u_int32_t internel_mask)
{
    plog(LLV_DEBUG,LOCATION,NULL,"Acking INTERNAL IP MASK\n"); 

    return setAttribute_v ( data, INTERNAL_IPV4_NETMASK, NULL, 0 );
}

int ackIPv4Dns(struct isakmp_data *data, u_int32_t internel_dns)
{
    plog(LLV_DEBUG,LOCATION,NULL,"Acking INTERNAL IP DNS\n"); 

    return setAttribute_v ( data, INTERNAL_IPV4_DNS, NULL, 0 );
}

int ackIPv4DomainName(struct isakmp_data *data, char* internal_domain_name)
{
    plog(LLV_DEBUG,LOCATION,NULL,"Acking INTERNAL DOMAIN NAME\n"); 

    return setAttribute_v ( data, CFG_DOMAIN_NAME, NULL, 0 );
}

int ackCfgBifurcation(struct isakmp_data *data, vchar_t *rt_list)
{
    plog(LLV_DEBUG,LOCATION,NULL,"Acking CFG BIFURCATION\n");

    return setAttribute_v ( data, CFG_BIFURCATION, NULL, 0 );
}


/*******************Attribute payload types **************/

int handleCfgAuthOK(struct isakmp_data *data)
{

    /* 
       1. Inform GUI plugin of the same 
    */
    evt_push(NULL,NULL,EVTT_XAUTH_SUCCESS,NULL);
    plog(LLV_DEBUG,LOCATION,NULL,"XAUTH SUCCEEDED... \n");
    //printf(" XAUTH SUCCEEDED.... \n"); 
    return 0;
}

int handleCfgAuthFailed(struct isakmp_data *data)
{

    /* 
       1. Inform GUI plugin of the same 
    */
//    evt_push(NULL,NULL,EVTT_XAUTH_FAILED,NULL);
    plog(LLV_DEBUG,LOCATION,NULL,"XAUTH FAILED... \n");
 //   printf(" XAUTH FAILED.... \n"); 
   
    return 0;
}

int fill_natt_options(struct ph2natt *natt)
{
	natt->type = UDP_ENCAP_ESPINUDP;
	natt->sport = 4500;
	natt->dport = nat_dst_float_port;
	natt->oa = NULL;

	return 0;   
}
