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
#ifndef __ADMIN_PORT_H__
#define __ADMIN_PORT_H__ 1
#include <netinet/in.h>

#define TURNPIKE_INTERFACE_VERSION 1

#define EVTT_ISAKMP_CFG_DONE	4
#define EVTT_PHASE2_UP		5

#define MAX_BUFFER_SIZE         2048

#define ADMIN_REPLACE_SAINFO            0x0306
#define ADMIN_GET_VENDOR_PRIV_DATA      0X0308
#define ADMIN_PROTO_ISAKMP	        0x01ff


#define GETDATA_IPV4_ADDR_MASK	1

// from ipsec_doi.h

#define IPSECDOI_ID_IPV4_ADDR                        1
#define IPSECDOI_ID_FQDN                             2
#define IPSECDOI_ID_USER_FQDN                        3
#define IPSECDOI_ID_IPV4_ADDR_SUBNET                 4
#define IPSECDOI_ID_IPV6_ADDR                        5
#define IPSECDOI_ID_IPV6_ADDR_SUBNET                 6
#define IPSECDOI_ID_IPV4_ADDR_RANGE                  7
#define IPSECDOI_ID_IPV6_ADDR_RANGE                  8


typedef struct admin_com_ph1proposal         AdminComPh1Proposal;
typedef struct admin_com_ph1config           AdminComPh1Config;
typedef struct admin_com_ph1proposal_list    AdminComPh1ProposalList;

typedef struct admin_com                     AdminComHeader;
typedef struct admin_com                     comHeader_t;

typedef struct _RacoonConfInfo               RacoonConfInfo;

struct admin_com_ph1proposal {
        u_int8_t        encryption_algo;
        u_int8_t        hash_algo;
        u_int8_t        auth_method;
        u_int8_t        dh_group;
};

struct admin_com_ph1config {
        struct sockaddr_storage dst; //dst
        u_int8_t                mode;
        u_int8_t                verify_cert;
        
	/* Temporary Fix : Begin */
        u_int8_t                certtype;
        char                    mycertfile[512];
        char                    myprivfile[512];
        char                    peerscertfile[512];
        /* Temporary Fix : End */

        u_int8_t                verify_identifier; // = 0
        u_int8_t                my_identifier_type; // ASN1DN
        u_int16_t               my_identifier_len; // = 0
        u_int16_t               num_peer_identifier; // = 0
        char                    id[1];          //will be in format – my_identifier followed by peer_identifier struct(s)
};

struct admin_com_ph1proposal_list {
        struct sockaddr_storage dst;
        u_int8_t num_proposal; /* number of proposals being sent */
        struct admin_com_ph1proposal ph1proposal[1];/* if num_proposal > 1, */
                                        /*this will be a list of proposals */
};


struct admin_com {
	u_int16_t ac_len;	/* total packet length including data */
	u_int16_t ac_cmd;
	int16_t ac_errno;
	u_int16_t ac_proto;
};

struct _RacoonConfInfo
{
	char filename[256];
	int nat_traversal;
	char server_ip_addr[64];
	char source_ip_addr[64];
	char racoon_cert_path[256];
	struct 
	{
		char encalgo[64];
		char hashalgo[64];
		char authmethod[64];
		char dhgroup[64];
	} ph1_proposal;
	struct 
	{
		char encalgo[64];
		char hashalgo[64];
		char pfsgroup[64];
	} ph2_proposal;
};

#endif // __ADMIN_PORT_H__
