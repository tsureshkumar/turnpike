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
#ifndef __COMMON_ADMIN_H__
#define __COMMON_ADMIN_H__   1

#include <netinet/in.h>

#define GETDATA_IPV4_ADDR_MASK	           1
#define TURNPIKE_INTERFACE_VERSION         1

// from ipsec_doi.h

#define IPSECDOI_ID_IPV4_ADDR                        1
#define IPSECDOI_ID_FQDN                             2
#define IPSECDOI_ID_USER_FQDN                        3
#define IPSECDOI_ID_IPV4_ADDR_SUBNET                 4
#define IPSECDOI_ID_IPV6_ADDR                        5
#define IPSECDOI_ID_IPV6_ADDR_SUBNET                 6
#define IPSECDOI_ID_IPV4_ADDR_RANGE                  7
#define IPSECDOI_ID_IPV6_ADDR_RANGE                  8

#define MAX_BUFFER_SIZE 	                     2048


typedef struct vendor_private_data           VendorPrivateData;
typedef struct vendor_private_data_trailer   VendorPrivateDataTrailer;

typedef struct _nortel_admin_com_addrinfo            AdminComAddrInfo;

int nortel_get_vendor_private_data (char * out, int length, size_t *outlen);

/* REPLACE SA INFO */
struct _nortel_admin_com_addrinfo {
    int addrType; /* Use IPSECDOI_ID_xxxx_xxxx types. eg. IPSECDOI_ID_IPV4_ADDR */
    
    union {
    	struct sockaddr_storage addr;
    	struct {
		struct sockaddr_storage laddr;
        	struct sockaddr_storage haddr;
    	} range;
    } addrt ;
};


int nortel_admin_replace_sainfo (void * out, int length, size_t *outlen,
				 int source_addr,
				 int assigned_ip_addr,
				 int server_addr);

void byte_dump (char *msg, char *p, int length);

#endif // __COMMON_ADMIN_H__
