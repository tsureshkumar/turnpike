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
#ifndef __NORTEL_UTILITY_H__
#define __NORTEL_UTILITY_H__

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int boolean_t;

#ifndef TRUE
#define TRUE 1
#endif // TRUE

#ifndef FALSE
#define FALSE 0
#endif // FALSE

#if 1

//Things required for plog

#include <stdarg.h>

#define HAVE_STDARG_H
#include "common/plog.h"

#endif

#include "racoon/vmbuf.h"

#define  constructPosition(exch, initorresp, sendorrecv, messageno, payload1, payload2) \
         MAKE_POS(exch, initorresp, sendorrecv, messageno, payload1, payload2) 

#define constructHookPoint(hook, Type, attrOrPayloadType, attrOrPayloadSubType, pos, manOrOpt, klen, k)\
{\
    (hook)->type = Type;\
    (hook)->payloadtype = attrOrPayloadType  ;\
    (hook)->subtype = attrOrPayloadSubType;\
    (hook)->position = pos;\
    (hook)->isoptional = manOrOpt;\
    (hook)->keylen = klen;\
    (hook)->key = k;\
}

#define constructHandlerInfo( hi, dataTypeToBeSent, dataTypeToBeRecvd, cback)\
{\
    (hi)->hprivdata = NULL;\
    (hi)->datatypein = dataTypeToBeSent;\
    (hi)->datatypeout = dataTypeToBeRecvd;\
    (hi)->callback = cback;\
}
#if 0 

#define PACK  tpike_pack_in
#define UNPACK tpike_pack_out 

#else
#define PACK(arr, n, ...)  tpike_pack_in((arr),(n),__VA_ARGS__)


#define UNPACK(arr, n, ...) tpike_pack_out((arr),(n),__VA_ARGS__)

#endif

int addRoutesForServerPolicies(
		vchar_t *rt_list,
	   	int vpnGatewayIPAddress,
	   	int assignedIPAddress,
	   	int netMask,
		int split_tunnel);

void ipaliasdown();

int updateDNSForServerPolicies(
		int no_dns,
		int primary_dns,
		int secondary_dns,
		char *domain);

void dnsdown();

extern const char * sock_numeric_host (struct sockaddr *sa);

#endif

