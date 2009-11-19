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
#ifndef __NORTEL_INF_H__
#define __NORTEL_INF_H__ 


/* Nortel Plugin Version
 * please increment this when any structure format, 
 * function prototype etc. changes 
*/
#define NORTEL_IKEPLUGIN_VERSION	 0x0001

/* IKE Attributes */
#define CONTIVITY_CLIENT_VERSION	 0xFFFF
#define XTNDD_CONTIVITY_CLIENT_VERSION	 0x7FFF 

/* IKE Attributes Value */
#define CONTIVITY_CLIENT_VERSION_VALUE 0x0b00

/*IPSec Attribute value */
#define UDP_ENCAP_FLAG	0x7ffe

#define NATT_VERSION_VENDOR_SPECIFIC 0x00ffff00
#define UDP_ENCAP_ESPINUDP		2

/* CFG ATTR */
// This should be in the "src/racoon/isakmp_cfg.h"
// The CES uses the first two attributes to assign an IP address and
// netmask to the VPN client.
// The EAC sets the IP address and mask of the virtual IP interface to
// these value.
#define INTERNAL_IPV4_ADDRESS		1
#define INTERNAL_IPV4_NETMASK		2		
// The IP address of DNS server that the client should use to resolve
// internal DNS names. Now the client only support the primary and
// secondary DNS server address.
#define INTERNAL_IPV4_DNS			3
#define INTERNAL_IPV4_NBNS			4
#define INTERNAL_IPV4_DHCP			6

/* support big endian for ppc */
#if BYTE_ORDER == BIG_ENDIAN
#define NORTEL_XAUTH_TYPE           0x000D
#define XAUTH_USER_NAME             0x000E
#define XAUTH_USER_PASSWORD         0x000F
#else
#define NORTEL_XAUTH_TYPE           0x0D00
#define XAUTH_USER_NAME             0x0E00
#define XAUTH_USER_PASSWORD         0x0F00
#endif

//Nortel properitary stuff
#define CFG_BIFURCATION     	       0x4000
#define KEEPALIVE_TIME_INTERVAL        0x4009 
#define CFG_3RDPARTY_LICENSE_NUMBER    0x4011 
#define CFG_3RDPARTY_VERSION_DATA      0x4012
#define CFG_DOMAIN_NAME                0x4005
#define CFG_NAT_KEEPALIVE_INTERVAL     0x400F

/* CFG ATTR Values */
#define XAUTH_TYPE_RADIUS 1

/* CFG Attribute payload types. In addition to normal SET/ACK/REQ/REP */

#define ISAKMP_CFG_AUTH_OK         5
#define ISAKMP_CFG_AUTH_FAILED     6

/* Config Data Structure */

struct configInf{

	u_int32_t gatewayIP;
	vchar_t uname;
	vchar_t upass;
	vchar_t grpname;
	vchar_t grppasswd;

};

struct nortelHandle{

	struct configInf *cfg;

	/* TODO: Make these as 1 bit values */
	u_int8_t isAuthSuccess; /* 0 - failure, 1 - success */
	u_int8_t isNatDetected; /* 0 - failure, 1 - success */
	u_int8_t isPhase2Complete; /* 0- not complete, 1 - complete */
	u_int8_t noSplitTunnel; /* 1- no split tunnel, 0 - split tunnel, default value */
	u_int8_t noDNS;         /* 1- don't set DNS and Domain name, 0 - use the dnsupdate script set them */
	u_int32_t keepAliveInSec; /* in secs */

	u_int32_t assignedIPAddr;
	u_int32_t assignedNetMask;
	u_int32_t assignedDNSAddrPrimary;
	u_int32_t assignedDNSAddrSecondary;
	char assignedDomainName[256];
	vchar_t *rt_list;       /* list of routes */
};

/* nortel plugin-framework interface functions */

/* turnpike_nortel_getdata: Get nortel specific data
 * GETDATA_IPV4ADDRMASK: In: type - GETDATA_IPV4ADDRMASK - 4 bytes - host order
 *                       Out: ipv4addr - 4 bytes - host order
 *                            ipv4mask - 4 bytes - host order
 * GETDATA_DNSADDR:      In: type = GETDATA_DNSADDR - 4 bytes - host order
 *                       Out: numofentries - 4 bytes - host order
 *                            list of ipv4addr - 4 bytes each - host order
 * GETDATA_VERSION:      In: type = GETDATA_VERSION - 4 bytes - host order
 *                       Out: version - 4 bytes - host order
 */
#define GETDATA_VERSION 0
#define GETDATA_IPV4ADDRMASK 1
#define GETDATA_DNSADDR 2

/* Turnpike Interface data version  */
#define TURNPIKE_INTERFACE_VER 1

extern int turnpike_nortel_getdata(short ver, void *gprivdata, int inlen, char *inbuf,
				   int *outlen, char **outbuf);
extern int turnpike_nortel_init(short ver, void *configptr, void **gprivdata);

/* Handler callback prototype */ 
typedef int (*CALLBACK)(void *, void *, void *, void **);

#define  GETPLUGINHANDLE(x) ((struct nortelHandle *)((x)))


struct ph1handle * nortel_get_ph1_handle (struct nortelHandle * h_nortel);

#endif
