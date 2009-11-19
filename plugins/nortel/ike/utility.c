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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <openssl/des.h>


#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "callbacks.h"
#include "utility.h"
#include "nortel_cfg.h"

#include "racoon/admin.h"

#include "common/encrypt.h"
#include "common/plog.h"

#define STRIVEC "QWERTGBVCXZA"

#define IPADDR_CFGFILE "/var/tmp/ipcfg"
#define DNS_CFGFILE "/var/tmp/dnscfg"
#define IPALIASUP   LIB_LOAD_PATH"/ipalias up"
#define IPALIASDOWN LIB_LOAD_PATH"/ipalias down"
#define DNSUP LIB_LOAD_PATH"/dnsupdate up"
#define DNSDOWN LIB_LOAD_PATH"/dnsupdate down"

static int writeDNScfg(
	int no_dns,
	int primary_dns,
	int secondary_dns,
	char *domain)
{
	FILE *fd;
	struct in_addr inaddr;

	if ((fd = fopen(DNS_CFGFILE, "w+")) == NULL ) {
		return -1;
	}

	fprintf(fd, "NOT_SET_DNS=%d\n", no_dns);

	if (domain && strlen (domain))
		fprintf(fd, "DOMAIN_NAME=%s\n", domain);

	if (primary_dns) {
		inaddr.s_addr = primary_dns;
		fprintf(fd, "PRIMARY_DNS=%s\n", inet_ntoa (inaddr));
	}

	if (secondary_dns) {
		inaddr.s_addr = secondary_dns;
		fprintf(fd, "SECONDARY_DNS=%s\n", inet_ntoa (inaddr));
	}

	fclose(fd);

	return 0;
}

static int writeToIpcfg(
	long *iplst,
   	int num,
   	int gwaddr,
   	int assignedip,
   	int netmask,
	int no_split_tunnel)
{
	FILE *fd;
	int i = 0;
	struct in_addr inaddr;

	if ((fd = fopen(IPADDR_CFGFILE, "w+")) == NULL ) {
		return -1;
	}

	fprintf(fd, "NO_SPLIT_TUNNEL=%d\n", no_split_tunnel);

	inaddr.s_addr = gwaddr;
	fprintf(fd, "GWADDR=%s\n", inet_ntoa(inaddr));

	inaddr.s_addr = assignedip;
	fprintf(fd, "ASSIGNEDIP=%s\n", inet_ntoa(inaddr));

	inaddr.s_addr = netmask;
	fprintf(fd, "NETMASK=%s\n", inet_ntoa(inaddr));

	inaddr.s_addr = assignedip & netmask;
	inaddr.s_addr = inaddr.s_addr | (~netmask);
	fprintf(fd, "BROADCAST=%s\n", inet_ntoa(inaddr));

	fprintf(fd, "NUMRT=%d\n", num);

	if (!num)
		fprintf(fd, "ANY=1\n");
	else
	{
		for (i = 0; i < num; i += 2) {
			inaddr.s_addr = *(iplst + i);
			fprintf(fd, "IPADDR[%d]=%s\n", i, inet_ntoa(inaddr));
			inaddr.s_addr = *(iplst + i +1);
			fprintf(fd, "IPMASK[%d]=%d\n", i, * ((int *) &inaddr));
		}
	}

	fclose(fd);
	/* don't set the interface, vpnc or NM will set it.*/
	if (-1 == system(IPALIASUP)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"Run script(%s) failed.\n", IPALIASUP);
	}
	return 0;
}

void ipaliasup()
{
	if (-1 == system(IPALIASUP)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"Run script(%s) failed.\n", IPALIASUP);
	}
}

void ipaliasdown()
{
	if (-1 == system(IPALIASDOWN)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"Run script(%s) failed.\n", IPALIASDOWN);
	}
}

int addRoutesForServerPolicies(
		vchar_t *rt_list,
	   	int vpnGatewayIPAddress,
	   	int assignedIPAddress,
	   	int netMask,
		int no_split_tunnel)
{
	uint32_t tmpmask = 0;
	int dstPrefixLen = 0;
	long *ipaddrlst = NULL;
	int iplstnum = 0;
	int tlen = 0;
	uint32_t net = 0, mask = 0; 
	int ipaddr_num = 0;

	if (rt_list) {
		ipaddr_num = rt_list->l / 8;

		plog(LLV_DEBUG, LOCATION, NULL,
				"The list of route length is %zu, all %d groups.\n",
				rt_list->l, ipaddr_num);

		ipaddrlst = (long *)malloc(ipaddr_num * sizeof(long) * 2);
		if (NULL == ipaddrlst) {
			plog(LLV_ERROR, LOCATION, NULL,
					"Malloc memory failed in addRoutesForServerPolicies.\n");
			return -1;
		}

		memset(ipaddrlst, 0x0, ipaddr_num * sizeof(long) * 2);

		for (tlen = 0; tlen < rt_list->l ; tlen+=8) {
			net = *((unsigned long int*)(((char *)(rt_list->v))+tlen));
			mask = *((uint32_t *)(((char *)(rt_list->v))+tlen+4));

			tmpmask = mask;
			dstPrefixLen = 0; 

			tmpmask = ntohl(tmpmask);
			while (tmpmask){
				tmpmask = tmpmask << 1;
				dstPrefixLen++;
			}

			*(ipaddrlst + iplstnum) = net;
			*(ipaddrlst + iplstnum + 1) = dstPrefixLen;
			iplstnum += 2;
		}
	}

	plog(LLV_DEBUG, LOCATION, NULL,
			"Write addrlist to file, list len is %d, ipaddr len is %d.\n",
			iplstnum, ipaddr_num);

	writeToIpcfg(ipaddrlst, iplstnum, vpnGatewayIPAddress,
		   	assignedIPAddress, netMask, no_split_tunnel);

	if (NULL != ipaddrlst)
		free(ipaddrlst);

	return 0;
}

/* convert sockaddress to a numeric host string */
const char * sock_numeric_host (struct sockaddr *sa)
{
	static char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int len;

	if (sa == NULL)
		return NULL;
#ifdef __linux__
	len =  sizeof (struct sockaddr_in);
#else /*! __linux__ */
	len = sa->sa_len;
#endif 

	if (getnameinfo(sa, len, hbuf, sizeof(hbuf), sbuf,
				sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0)
		return hbuf;
	return NULL;
}

int updateDNSForServerPolicies(
		int no_dns,
		int primary_dns,
		int secondary_dns,
		char *domain)
{
	int ret = 0;

	ret = writeDNScfg (no_dns, primary_dns, secondary_dns, domain);
	if (ret != 0) {
		plog(LLV_ERROR, LOCATION, NULL, "writeDNScfg failed.\n");
		return -1;
	}

    /* don't set the interface, vpnc or NM will set it.*/
	if (-1 == system(DNSUP)) {
		plog(LLV_ERROR, LOCATION, NULL,
				"Run script(%s) failed.\n", DNSUP);
	}

	return 0;
}

void dnsdown()
{
	if (-1 == system(DNSDOWN)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"Run script(%s) failed.\n", DNSDOWN);
	}
}
