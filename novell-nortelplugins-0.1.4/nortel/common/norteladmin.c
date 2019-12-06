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
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <linux/errno.h>
#include <time.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

// racoon headers
#include "racoon/admin.h"

#include "norteladmin.h"

/*
 * @out    : buffer to fill private data
 * @length : length of input buffer
 * @@outlen : length filled in, -1 if buffer is not enough
 * returns : n if length is not enough where n is additional bytes needed.
 *           0, if buffer is enough
 */
int
nortel_get_vendor_private_data (char * out, int length, size_t *outlen)
{
	const char * plugin_name = "nortel";
	char *p = out;

	assert (out != NULL);

	* ((short *) p) = TURNPIKE_INTERFACE_VERSION;

	p += sizeof (short);
	* ((size_t *) p)   = strlen (plugin_name);
	p += sizeof (size_t);
	strcpy (p, plugin_name);
	p += strlen (plugin_name);

	* ((size_t *) p) = sizeof (int);  // private data length
	p += sizeof (size_t);

        // private data starts here
	* ((int *) p) = GETDATA_IPV4_ADDR_MASK;
	p += sizeof (int);

	*outlen = p - out;
	return 0;
}

/*
 * @out    : buffer to fill private data
 * @length : length of input buffer
 * @@outlen : length filled in, -1 if buffer is not enough
 * returns : n if length is not enough where n is additional bytes needed.
 *           0, if buffer is enough
 */
int
nortel_admin_replace_sainfo (void * out, int length, size_t *outlen,
			     int source_addr,
			     int assigned_ip_addr,
			     int server_addr)
{
	struct admin_com_replace_sainfo *sa_info = NULL;
	struct sockaddr_in *sock_addr = NULL;

	assert (out != NULL);

	// FIXME : check input buffer length

	sa_info = (struct admin_com_replace_sainfo *) out;
			
	sa_info->old_src_addr.addrtype = IPSECDOI_ID_IPV4_ADDR;
	sock_addr = (struct sockaddr_in *) &(sa_info->old_src_addr.addrt.addr);
	sock_addr->sin_addr.s_addr = source_addr;
	sock_addr->sin_family      = AF_INET;
			
	sa_info->old_dst_addr.addrtype = IPSECDOI_ID_IPV4_ADDR_RANGE;
	sock_addr = (struct sockaddr_in *) &(sa_info->old_dst_addr.addrt.range.laddr);
	sock_addr->sin_addr.s_addr = 0x0;
	sock_addr->sin_family      = AF_INET;
	sock_addr = (struct sockaddr_in *) &(sa_info->old_dst_addr.addrt.range.haddr);
	sock_addr->sin_addr.s_addr = 0xffffffff;
	sock_addr->sin_family      = AF_INET;

	sa_info->new_src_addr.addrtype = IPSECDOI_ID_IPV4_ADDR;
	sock_addr = (struct sockaddr_in *) &(sa_info->new_src_addr.addrt.addr);
	sock_addr->sin_addr.s_addr = assigned_ip_addr;
	sock_addr->sin_family      = AF_INET;

	sa_info->new_dst_addr.addrtype = IPSECDOI_ID_IPV4_ADDR_RANGE;
	sock_addr = (struct sockaddr_in *) &(sa_info->new_dst_addr.addrt.range.laddr);
	sock_addr->sin_addr.s_addr = 0x0;
	sock_addr->sin_family      = AF_INET;
	sock_addr = (struct sockaddr_in *) &(sa_info->new_dst_addr.addrt.range.haddr);
	sock_addr->sin_addr.s_addr = 0xffffffff;
	sock_addr->sin_family      = AF_INET;

	sock_addr = (struct sockaddr_in *)&(sa_info->peeraddr);
	sock_addr->sin_addr.s_addr = server_addr;
	sock_addr->sin_family = AF_INET;

	*outlen = sizeof (struct admin_com_replace_sainfo);
	return 0;
}


void byte_dump (char *msg, char *p, int length)
{
	char *pp = p;
	printf ("%s: ", msg);
	while (pp-p <=length) {
		printf ("%02X", (unsigned int) (*pp));
		pp++;
	}
	printf ("\n");
}
