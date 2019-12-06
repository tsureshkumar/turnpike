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
#include <inttypes.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PATH_IPSEC_H <netinet/ipsec.h>

#include <libipsec/libpfkey.h>
#include <racoon/admin.h>


/* My headers */
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "callbacks.h"
#include "utility.h"

#include "racoon/handler.h"

#include "common/plog.h"

struct ph1handle *
nortel_get_ph1_handle (struct nortelHandle * h_nortel)
{
   uint32_t gateway_ip = h_nortel->cfg->gatewayIP;
   struct sockaddr_in remote;
   struct ph1handle *ph1handle = NULL;

   /* get remote gw into sockaddr */
   memset (&remote, 0, sizeof (remote));
   remote.sin_family = AF_INET;
   remote.sin_addr.s_addr = gateway_ip;

   ph1handle = getph1bydstaddrwop ( (struct sockaddr *) &remote);

   return ph1handle;
}
