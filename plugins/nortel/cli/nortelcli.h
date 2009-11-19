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
#ifndef __NORTELCLI_H__
#define __NORTELCLI_H__

#include <sys/types.h>
#include <libintl.h>

#ifdef HAVE_TURNPIKE_DIR
#include "commoncli.h"
#else
#include "turnpike/commoncli.h"
#endif

#define _(x)  (gettext ( (const char *) (x)))

#define CERTIFICATE 1
#define XAUTH 2

struct pluginInfo {
	
	struct interfaceInfo ifInfo;
	u_int32_t assigned_ip_addr;
	u_int32_t assigned_net_mask;
	u_int32_t assigned_dns_addr1; // Primary DNS addr
	u_int32_t assigned_dns_addr2; // Secondary DNS addr
	char* assigned_domain_name;
	int (*nortel_event_handler)(int evt_type, void *gp);
	
	/* Any other plugin specific info can go here */
};

#endif // __NORTELCLI_H__
