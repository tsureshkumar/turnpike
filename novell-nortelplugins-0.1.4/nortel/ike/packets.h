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
#ifndef __NORTEL_TRAFFIC_H__
#define  __NORTEL_TRAFFIC_H__

#include <sys/types.h>

typedef struct traffic
{
    u_int32_t local;
    u_int32_t remote;
    double outbytes;
    double inbytes;
    
}traffic_t;

//int create_pfkey_socket();
int isNoTraffic(traffic_t *t);

#endif

