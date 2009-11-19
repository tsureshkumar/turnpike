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
#ifndef __PAYLOAD_GEN_H__
#define __PAYLOAD_GEN_H__

#include "racoon/vmbuf.h"
#include "racoon/handler.h"

#include "packets.h"

typedef struct kaInf{

    struct sched *s;
    traffic_t traf;
    u_int32_t kainsec; // keepalive interval in secs
    
}kaInf_t;

int generateNortelVID(struct payload_list *pl, struct ph1handle *);
int generateOpaqueID(vchar_t *grpname, vchar_t **);
int generateNotifyPayload(vchar_t *payload, struct ph1handle *iph1, int type, u_int32_t );

#endif
