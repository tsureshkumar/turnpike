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
#ifndef __H_NORTEL_CFG__
#define _H_NORTEL_CFG__

#include "utility.h"

inline boolean_t nortel_cfg_split_tunnel_mode (
		struct nortelHandle *h_nortel);
int nortel_cfg_split_tunnel (struct nortelHandle *h_nortel);
struct isakmp_data * nortel_cfg_set (struct nortelHandle * h_nortel, 
                                     struct isakmp_data *attr);
#endif /* _H_NORTEL_CFG__ */
