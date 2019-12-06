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
#ifndef __NORTEL_ATTRGEN_H__
#define __NORTEL_ATTRGEN_H__

#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/nattraversal.h"
#include "racoon/evt.h"

int setCESClientVer(struct isakmp_data *data);
int replyXauthType(struct isakmp_data *data);
int replyXauthUserName(struct isakmp_data *data, int unamelen, caddr_t uname);
int replyXauthPasswd(struct isakmp_data *data, int passlen, caddr_t passwd);
int replyCfg3PartyLicense(struct isakmp_data *data);
int replyCfg3PartyVersion(struct isakmp_data *data);
int ackKATimer(struct isakmp_data *data , u_int32_t ka);
int ackIPv4Addr(struct isakmp_data *data , u_int32_t internel_ip );
int ackIPv4Mask(struct isakmp_data *data, u_int32_t internel_mask);
int ackIPv4Dns(struct isakmp_data *data, u_int32_t internel_dns);
int ackIPv4DomainName(struct isakmp_data *data, char* DomainName);
int ackCfgBifurcation(struct isakmp_data *data, vchar_t *rt_list);
int handleCfgAuthOK(struct isakmp_data *data);
int handleCfgAuthFailed(struct isakmp_data *data);
int fill_natt_options(struct ph2natt *natt);

#endif // __NORTEL_ATTRGEN_H__
