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
#ifndef __COMMON_PROFILE_H__
#define __COMMON_PROFILE_H__ 1

int nortel_profile_update_user (const char *file_name, const char *username);
int nortel_rewrite_profile (const char *file_name,
			    const char *group_name,
			    const char *group_password,
			    const char *gatewayIP );
int nortel_read_profile (const char *profilename,
			 char *groupName,
			 char *grpPasswd,
			 char *usrName);

const char * nortel_get_profile_location (const char *name);
int nortel_enc_password(char *group_unenc_password, 
			int unenc_len, 
			char *group_enc_password, 
			int enc_len);

#endif // __COMMON_PROFILE_H__
