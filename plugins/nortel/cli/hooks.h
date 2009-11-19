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
#ifndef __HOOKS_H__
#define __HOOKS_H__

int nortel_get_privdata(char *buf, void *gp);
void nortel_event_handler(int state, void *gp);
void nortel_get_ikeplugin_lib_path(char *libpath);

int nortel_cli_plugin_init(void *cp, void **gp);
int nortel_write_racoon_conf_for_reparse(struct racoon_conf *rcbuf, void *gp);
int nortel_disconnect(char *buf);
int nortel_update_profile (char *profilename);
int nortel_create_vendor_profile(char *vendorProfileFileName);

#endif // __HOOKS_H__
