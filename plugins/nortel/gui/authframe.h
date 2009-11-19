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
#ifndef __AUTHFRAME_H__
#define __AUTHFRAME_H__

#include <gtk/gtk.h>

char * nortel_gui_get_username ();
void   nortel_gui_set_username (const char *username);
char * nortel_gui_get_password ();
char * nortel_gui_get_pm_groupname ();
char * nortel_gui_get_pm_grouppassword ();
void   nortel_gui_set_pm_groupname (const char *groupname);
void   nortel_gui_set_pm_grouppassword (const char *password);
void   nortel_gui_focus_userpasswordentry ();
void   nortel_gui_init ();
void   nortel_gui_cleanup ();

#endif // __AUTHFRAME_H__
