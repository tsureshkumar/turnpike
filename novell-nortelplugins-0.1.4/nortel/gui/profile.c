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
#include <sys/stat.h>


#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

#include "authframe.h"

#include "common/profile.h"
#include "common/encrypt.h"

extern void show_dialog_message(char *string); // turnpike

int nortel_write_profile (char *fileName, char* gatewayIP);
int nortel_display_profile (char * vendorFile);
int nortel_pm_load_from_vendor_profile (char *profile);
int nortel_load_from_vendor_profile (char *profile);
int parse_vendor_profile (char *profilename);
int pm_parse_vendor_profile (char *profilename);
int nortel_update_profile (char *profilename);

extern char grpName [256];
extern char grpPasswd [256];
extern char usrName [256];

int
nortel_write_profile (char *fileName, char* gatewayIP)
{
	char *groupN = NULL;
	char *groupP = NULL;
	
	groupN = nortel_gui_get_pm_groupname ();
	groupP = nortel_gui_get_pm_grouppassword ();

	return nortel_rewrite_profile ( (const char *) fileName,
					(const char *) groupN,
					(const char *) groupP,
					(const char *) gatewayIP
					);
	return 0;
}

int
nortel_display_profile (char * vendorFile)
{
	return 0;
}

int 
nortel_pm_load_from_vendor_profile (char *profile)
{
	char groupPDec[128];
	size_t groupPDecLen = sizeof(groupPDec);

	pm_parse_vendor_profile(profile);
	nortel_decode (grpPasswd, strlen ( (const char *) grpPasswd), groupPDec, &groupPDecLen, ENCRYPT_KEY, strlen ( (const char *) ENCRYPT_KEY));
	nortel_gui_set_pm_groupname ( (const char *) grpName);
	nortel_gui_set_pm_grouppassword ( (const char *) groupPDec);
	//gtk_entry_set_text((GtkEntry *)userNameEntry, usrName);
	return 0;
}

int
nortel_load_from_vendor_profile (char *profile)
{
	parse_vendor_profile(profile);
	//gtk_entry_set_text((GtkEntry *)groupNameEntry, grpName);
	//gtk_entry_set_text((GtkEntry *)groupPasswdEntry, grpPasswd);
	//gtk_widget_set_sensitive(groupNameEntry, FALSE);
	//gtk_widget_set_sensitive(groupPasswdEntry, FALSE);
	return 0;
}

int
pm_parse_vendor_profile (char *profilename)
{
	nortel_read_profile ( (const char *) profilename,
			      grpName,
			      grpPasswd,
			      usrName);
	return 0;
}

int
parse_vendor_profile (char *profilename)
{
	nortel_read_profile ( (const char *) profilename,
			      grpName,
			      grpPasswd,
			      usrName);
	nortel_gui_set_username (usrName);
	if( strcmp(usrName,"")!=0)
		nortel_gui_focus_userpasswordentry ();
	return 0;

}

int
nortel_update_profile (char *profilename)
{
	return nortel_profile_update_user ((const char *) profilename,
					   nortel_gui_get_username ()
		);
}
