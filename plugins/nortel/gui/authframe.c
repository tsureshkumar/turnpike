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
#include <stdarg.h>
#include "authframe.h"

extern int pmPluginActive;

extern GtkWidget *mainWindow;
extern GtkWidget *gwMaintable;
extern GtkWidget *pmGeneralTable;
extern GtkWidget *pmAuthenticateLabel;
extern GtkWidget *pmauthenticateCombo;

GtkWidget *authFrame = NULL;
GtkWidget *pmAuthFrame = NULL;
GtkWidget *newAuthFrame = NULL;
GtkWidget *newPmAuthFrame = NULL;


GtkWidget *groupNamelabel;
GtkWidget *groupNameEntry;
GtkWidget *groupPasswdLabel;
GtkWidget *groupPasswdEntry;

GtkWidget *pmGroupNamelabel;
GtkWidget *pmGroupNameEntry;
GtkWidget *pmGroupPasswdLabel;
GtkWidget *pmGroupPasswdEntry;


GtkWidget *userNamelabel;
GtkWidget *userNameEntry;
GtkWidget *userPasswdLabel;
GtkWidget *userPasswdEntry;


GtkWidget* lookup_widget (GtkWidget *widget, const gchar *widget_name);
int get_authFrame(void);
int get_pmAuthFrame(void);
int cleanup_module_authFrame(void);
int removeAuthFrame(void);
int initializeAuthFrame(void);
int bring_back_old_pmAuthFrame(void);
int initializePmAuthFrame(void);

#define MAX_ERROR_LENGTH        1024

GtkWidget*
lookup_widget (GtkWidget       *widget,
	       const gchar     *widget_name)
{
	GtkWidget *parent, *found_widget;

	for (;;)
	{
		if (GTK_IS_MENU (widget))
			parent = gtk_menu_get_attach_widget (GTK_MENU (widget));
		else
			parent = widget->parent;
		if (!parent)
			parent = (GtkWidget*) g_object_get_data (G_OBJECT (widget), "GladeParentKey");
		if (parent == NULL)
			break;
		widget = parent;
	}

	found_widget = (GtkWidget*) g_object_get_data (G_OBJECT (widget),
						       widget_name);
	if (!found_widget)
		g_warning ("Widget not found: %s", widget_name);
	return found_widget;
}

int
get_authFrame(void)
{
	
	if((authFrame = (GtkWidget *)lookup_widget(mainWindow, "authFrame")) == NULL)
	{
		printf("WIDGET_GW_AUTH_FRAME not found .. \n");
		return -1;
	}
	
	return 0;
}

int 
get_pmAuthFrame(void)
{
	
	if((pmAuthFrame = (GtkWidget *)lookup_widget(mainWindow, "pmAuthframe")) == NULL)
	{
		printf("WIDGET_GW_PM_AUTH_FRAME not found .. \n");
		return -1;
	}
	
	return 0;
}

int 
cleanup_module_authFrame(void)
{
	gtk_container_remove((GtkContainer *)gwMaintable, newAuthFrame);
	gtk_table_attach (GTK_TABLE (gwMaintable), authFrame, 0, 2, 4, 5,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);
		    
	g_object_unref (authFrame);
	gtk_widget_show (authFrame);
	
	return 0;
}

int
bring_back_old_pmAuthFrame(void)
{
	gtk_container_remove((GtkContainer *)pmGeneralTable, newPmAuthFrame);
	gtk_table_attach (GTK_TABLE (pmGeneralTable), pmAuthFrame, 0, 2, 4, 5,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);
		    
	g_object_unref (pmAuthFrame);
	gtk_widget_show (pmAuthFrame);
	
	gtk_widget_hide(pmAuthenticateLabel);
	gtk_widget_hide(pmauthenticateCombo);                                      	
	return 0;
}

int
removeAuthFrame(void)
{
	if((gwMaintable = (GtkWidget *)lookup_widget(mainWindow, "gwMainTable")) == NULL)
	{
		printf("WIDGET_GW_MAIN_TABLE not found .. \n");
		return -1;
	}
	g_object_ref(authFrame);
	gtk_container_remove((GtkContainer *)gwMaintable, authFrame);
                                             
	return 0;
}


int
initializeAuthFrame(void)
{

	GtkWidget *alignment4;
	GtkWidget *table2;
	GtkWidget *authenticateHeadingLabel;
		
	newAuthFrame = gtk_frame_new (NULL);
	gtk_widget_show (newAuthFrame);
	gtk_table_attach (GTK_TABLE (gwMaintable), newAuthFrame, 0, 2, 4, 5,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);
	gtk_frame_set_shadow_type (GTK_FRAME (newAuthFrame), GTK_SHADOW_NONE);
	
	alignment4 = gtk_alignment_new (0.5, 0.5, 1, 1);
	gtk_widget_show (alignment4);
	gtk_container_add (GTK_CONTAINER (newAuthFrame), alignment4);
	gtk_alignment_set_padding (GTK_ALIGNMENT (alignment4), 0, 0, 12, 0);
	table2 = gtk_table_new (2, 2, FALSE);
	gtk_widget_show (table2);
	gtk_container_add (GTK_CONTAINER (alignment4), table2);
	gtk_container_set_border_width (GTK_CONTAINER (table2), 12);
	gtk_table_set_row_spacings (GTK_TABLE (table2), 13);
	gtk_table_set_col_spacings (GTK_TABLE (table2), 6);
	
	userNamelabel = gtk_label_new_with_mnemonic ("_Username:");
	gtk_widget_show (userNamelabel);
	gtk_table_attach (GTK_TABLE (table2), userNamelabel, 0, 1, 0, 1,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (userNamelabel), 0, 0.5);
	userNameEntry = gtk_entry_new ();
	GTK_WIDGET_SET_FLAGS (userNameEntry, GTK_CAN_FOCUS);
	
	gtk_widget_show (userNameEntry);
	
	gtk_table_attach (GTK_TABLE (table2), userNameEntry, 1, 2, 0, 1,
			  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			  (GtkAttachOptions) (GTK_FILL), 0, 0);
				
	userPasswdLabel = gtk_label_new_with_mnemonic ("User Pass_word:");
	gtk_widget_show (userPasswdLabel);
	gtk_table_attach (GTK_TABLE (table2), userPasswdLabel, 0, 1, 1, 2,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (userPasswdLabel), 0, 0.5);
	userPasswdEntry = gtk_entry_new ();
	gtk_widget_show (userPasswdEntry);
	gtk_table_attach (GTK_TABLE (table2), userPasswdEntry, 1, 2, 1, 2,
			  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);
	gtk_entry_set_visibility (GTK_ENTRY (userPasswdEntry), FALSE);

	
	authenticateHeadingLabel = gtk_label_new ("<b>Nortel Contivity</b>");
	gtk_widget_show (authenticateHeadingLabel);
	gtk_frame_set_label_widget (GTK_FRAME (newAuthFrame), authenticateHeadingLabel);
	gtk_widget_set_size_request (authenticateHeadingLabel, -1, 28);
	gtk_label_set_use_markup (GTK_LABEL (authenticateHeadingLabel), TRUE);

	
	gtk_label_set_mnemonic_widget (GTK_LABEL (userNamelabel), userNameEntry);
	gtk_label_set_mnemonic_widget (GTK_LABEL (userPasswdLabel), userPasswdEntry);
	
	gtk_widget_grab_focus(userNameEntry);

	return 0;
}


int
initializePmAuthFrame(void)
{

	GtkWidget *alignment4;
	GtkWidget *table2;
	GtkWidget *pmAuthenticateHeadingLabel;
		
	newPmAuthFrame = gtk_frame_new (NULL);
	gtk_widget_show (newPmAuthFrame);
	gtk_table_attach (GTK_TABLE (pmGeneralTable), newPmAuthFrame, 0, 2, 4, 5,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);
	gtk_frame_set_shadow_type (GTK_FRAME (newPmAuthFrame), GTK_SHADOW_NONE);
	
	alignment4 = gtk_alignment_new (0.5, 0.5, 1, 1);
	gtk_widget_show (alignment4);
	gtk_container_add (GTK_CONTAINER (newPmAuthFrame), alignment4);
	gtk_alignment_set_padding (GTK_ALIGNMENT (alignment4), 0, 0, 12, 0);
	table2 = gtk_table_new (2, 2, FALSE);
	gtk_widget_show (table2);
	gtk_container_add (GTK_CONTAINER (alignment4), table2);
	gtk_container_set_border_width (GTK_CONTAINER (table2), 12);
	gtk_table_set_row_spacings (GTK_TABLE (table2), 9);
	gtk_table_set_col_spacings (GTK_TABLE (table2), 6);
	pmGroupNamelabel = gtk_label_new_with_mnemonic ("_Groupname:");
	gtk_widget_show (pmGroupNamelabel);
	gtk_table_attach (GTK_TABLE (table2), pmGroupNamelabel, 0, 1, 0, 1,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (pmGroupNamelabel), 0, 0.5);
	pmGroupNameEntry = gtk_entry_new ();
	gtk_widget_show (pmGroupNameEntry);
	gtk_table_attach (GTK_TABLE (table2), pmGroupNameEntry, 1, 2, 0, 1,
			  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			  (GtkAttachOptions) (GTK_FILL), 0, 0);
	
	pmGroupPasswdLabel = gtk_label_new_with_mnemonic ("Group P_assword:");
	gtk_widget_show (pmGroupPasswdLabel);
	gtk_table_attach (GTK_TABLE (table2), pmGroupPasswdLabel, 0, 1, 1, 2,
			  (GtkAttachOptions) (GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (pmGroupPasswdLabel), 0, 0.5);
	pmGroupPasswdEntry = gtk_entry_new ();
	gtk_widget_show (pmGroupPasswdEntry);
	gtk_table_attach (GTK_TABLE (table2), pmGroupPasswdEntry, 1, 2, 1, 2,
			  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			  (GtkAttachOptions) (0), 0, 0);
	gtk_entry_set_visibility (GTK_ENTRY (pmGroupPasswdEntry), FALSE);
	
	
	pmAuthenticateHeadingLabel = gtk_label_new ("<b>Nortel Contivity</b>");
	gtk_widget_show (pmAuthenticateHeadingLabel);
	gtk_frame_set_label_widget (GTK_FRAME (newPmAuthFrame), pmAuthenticateHeadingLabel);
	gtk_widget_set_size_request (pmAuthenticateHeadingLabel, -1, 28);
	gtk_label_set_use_markup (GTK_LABEL (pmAuthenticateHeadingLabel), TRUE);

	
	//set the mnemonics
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmGroupNamelabel), pmGroupNameEntry);
	gtk_label_set_mnemonic_widget (GTK_LABEL (pmGroupPasswdLabel), pmGroupPasswdEntry);
	
	
	///////////
	
	/*
	  gtk_entry_set_text((GtkEntry *)groupNameEntry, grpName);
	  gtk_entry_set_text((GtkEntry *)groupPasswdEntry, grpPasswd);
	  gtk_entry_set_text((GtkEntry *)userNameEntry, usrName);
	*/
	return 0;
}

int
removePmAuthFrame(void)
{
/*	if((pmGenTable = (GtkWidget *)lookup_widget(mainWindow, "pmGeneralTable")) == NULL)
	{
	printf("WIDGET_PM_GENERAL_TABLE not found .. \n");
	return -1;
	}
*/
	g_object_ref(pmAuthFrame);
	gtk_container_remove((GtkContainer *)pmGeneralTable, pmAuthFrame);
	gtk_widget_hide(pmAuthenticateLabel);
	gtk_widget_hide(pmauthenticateCombo);                                             
	return 0;
}


char *
nortel_gui_get_username () 
{
	return (char *) gtk_entry_get_text(GTK_ENTRY(userNameEntry));
}

void
nortel_gui_set_username (const char *username) 
{
	gtk_entry_set_text((GtkEntry *)userNameEntry, username);
}

char *
nortel_gui_get_password () 
{
	return (char *) gtk_entry_get_text(GTK_ENTRY(userPasswdEntry));

}

char *
nortel_gui_get_pm_groupname ()
{
	return (char *)gtk_entry_get_text((GtkEntry *)pmGroupNameEntry);
}

char *
nortel_gui_get_pm_grouppassword ()
{
	return (char *)gtk_entry_get_text((GtkEntry *)pmGroupPasswdEntry);
}

void
nortel_gui_set_pm_groupname (const char *name) 
{
	gtk_entry_set_text((GtkEntry *)pmGroupNameEntry, name);
}

void
nortel_gui_set_pm_grouppassword (const char *password) 
{
	gtk_entry_set_text((GtkEntry *)pmGroupPasswdEntry, password);
}

void
nortel_gui_focus_userpasswordentry ()
{
	gtk_widget_grab_focus(userPasswdEntry);
}

void
nortel_gui_init ()
{
	if(pmPluginActive)
	{
		if(get_pmAuthFrame())
			return;
		removePmAuthFrame();
		initializePmAuthFrame();
		
		return;
	}
	if(get_authFrame())
	{
		printf("********** could not get auth frame .. error\n");
		return;
	}
	removeAuthFrame();
	initializeAuthFrame();
}

void 
nortel_gui_cleanup ()
{
	if(pmPluginActive)
	{
		bring_back_old_pmAuthFrame();
		return;
	}
	cleanup_module_authFrame();
}


static
void show_message (const char *string)
{

	GtkWidget *message = gtk_message_dialog_new(GTK_WINDOW(mainWindow), 
		GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, string);
	gtk_dialog_run(GTK_DIALOG(message));

	gtk_widget_destroy (message);
}


void show_error_message (char * format, ...)
{
	char message [MAX_ERROR_LENGTH];
	va_list params;
	
	va_start (params, format);
	vsnprintf (message, MAX_ERROR_LENGTH, format, params);
	va_end (params);

	show_message ( (const char *) message);
}
