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

#ifdef HAVE_TURNPIKE_DIR
#include "gui-hooks.h"
#else
#include "turnpike/gui-hooks.h"
#endif

#include "hooks.h"

extern void nortel_gui_init();
extern size_t nortel_connect (char *);
extern int nortel_disconnect (char *);

extern int nortel_fill_ph1_config_buffer (char *);
extern int nortel_fill_ph1_proposal_buffer (char *);

extern int nortel_parse_message_from_adminport(char *buf);
extern void nortel_state_recv_from_adminport (int state);

extern int nortel_display_profile (char * vendor_file);
extern int nortel_write_profile (char *filename, char* gatewayIP);
extern int nortel_update_profile (char *profilename);
extern int nortel_pm_load_from_vendor_profile (char *profile);
extern int nortel_load_from_vendor_profile (char *profile);

extern int nortel_write_racoon_conf (char *buff);

void nortel_register_hooks (void)
{
	tpike_guihook_plugin_init(&nortel_gui_init);
	tpike_guihook_connect (&nortel_connect);
	tpike_guihook_disconnect (&nortel_disconnect);

	tpike_guihook_pm_display (&nortel_display_profile);
	tpike_guihook_pm_write (&nortel_write_profile);
	tpike_guihook_pm_load_vendorprofile (&nortel_pm_load_from_vendor_profile);
	tpike_guihook_profile_update (&nortel_update_profile);
	tpike_guihook_load_vendorprofile (&nortel_load_from_vendor_profile);

	tpike_guihook_ph1_config (&nortel_fill_ph1_config_buffer);
	tpike_guihook_ph1_proposal (&nortel_fill_ph1_proposal_buffer);

	tpike_guihook_state_notification (&nortel_state_recv_from_adminport);
	tpike_guihook_admin_port_parse_message (&nortel_parse_message_from_adminport);

	tpike_guihook_racoon_conf_write (&nortel_write_racoon_conf);
	return;
}
 
void  nortel_unregister_hooks (void)
{
	tpike_guiunhook_connect ();
	return;
}
