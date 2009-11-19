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
#include <gmodule.h>
#include "hooks.h"
#include "authframe.h"

extern int pmPluginActive;

void g_module_unload(GModule *module);
const gchar* g_module_check_init(GModule* module);

const gchar*
g_module_check_init (GModule* module) 
{
	nortel_register_hooks ();
        return NULL;
}
void
g_module_unload (GModule *module)
{
	nortel_unregister_hooks ();
	nortel_gui_cleanup ();
	return;
}
