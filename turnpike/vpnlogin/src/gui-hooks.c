
/************************************************************************************
*   Copyright (c) 2005, Novell Inc.,                                                * 
*   All rights reserved.                                                            *
*                                                                                   *
*   Redistribution and use in source and binary forms, with or without              *
*   modification, are permitted provided that the following conditions              *
*   are met:                                                                        *
*   1.  Redistributions of source code must retain the above copyright              *
*       notice, this list of conditions and the following disclaimer.               *
*   2.  Redistributions in binary form must reproduce the above copyright           *
*       notice, this list of conditions and the following disclaimer in the         *
*       documentation and/or other materials provided with the distribution.        *
*   3.  Neither the name of the Novell nor the names of its contributors            *
*       may be used to endorse or promote products derived from this software       *
*       without specific prior written permission.                                  *
*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND *
*   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE           *
*   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE      *
*   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE *
*   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL      *
*   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS         *
*   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)           *
*   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT      *
*   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY       *
*   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF          *
*   SUCH DAMAGE.                                                                    *
*************************************************************************************/

#include "gui-hooks.h"
#include "CommonUI.h"

/*
int (*plugin_connect_callback) (char *); 
int (*plugin_ph1_config_callback) (char *); 
int (*plugin_ph1_proposal_callback) (char *); 
int (*plugin_disconnect_callback) (char *); 
void (*plugin_state_notification_callback) (int);
int (*plugin_admin_port_parse_message_callback) (char *);
int (*plugin_pm_display_callback)(char *);
int (*plugin_pm_write_callback)(char *);
int (*plugin_pm_load_vendorProfile_callback)(char *);
int (*plugin_load_vendorProfile_callback)(char *);
int (*plugin_racoon_conf_write_callback)(char *);
int (*plugin_profile_update_callback)(char *);
*/
extern Inf_t Inf;
void
tpike_guihook_plugin_init(void (*f)())
{
	Inf.plugin_gui_init = f;
}

void
tpike_guihook_pm_display (int (*f)(char *))
{
	Inf.plugin_pm_display = f;
	return;
}

void 
tpike_guihook_pm_write (int (*f)(char *, char*))
{
	Inf.plugin_pm_write = f;
	return;
}

void 
tpike_guihook_pm_load_vendorprofile (int (*f)(char *))
{
	Inf.plugin_pm_load_vendorProfile = f;
	return;
}

void 
tpike_guihook_load_vendorprofile (int (*f)(char *))
{
	Inf.plugin_load_vendorProfile = f;
	return;
}

void 
tpike_guihook_connect (size_t (*f)(char * ))
{
	Inf.plugin_connect = f;
}


void 
tpike_guihook_ph1_config (int (*f)(char * ))
{
	Inf.plugin_ph1_config = f;
	return;
}

void 
tpike_guihook_ph1_proposal (int (*f)(char * ))
{
	Inf.plugin_ph1_proposal = f;
	return;
}
void 
tpike_guihook_disconnect (int (*f)(char * ))
{
	Inf.plugin_disconnect = f;
	return;
}
void 
tpike_guihook_state_notification (void (*f)(int ))
{
	Inf.plugin_state_notification = f;
	return;
}

void 
tpike_guihook_admin_port_parse_message (int (*f)(char * ))
{
	Inf.plugin_admin_port_parse_message = f;
	return;
}

void 
tpike_guihook_racoon_conf_write (int (*f) (char *))
{
	Inf.plugin_racoon_conf_write = f;
	return;
}

void 
tpike_guihook_profile_update (int (*f) (char *))
{
	Inf.plugin_update_profile = f;
	return;
}

void 
tpike_guiunhook_connect (void)
{
	Inf.plugin_connect = 0;
	return;
}
