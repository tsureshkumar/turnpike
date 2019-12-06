
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

#ifndef __TPIKE_GUI_HOOKS__
#define __TPIKE_GUI_HOOKS__  1

#include <stdio.h>

extern void tpike_guihook_plugin_init		(void (*f) ());
extern void tpike_guihook_pm_display            (int  (*f) (char *));
extern void tpike_guihook_pm_write              (int   (*f) (char *, char *));
extern void tpike_guihook_pm_load_vendorprofile (int  (*f) (char *));
extern void tpike_guihook_load_vendorprofile    (int  (*f) (char *));
extern void tpike_guihook_connect               (size_t   (*f) (char *));
extern void tpike_guihook_disconnect            (int   (*f) (char *));
extern void tpike_guihook_ph1_config            (int   (*f) (char *));
extern void tpike_guihook_ph1_proposal          (int   (*f) (char *));
extern void tpike_guihook_state_notification    (void  (*f) (int ));
extern void tpike_guihook_racoon_conf_write     (int   (*f) (char *));
extern void tpike_guihook_profile_update        (int   (*f) (char *));
extern void tpike_guihook_admin_port_parse_message (int (*f) (char * ));

extern void tpike_guiunhook_connect             (void);

extern void register_connect_callback           (size_t (*f) (char *));
extern void register_ph1_config_callback        (int (*f) (char *));
extern void register_ph1_proposal_callback      (int (*f) (char *));
extern void register_disconnect_callback        (int (*f) (char *));
extern void register_state_notification_callback (void (*f) (int));
extern void register_admin_port_parse_message_callback (int (*f) (char *));
extern void register_pm_display_callback        (int (*f) (char *));
extern void register_pm_write_callback          (int (*f) (char *));
extern void register_pm_load_vendorProfile_callback (int (*f) (char *));
extern void register_load_vendorProfile_callback(int (*f) (char *));
extern void register_racoon_conf_write_callback (int (*f) (char *));
extern void register_profile_update_callback    (int (*f) (char *));


#endif // __TPIKE_GUI_HOOKS__
