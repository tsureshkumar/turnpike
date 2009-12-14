
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif // HAVE_CONFIG_H

#include <sys/stat.h>
#include <sys/queue.h>
#include <dirent.h>
#include <netdb.h>
#include <errno.h>
#include <pwd.h>
#include <string.h>

#include <gtk/gtk.h>
#include <gmodule.h>

#include "tpike-types.h"
#include "widgets.h"

const char * const dh_group_consts [] = { "dh1", "dh2" };
const char * const pfs_group_consts [] = { "off", "1", "2" };
const char * const exchange_modes_consts [] = { "AM", "MM"};
const char * const auth_types_consts [] = { "PSK", "X.509" };
const char * const gateway_types_consts [] = {"Standard IPsec gateway",
                                                  "nortel",
                                                 "unspecified"};
const char * const no_split_tunnel_consts [] = { "no", "yes" };

const gchar *
ui_helper_get_dh_group ()
{
   gint selected = 0;
   selected = gtk_combo_box_get_active ((GtkComboBox *)pmPh1DhCombo);
   if (selected == -1)
      selected = 0;
   return dh_group_consts [selected];
}

const gchar *
ui_helper_get_pfs_group ()
{
   gint selected = 0;
   selected = gtk_combo_box_get_active ((GtkComboBox *)pmPh2DhCombo);
   if (selected == -1)
      selected = 0;
   return pfs_group_consts [selected];
}

enum tpike_auth_type
ui_helper_get_authmethod ()
{
   return (enum tpike_auth_type) gtk_combo_box_get_active ( (GtkComboBox *) pmauthtypeCombo);
}

const gchar *
ui_helper_get_authmethod_text ()
{
   enum tpike_auth_type selected = TPIKE_AUTH_TYPE_XAUTH;

   selected = ui_helper_get_authmethod ();

   if (selected == TPIKE_AUTH_TYPE_NONE)
      selected = TPIKE_AUTH_TYPE_XAUTH;

   return auth_types_consts [selected];
}

const gchar *
ui_helper_get_split_tunnel ()
{
	gboolean res = FALSE;

	res = gtk_toggle_button_get_active (
			GTK_TOGGLE_BUTTON(pmSplitTunnelCheckBtn));
	if (res)
		return no_split_tunnel_consts [1]; // "yes"
	else
		return no_split_tunnel_consts [0]; // "no"
}

void
ui_helper_set_split_tunnel (const char const * flag)
{
	if (strcmp (flag, no_split_tunnel_consts [1]) == 0) // "yes"
		gtk_toggle_button_set_active (
				GTK_TOGGLE_BUTTON(pmSplitTunnelCheckBtn), TRUE);
	else // "no"
		gtk_toggle_button_set_active (
				GTK_TOGGLE_BUTTON(pmSplitTunnelCheckBtn), FALSE);
}

void
ui_helper_set_authmethod (const char const * method)
{
  int i = 0;
  while (i < ARRAYCOUNT(auth_types_consts)) {
    if (strcmp (method, auth_types_consts [i]) == 0)
      break;
    i++;
  }
  if (i > ARRAYCOUNT (auth_types_consts))
    i = 0;
  gtk_combo_box_set_active((GtkComboBox *)pmauthtypeCombo, i);
}

enum tpike_gateway_type
ui_helper_get_gateway_type ()
{
   int selected =
      gtk_combo_box_get_active ( (GtkComboBox *) pmgwtypeCombo);
   if (selected != -1)
      return selected - 1;
   return selected;
}

const gchar *
ui_helper_get_gateway_type_text ()
{
   enum tpike_gateway_type selected = TPIKE_GATEWAY_TYPE_STDGW;
   
   selected = ui_helper_get_gateway_type ();
   
   if (selected == TPIKE_GATEWAY_TYPE_NONE)
      selected = TPIKE_GATEWAY_TYPE_MAX; // unspecified
   
   return gateway_types_consts [selected];
}

const gchar *
ui_helper_get_exchange_mode_text ()
{
   int selected = 0;
   
   selected = gtk_combo_box_get_active ((GtkComboBox *)pmPh1ModeCombo);

   if (selected == -1)
      selected = 0;

   return exchange_modes_consts [selected];
}

