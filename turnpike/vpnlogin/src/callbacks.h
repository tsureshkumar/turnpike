
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

#include <gtk/gtk.h>


void
on_vpnlogin_show                       (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_vpnlogin_destroy                    (GtkObject       *object,
                                        gpointer         user_data);

void
on_button2_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_profileCombo_show                   (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_gwtypeCombo_show                    (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_authenticateCombo_show              (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_auth1Combo_show                     (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_profileCombo_changed                (GtkComboBox     *combobox,
                                        gpointer         user_data);

void
on_pmCancelBtn_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_pmRembtn_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_pmSavBtn_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_pmAddBtn_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_mainHelpBtn_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_button1_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_mainCancelBtn_clicked               (GtkButton       *button,
                                        gpointer         user_data);

void
on_button4_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_auth1Combo_changed                  (GtkComboBox     *combobox,
                                        gpointer         user_data);

void
on_mainDisconnectBtn_clicked           (GtkButton       *button,
                                        gpointer         user_data);

void
on_mainConnectBtn_clicked              (GtkButton       *button,
                                        gpointer         user_data);

void
on_mainConnectBtn_clicked              (GtkButton       *button,
                                        gpointer         user_data);

void
on_mainDisconnectBtn_clicked           (GtkButton       *button,
                                        gpointer         user_data);

void
on_ph1expander_activate                (GtkExpander     *expander,
                                        gpointer         user_data);

void
on_ph2expander_activate                (GtkExpander     *expander,
                                        gpointer         user_data);

gboolean
on_ikenotebook_select_page             (GtkNotebook     *notebook,
                                        gboolean         move_focus,
                                        gpointer         user_data);

void
on_ikenotebook_switch_page             (GtkNotebook     *notebook,
                                        GtkNotebookPage *page,
                                        guint            page_num,
                                        gpointer         user_data);

void
on_gwtypeCombo_changed                 (GtkComboBox     *combobox,
                                        gpointer         user_data);

void
on_pmgwtypeCombo_changed               (GtkComboBox     *combobox,
                                        gpointer         user_data);

void
on_pmauthtypeCombo_changed               (GtkComboBox     *combobox,
                                        gpointer         user_data);

void
on_mainConnectBtn_clicked              (GtkButton       *button,
                                        gpointer         user_data);

void on_pmSplitTunnelCheckBtn_toggled (
		GtkToggleButton *togglebtn,
	   	gpointer user_data);
