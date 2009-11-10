/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-novellvpn.h : GNOME UI dialogs for configuring novellvpn VPN connections
 *
 * Copyright (C) 2008 Bin Li <bili@novell.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#ifndef _NM_NOVELLVPN_H_
#define _NM_NOVELLVPN_H_

#include <glib-object.h>

typedef enum
{
	NOVELLVPN_PLUGIN_UI_ERROR_UNKNOWN = 0,
	NOVELLVPN_PLUGIN_UI_ERROR_INVALID_CONNECTION,
	NOVELLVPN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
	NOVELLVPN_PLUGIN_UI_ERROR_MISSING_PROPERTY,
	NOVELLVPN_PLUGIN_UI_ERROR_FILE_NOT_READABLE,
	NOVELLVPN_PLUGIN_UI_ERROR_FILE_NOT_NOVELLVPN
} NovellvpnPluginUiError;

#define NOVELLVPN_TYPE_PLUGIN_UI_ERROR (novellvpn_plugin_ui_error_get_type ()) 
GType novellvpn_plugin_ui_error_get_type (void);

#define NOVELLVPN_PLUGIN_UI_ERROR (novellvpn_plugin_ui_error_quark ())
GQuark novellvpn_plugin_ui_error_quark (void);


#define NOVELLVPN_TYPE_PLUGIN_UI            (novellvpn_plugin_ui_get_type ())
#define NOVELLVPN_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NOVELLVPN_TYPE_PLUGIN_UI, NovellvpnPluginUi))
#define NOVELLVPN_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NOVELLVPN_TYPE_PLUGIN_UI, NovellvpnPluginUiClass))
#define NOVELLVPN_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NOVELLVPN_TYPE_PLUGIN_UI))
#define NOVELLVPN_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NOVELLVPN_TYPE_PLUGIN_UI))
#define NOVELLVPN_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NOVELLVPN_TYPE_PLUGIN_UI, NovellvpnPluginUiClass))

typedef struct _NovellvpnPluginUi NovellvpnPluginUi;
typedef struct _NovellvpnPluginUiClass NovellvpnPluginUiClass;

struct _NovellvpnPluginUi {
	GObject parent;
};

struct _NovellvpnPluginUiClass {
	GObjectClass parent;
};

GType novellvpn_plugin_ui_get_type (void);


#define NOVELLVPN_TYPE_PLUGIN_UI_WIDGET            (novellvpn_plugin_ui_widget_get_type ())
#define NOVELLVPN_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NOVELLVPN_TYPE_PLUGIN_UI_WIDGET, NovellvpnPluginUiWidget))
#define NOVELLVPN_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NOVELLVPN_TYPE_PLUGIN_UI_WIDGET, NovellvpnPluginUiWidgetClass))
#define NOVELLVPN_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NOVELLVPN_TYPE_PLUGIN_UI_WIDGET))
#define NOVELLVPN_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NOVELLVPN_TYPE_PLUGIN_UI_WIDGET))
#define NOVELLVPN_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NOVELLVPN_TYPE_PLUGIN_UI_WIDGET, NovellvpnPluginUiWidgetClass))

typedef struct _NovellvpnPluginUiWidget NovellvpnPluginUiWidget;
typedef struct _NovellvpnPluginUiWidgetClass NovellvpnPluginUiWidgetClass;

struct _NovellvpnPluginUiWidget {
	GObject parent;
};

struct _NovellvpnPluginUiWidgetClass {
	GObjectClass parent;
};

GType novellvpn_plugin_ui_widget_get_type (void);

GValue *int_to_gvalue (gint i);

GValue *bool_to_gvalue (gboolean b);

GValue *str_to_gvalue (const char *str);

#endif	/* _NM_NOVELLVPN_H_ */

