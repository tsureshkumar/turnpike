plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-novellvpn-properties.la

libnm_novellvpn_properties_la_SOURCES = \
	import-export.c \
	import-export.h \
	nm-novellvpn.c 	\
	nm-novellvpn.h

uidir = $(datadir)/gnome-vpn-properties/novellvpn
ui_DATA = nm-novellvpn-dialog.ui

libnm_novellvpn_properties_la_CFLAGS =                          \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
	$(NM_CFLAGS)			\
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\""$(prefix)/$(DATADIRNAME)/locale"\"  \
        -DVERSION=\"$(VERSION)\"

libnm_novellvpn_properties_la_LIBADD =       \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)		\
	$(top_builddir)/common-gnome/libnm-novellvpn-common-gnome.la		\
	$(NULL)

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
