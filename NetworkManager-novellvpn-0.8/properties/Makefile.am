plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-novellvpn-properties.la

libnm_novellvpn_properties_la_SOURCES = \
	import-export.c \
	import-export.h \
	nm-novellvpn.c 	\
	nm-novellvpn.h

gladedir = $(datadir)/gnome-vpn-properties/novellvpn
glade_DATA = nm-novellvpn-dialog.glade

libnm_novellvpn_properties_la_CFLAGS =                          \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(LIBGNOMEUI_CFLAGS)                            \
	$(NETWORK_MANAGER_CFLAGS)			\
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\""$(prefix)/$(DATADIRNAME)/locale"\"  \
        -DVERSION=\"$(VERSION)\"

libnm_novellvpn_properties_la_LIBADD =       \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(LIBGNOMEUI_LIBS)		\
	$(top_builddir)/common-gnome/libnm-novellvpn-common-gnome.la		\
	$(NULL)

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
