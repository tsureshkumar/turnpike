noinst_LTLIBRARIES=libnm-novellvpn-common-gnome.la

libnm_novellvpn_common_gnome_la_CPPFLAGS = \
				      $(NETWORK_MANAGER_CFLAGS) \
				      $(GLIB_CFLAGS) \
				      $(GNOMEKEYRING_CFLAGS) \
				      -DG_DISABLE_DEPRECATED

libnm_novellvpn_common_gnome_la_SOURCES= \
				    keyring-helpers.c \
				    keyring-helpers.h

libnm_novellvpn_common_gnome_la_LIBADD = \
				    $(NETWORK_MANAGER_LIBS) \
				    $(GLIB_LIBS) \
				    $(GNOMEKEYRING_LIBS)
