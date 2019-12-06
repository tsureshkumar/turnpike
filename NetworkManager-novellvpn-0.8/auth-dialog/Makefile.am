libexec_PROGRAMS = nm-novellvpn-auth-dialog

nm_novellvpn_auth_dialog_CPPFLAGS =			\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(LIBGNOMEUI_CFLAGS)			\
	$(NETWORK_MANAGER_CFLAGS)		\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DGLADEDIR=\""$(gladedir)"\"		\
	-DBINDIR=\""$(bindir)"\"		\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED		\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-DVERSION=\"$(VERSION)\"			\
	$(NULL)

nm_novellvpn_auth_dialog_SOURCES =			\
	main.c					\
	gnome-two-password-dialog.c		\
	gnome-two-password-dialog.h		\
	profile.c				\
	profile.h				\
	$(NULL)

nm_novellvpn_auth_dialog_LDADD =			\
	$(GTK_LIBS)				\
	$(LIBGNOMEUI_LIBS)			\
	$(top_builddir)/common-gnome/libnm-novellvpn-common-gnome.la		\
	$(NULL)

CLEANFILES = *~
