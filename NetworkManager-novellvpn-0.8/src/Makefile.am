#INCLUDES = -I${top_srcdir}  -I${top_srcdir}/utils -I${top_srcdir}/vpn-daemons/novellvpn

AM_CPPFLAGS =							\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	$(LIBNL_CFLAGS)						\
	$(NETWORK_MANAGER_CFLAGS)				\
	-DDBUS_API_SUBJECT_TO_CHANGE				\
	-DG_DISABLE_DEPRECATED					\
	-DBINDIR=\"$(bindir)\"					\
	-DPREFIX=\""$(prefix)"\"				\
	-DSYSCONFDIR=\""$(sysconfdir)"\"			\
	-DVERSION="\"$(VERSION)\""				\
	-DLIBDIR=\""$(libdir)"\"				\
	-DLIBEXECDIR=\""$(libexecdir)"\"				\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"		 	\
	-DDATADIR=\"$(datadir)\"

libexec_PROGRAMS = nm-novellvpn-service nm-novellvpn-service-novellvpn-helper
dist_libexec_SCRIPTS = nm_novellvpn_racoon_launcher.sh

nm_novellvpn_service_SOURCES =				\
				nm-novellvpn-service.c	\
				nm-novellvpn-service.h


nm_novellvpn_service_LDADD = 						\
				$(DBUS_LIBS)				\
				$(GTHREAD_LIBS)				\
				$(NETWORK_MANAGER_LIBS)			\
				-lnm-glib-vpn



nm_novellvpn_service_novellvpn_helper_SOURCES = 					\
				nm-novellvpn-service-novellvpn-helper.c			\
				mtu.c

nm_novellvpn_service_novellvpn_helper_LDADD = 					\
				$(DBUS_LIBS)				\
				$(GTHREAD_LIBS)				\
				$(LIBNL_LIBS)				\
				$(NETWORK_MANAGER_LIBS)

CLEANFILES = *~
