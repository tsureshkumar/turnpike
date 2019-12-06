include_plugin_framedir = ${includedir}/plugin_frame

noinst_LTLIBRARIES = libplugin_frame.la

INCLUDES=-I${srcdir}/../racoon/ -I${srcdir}/../libipsec/
AM_CFLAGS = -D_GNU_SOURCE @GLIBC_BUGS@ -DSYSCONFDIR=\"${sysconfdir}\" \
	-DADMINPORTDIR=\"${adminsockdir}\"

libplugin_frame_la_SOURCES = \
       hashtable.c registration.c dispatch.c

libplugin_framedir = $(includedir)/plugin_frame

include_plugin_frame_HEADERS= \
	hashtable.h           common.h      framework.h   error.h      position.h

libplugin_frame_la_LDFLAGS = -version-info 1:0:0 -static
