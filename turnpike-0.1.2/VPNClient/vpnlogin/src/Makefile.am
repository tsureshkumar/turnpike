## Process this file with automake to produce Makefile.in

INCLUDES = \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	@LIBXML_CFLAGS@ \
	@GTK_CFLAGS@ \
	-I${top_srcdir}/ErrorGenerator/ \
	-I${top_srcdir}/utility/  \
	-I${top_srcdir}/VPNClient/vpnlogin/include \
	-I${top_srcdir}/VPNClient/include

bin_PROGRAMS = vpnlogin

vpnlogin_SOURCES = \
	main.c \
	support.c \
	interface.c \
	callbacks.c \
        utility.c \
        profile.c \
	ph2fill.c \
	widgets.h \
	interface.h \
	callbacks.h \
	support.h \
	ui-helpers.h \
	ui-helpers.c \
	gui-hooks.c

vpnlogin_LDFLAGS = -export-dynamic
vpnlogin_LDADD = $(INTLLIBS) -lcrypto  ../../../ErrorGenerator/libErrorHandling.la ../../CommonUI/libCommonUI.la ../../../utility/libgetip.la @GTK_LIBS@ @LIBXML_LIBS@ 

#noinst_HEADERS=interface.h callbacks.h utility.h externs.h 

libexec_PROGRAMS = vpnUpdateMenu
vpnUpdateMenu_SOURCES = menuUpdate.c
vpnUpdateMenu_CFLAGS = @LIBXML_CFLAGS@
vpnUpdateMenu_LDFLAGS = @LIBXML_LIBS@
